"""
Docker API honeypot — port 2375
Emulates an unauthenticated Docker daemon REST API.
Detects container escape / cryptominer deployment / reverse-shell injection.
"""

import socket
import threading
import time
import random
import json
import logging
import re

logger = logging.getLogger("honeypot.docker")

# ── fake data ─────────────────────────────────────────────────────────────────

_FAKE_CONTAINERS = [
    {
        "Id":      "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2",
        "Names":   ["/ipcam-web"],
        "Image":   "hikvision/ipcam-web:latest",
        "ImageID": "sha256:deadbeef0001",
        "Command": "/bin/ipcam-web -c /etc/ipcam/config.ini",
        "Created": 1700000000,
        "Status":  "Up 30 days",
        "State":   "running",
        "Ports":   [{"IP":"0.0.0.0","PrivatePort":80,"PublicPort":80,"Type":"tcp"},
                    {"IP":"0.0.0.0","PrivatePort":443,"PublicPort":443,"Type":"tcp"}],
    },
    {
        "Id":      "b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3",
        "Names":   ["/nvr-recorder"],
        "Image":   "dahua/nvr:3.218",
        "ImageID": "sha256:deadbeef0002",
        "Command": "/usr/bin/nvr-daemon --port 37777",
        "Created": 1700100000,
        "Status":  "Up 28 days",
        "State":   "running",
        "Ports":   [{"IP":"0.0.0.0","PrivatePort":37777,"PublicPort":37777,"Type":"tcp"}],
    },
]

_FAKE_IMAGES = [
    {
        "Id":          "sha256:deadbeef0001",
        "RepoTags":    ["hikvision/ipcam-web:latest"],
        "Created":     1699000000,
        "Size":        18432000,
        "VirtualSize": 18432000,
    },
    {
        "Id":          "sha256:deadbeef0002",
        "RepoTags":    ["dahua/nvr:3.218"],
        "Created":     1698000000,
        "Size":        22020096,
        "VirtualSize": 22020096,
    },
]

_VERSION = {
    "Version":       "19.03.15",
    "ApiVersion":    "1.40",
    "MinAPIVersion": "1.12",
    "GitCommit":     "99e3ed8",
    "GoVersion":     "go1.13.15",
    "Os":            "linux",
    "Arch":          "arm",
    "KernelVersion": "3.10.14",
    "BuildTime":     "2021-09-23T15:45:00.000000000+00:00",
}

_INFO = {
    "ID":              "FAKE:DOCK:RINFO:0001",
    "Containers":      2,
    "ContainersRunning": 2,
    "ContainersPaused": 0,
    "ContainersStopped": 0,
    "Images":          2,
    "Driver":          "overlay2",
    "MemoryLimit":     True,
    "SwapLimit":       True,
    "KernelMemory":    True,
    "CpuCfsPeriod":    True,
    "CpuCfsQuota":     True,
    "IPv4Forwarding":  True,
    "BridgeNfIptables": True,
    "BridgeNfIp6tables": True,
    "OomKillDisable":  True,
    "NGoroutines":     41,
    "LoggingDriver":   "json-file",
    "DockerRootDir":   "/var/lib/docker",
    "HttpProxy":       "",
    "HttpsProxy":      "",
    "NoProxy":         "",
    "Name":            "ipcam-host",
    "OperatingSystem": "Linux/ARM",
    "OSType":          "linux",
    "Architecture":    "armv7l",
    "NCPU":            4,
    "MemTotal":        536870912,
    "ServerVersion":   "19.03.15",
}


# ── HTTP helpers ──────────────────────────────────────────────────────────────

def _json_resp(status, body_obj, extra_headers=""):
    body = json.dumps(body_obj, indent=2).encode()
    status_text = {200: "OK", 201: "Created", 204: "No Content",
                   400: "Bad Request", 404: "Not Found", 409: "Conflict",
                   500: "Internal Server Error"}.get(status, "OK")
    headers = (
        f"HTTP/1.1 {status} {status_text}\r\n"
        f"Content-Type: application/json\r\n"
        f"Content-Length: {len(body)}\r\n"
        f"Server: Docker/19.03.15 (linux)\r\n"
        f"Api-Version: 1.40\r\n"
        f"Date: {time.strftime('%a, %d %b %Y %H:%M:%S GMT', time.gmtime())}\r\n"
        + extra_headers +
        "\r\n"
    )
    return headers.encode() + body


def _stream_resp(lines):
    """Return chunked-looking exec output."""
    body = b""
    for line in lines:
        enc = (line + "\n").encode()
        # Docker multiplexed stream: 1-byte type, 3-byte pad, 4-byte size, data
        size = len(enc)
        body += b"\x01\x00\x00\x00" + size.to_bytes(4, "big") + enc
    headers = (
        "HTTP/1.1 200 OK\r\n"
        "Content-Type: application/vnd.docker.raw-stream\r\n"
        f"Content-Length: {len(body)}\r\n"
        "Server: Docker/19.03.15 (linux)\r\n"
        "Api-Version: 1.40\r\n"
        "\r\n"
    )
    return headers.encode() + body


def _parse_request(raw):
    try:
        header_part, _, body = raw.partition(b"\r\n\r\n")
        lines = header_part.decode(errors="replace").split("\r\n")
        method, path, _ = lines[0].split(" ", 2)
        headers = {}
        for line in lines[1:]:
            if ": " in line:
                k, v = line.split(": ", 1)
                headers[k.lower()] = v
        return method.upper(), path.split("?")[0], body, headers
    except Exception:
        return None, None, b"", {}


# ── main handler ──────────────────────────────────────────────────────────────

def handle_docker(conn, addr, log_attack=None, inc_counter=None):
    ip = addr[0]
    attacks = []

    try:
        conn.settimeout(30)
        buf = b""

        for _ in range(50):
            try:
                chunk = conn.recv(8192)
                if not chunk:
                    break
                buf += chunk
            except socket.timeout:
                break

            if b"\r\n\r\n" not in buf:
                continue

            method, path, body, headers = _parse_request(buf)
            buf = b""

            if not method:
                continue

            body_str = body.decode(errors="replace")
            body_obj = {}
            if body_str.strip():
                try:
                    body_obj = json.loads(body_str)
                except Exception:
                    pass

            # ── route dispatch ────────────────────────────────────────────
            resp = None

            # Version / Info
            if path in ("/version", "/_ping"):
                resp = _json_resp(200, _VERSION if path == "/version" else "OK")

            elif path == "/info":
                resp = _json_resp(200, _INFO)

            # Containers list
            elif re.match(r"^/v?\d*\.?\d*/containers/json$", path) or path == "/containers/json":
                resp = _json_resp(200, _FAKE_CONTAINERS)

            # Container inspect
            elif re.match(r"^/containers/([^/]+)/json$", path):
                cid = path.split("/")[2]
                c = next((c for c in _FAKE_CONTAINERS if c["Id"].startswith(cid) or cid in c["Names"][0]), None)
                if c:
                    resp = _json_resp(200, c)
                else:
                    resp = _json_resp(404, {"message": f"No such container: {cid}"})

            # Images list
            elif path in ("/images/json", "/v1.40/images/json"):
                resp = _json_resp(200, _FAKE_IMAGES)

            # Container create — the main attack surface
            elif path == "/containers/create" and method == "POST":
                image    = body_obj.get("Image", "")
                cmd      = body_obj.get("Cmd", [])
                binds    = body_obj.get("HostConfig", {}).get("Binds", [])
                privil   = body_obj.get("HostConfig", {}).get("Privileged", False)
                net_mode = body_obj.get("HostConfig", {}).get("NetworkMode", "")
                pid_mode = body_obj.get("HostConfig", {}).get("PidMode", "")

                fake_id = "".join(random.choices("0123456789abcdef", k=12))
                resp = _json_resp(201, {"Id": fake_id * 5, "Warnings": []})

                # Classify attack intent
                attack_type = "DOCKER_CONTAINER_CREATE"
                note = ""
                if privil:
                    attack_type = "DOCKER_PRIVILEGED_ESCAPE"
                    note = "Privileged container = host root escape"
                elif "host" in net_mode or "host" in pid_mode:
                    attack_type = "DOCKER_HOST_NAMESPACE_ABUSE"
                    note = f"NetworkMode={net_mode} PidMode={pid_mode}"
                elif any(":/host" in b or ":/etc" in b or ":/root" in b for b in binds):
                    attack_type = "DOCKER_HOSTFS_MOUNT"
                    note = f"Mounts: {binds}"
                elif any(x in " ".join(cmd).lower() for x in ["xmrig", "minerd", "cryptonight", "monero"]):
                    attack_type = "DOCKER_CRYPTOMINER_DEPLOY"
                    note = f"Cmd: {' '.join(cmd[:5])}"
                elif any(x in " ".join(cmd).lower() for x in ["bash -i", "nc -e", "mkfifo", "socat"]):
                    attack_type = "DOCKER_REVERSE_SHELL"
                    note = f"Cmd: {' '.join(cmd[:5])}"

                attacks.append(attack_type)
                if log_attack:
                    log_attack(ip, 2375, attack_type, json.dumps({
                        "image": image, "cmd": cmd[:10], "binds": binds,
                        "privileged": privil, "network_mode": net_mode,
                        "note": note,
                    }))

            # Container start
            elif re.match(r"^/containers/([^/]+)/start$", path) and method == "POST":
                resp = _json_resp(204, {})
                if log_attack:
                    cid = path.split("/")[2]
                    log_attack(ip, 2375, "DOCKER_CONTAINER_START", json.dumps({"container": cid}))

            # Exec create (command injection)
            elif re.match(r"^/containers/([^/]+)/exec$", path) and method == "POST":
                cmd = body_obj.get("Cmd", [])
                fake_exec_id = "".join(random.choices("0123456789abcdef", k=64))
                resp = _json_resp(201, {"Id": fake_exec_id})
                if log_attack:
                    log_attack(ip, 2375, "DOCKER_EXEC_CREATE", json.dumps({
                        "container": path.split("/")[2],
                        "cmd": cmd[:10],
                        "note": "exec into running container"
                    }))

            # Exec start (get output)
            elif re.match(r"^/exec/([^/]+)/start$", path) and method == "POST":
                resp = _stream_resp(["uid=0(root) gid=0(root) groups=0(root)"])
                if log_attack:
                    log_attack(ip, 2375, "DOCKER_EXEC_START", json.dumps({
                        "exec_id": path.split("/")[2][:16]
                    }))

            # Pull image (could be malicious image)
            elif path.startswith("/images/create") and method == "POST":
                from_image = ""
                for part in path.split("?")[-1].split("&"):
                    if part.startswith("fromImage="):
                        from_image = part[10:]
                resp = _json_resp(200, {"status": f"Pulling from {from_image}", "progressDetail": {}})
                if log_attack:
                    log_attack(ip, 2375, "DOCKER_IMAGE_PULL", json.dumps({
                        "image": from_image,
                        "note": "attacker pulling image — possibly malicious"
                    }))

            # Swarm / service (Kubernetes-style lateral movement)
            elif path.startswith("/swarm") or path.startswith("/services") or path.startswith("/nodes"):
                resp = _json_resp(200, {"ID": "fake-swarm-id", "Nodes": 1})

            # Networks
            elif path.startswith("/networks"):
                resp = _json_resp(200, [{"Id": "bridge1", "Name": "bridge", "Driver": "bridge"}])

            # Volumes
            elif path.startswith("/volumes"):
                resp = _json_resp(200, {"Volumes": [], "Warnings": None})

            # Default — 404
            else:
                resp = _json_resp(404, {"message": f"page not found"})

            if resp:
                conn.sendall(resp)

            # Keep-alive — check Connection header
            if headers.get("connection", "").lower() == "close":
                break

    except (ConnectionResetError, BrokenPipeError, OSError):
        pass
    except Exception as e:
        logger.debug("Docker handler error from %s: %s", ip, e)
    finally:
        if attacks and log_attack:
            log_attack(ip, 2375, "DOCKER_SESSION_SUMMARY", json.dumps({"attacks": attacks}))
        try:
            conn.close()
        except Exception:
            pass


def start_docker_server(host="0.0.0.0", port=2375, log_attack=None, inc_counter=None):
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((host, port))
    srv.listen(50)
    logger.info("Docker API honeypot listening on %s:%d", host, port)
    while True:
        try:
            conn, addr = srv.accept()
            t = threading.Thread(
                target=handle_docker,
                args=(conn, addr, log_attack, inc_counter),
                daemon=True,
            )
            t.start()
        except Exception as e:
            logger.error("Docker accept error: %s", e)
