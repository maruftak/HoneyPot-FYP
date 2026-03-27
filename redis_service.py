"""
Redis honeypot — port 6379
Emulates a real Redis 3.x instance (common on exposed IoT gateways / NVRs).
Logs all commands, detects mass-scanners and CONFIG SET / SLAVEOF abuse.
"""

import socket
import threading
import time
import random
import json
import logging

logger = logging.getLogger("honeypot.redis")

# ── fake dataset ──────────────────────────────────────────────────────────────
_FAKE_KEYS = {
    "admin_password":     "Admin@2024!",
    "device_token":       "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.fake",
    "session:abc123":     '{"user":"admin","ip":"192.168.1.5","exp":9999999999}',
    "config:smtp_pass":   "SmtpP@ss2024",
    "config:db_url":      "mysql://root:DBr00t@localhost/ipcam",
    "last_backup_path":   "/mnt/dvr_rec/backup_2024.tar.gz",
    "cloud_api_key":      "sk-live-HikvisionCloud-FAKEKEY00001",
}

_INFO_RESP = (
    "# Server\r\n"
    "redis_version:3.0.6\r\n"
    "redis_git_sha1:00000000\r\n"
    "redis_git_dirty:0\r\n"
    "redis_build_id:0\r\n"
    "redis_mode:standalone\r\n"
    "os:Linux 3.10.14 armv7l\r\n"
    "arch_bits:32\r\n"
    "multiplexing_api:epoll\r\n"
    "gcc_version:4.8.3\r\n"
    "process_id:1112\r\n"
    "run_id:a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2\r\n"
    "tcp_port:6379\r\n"
    "uptime_in_seconds:2592000\r\n"
    "uptime_in_days:30\r\n"
    "hz:10\r\n"
    "lru_clock:12345678\r\n"
    "executable:/usr/bin/redis-server\r\n"
    "config_file:/etc/redis/redis.conf\r\n"
    "# Clients\r\n"
    "connected_clients:3\r\n"
    "client_longest_output_list:0\r\n"
    "client_biggest_input_buf:0\r\n"
    "blocked_clients:0\r\n"
    "# Memory\r\n"
    "used_memory:824320\r\n"
    "used_memory_human:805.00K\r\n"
    "used_memory_rss:2850816\r\n"
    "used_memory_peak:991232\r\n"
    "used_memory_peak_human:968.00K\r\n"
    "total_system_memory:131072000\r\n"
    "total_system_memory_human:125.00M\r\n"
    "# Stats\r\n"
    "total_connections_received:4128\r\n"
    "total_commands_processed:9843\r\n"
    "instantaneous_ops_per_sec:2\r\n"
    "# Replication\r\n"
    "role:master\r\n"
    "connected_slaves:0\r\n"
    "master_replid:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\r\n"
    "master_repl_offset:0\r\n"
    "# Keyspace\r\n"
    "db0:keys=7,expires=0,avg_ttl=0\r\n"
)

_CONFIG_GET_RESP = {
    "dir":        "/var/lib/redis",
    "dbfilename": "dump.rdb",
    "bind":       "0.0.0.0",
    "requirepass": "",
    "save":       "900 1 300 10 60 10000",
    "loglevel":   "notice",
    "logfile":    "/var/log/redis/redis-server.log",
    "maxmemory":  "0",
    "appendonly": "no",
}


def _bulk(s):
    if s is None:
        return b"$-1\r\n"
    enc = s.encode()
    return f"${len(enc)}\r\n".encode() + enc + b"\r\n"


def _array(items):
    out = f"*{len(items)}\r\n".encode()
    for i in items:
        out += _bulk(i)
    return out


def _inline(s):
    return f"+{s}\r\n".encode()


def _err(s):
    return f"-ERR {s}\r\n".encode()


def _int(n):
    return f":{n}\r\n".encode()


# ── RESP parser ───────────────────────────────────────────────────────────────

def _parse_resp(buf):
    """Parse one RESP command from buf. Returns (args_list, remaining_bytes) or (None, buf)."""
    if not buf:
        return None, buf
    if buf[0:1] == b"*":
        # Array command
        try:
            end = buf.index(b"\r\n")
        except ValueError:
            return None, buf
        count = int(buf[1:end])
        pos = end + 2
        args = []
        for _ in range(count):
            if pos >= len(buf) or buf[pos:pos+1] != b"$":
                return None, buf
            try:
                end2 = buf.index(b"\r\n", pos)
            except ValueError:
                return None, buf
            blen = int(buf[pos+1:end2])
            pos = end2 + 2
            if pos + blen + 2 > len(buf):
                return None, buf
            args.append(buf[pos:pos+blen].decode(errors="replace"))
            pos += blen + 2
        return args, buf[pos:]
    else:
        # Inline command
        try:
            end = buf.index(b"\r\n")
        except ValueError:
            try:
                end = buf.index(b"\n")
            except ValueError:
                return None, buf
        line = buf[:end].decode(errors="replace").strip()
        remaining = buf[end+2:] if buf[end:end+2] == b"\r\n" else buf[end+1:]
        return line.split(), remaining


# ── main handler ──────────────────────────────────────────────────────────────

def handle_redis(conn, addr, log_attack=None, inc_counter=None):
    ip = addr[0]
    commands_seen = []
    config_set_attempts = []

    try:
        conn.settimeout(30)
        buf = b""

        for _ in range(200):
            # read more data if needed
            try:
                chunk = conn.recv(4096)
                if not chunk:
                    break
                buf += chunk
            except socket.timeout:
                break

            while buf:
                args, buf = _parse_resp(buf)
                if args is None:
                    break
                if not args:
                    continue

                cmd = args[0].upper()
                rest = args[1:]
                commands_seen.append(cmd)

                # ── command dispatch ──
                if cmd == "PING":
                    if rest:
                        conn.sendall(_bulk(rest[0]))
                    else:
                        conn.sendall(_inline("PONG"))

                elif cmd == "INFO":
                    conn.sendall(_bulk(_INFO_RESP))

                elif cmd == "CLIENT":
                    sub = rest[0].upper() if rest else ""
                    if sub == "SETNAME":
                        conn.sendall(_inline("OK"))
                    elif sub == "GETNAME":
                        conn.sendall(_bulk(""))
                    elif sub == "LIST":
                        conn.sendall(_bulk("id=1 addr=127.0.0.1:48210 fd=8 name= age=0 idle=0 flags=N db=0 sub=0 psub=0 multi=-1 qbuf=0 qbuf-free=32768 obl=0 oll=0 omem=0 events=r cmd=client\n"))
                    else:
                        conn.sendall(_inline("OK"))

                elif cmd == "SELECT":
                    conn.sendall(_inline("OK"))

                elif cmd == "DBSIZE":
                    conn.sendall(_int(len(_FAKE_KEYS)))

                elif cmd == "KEYS":
                    pattern = rest[0] if rest else "*"
                    if pattern == "*":
                        conn.sendall(_array(list(_FAKE_KEYS.keys())))
                    else:
                        conn.sendall(_array([k for k in _FAKE_KEYS if pattern.strip("*") in k]))

                elif cmd == "GET":
                    key = rest[0] if rest else ""
                    val = _FAKE_KEYS.get(key)
                    conn.sendall(_bulk(val))
                    if val and log_attack:
                        log_attack(ip, 6379, "REDIS_GET_SENSITIVE", json.dumps({
                            "key": key, "value_preview": val[:60]
                        }))

                elif cmd == "SET":
                    conn.sendall(_inline("OK"))

                elif cmd == "DEL":
                    conn.sendall(_int(1))

                elif cmd == "EXISTS":
                    key = rest[0] if rest else ""
                    conn.sendall(_int(1 if key in _FAKE_KEYS else 0))

                elif cmd == "TYPE":
                    key = rest[0] if rest else ""
                    conn.sendall(_inline("string" if key in _FAKE_KEYS else "none"))

                elif cmd == "TTL":
                    conn.sendall(_int(-1))

                elif cmd == "EXPIRE":
                    conn.sendall(_int(1))

                elif cmd == "CONFIG":
                    sub = rest[0].upper() if rest else ""
                    if sub == "GET":
                        param = rest[1].lower() if len(rest) > 1 else ""
                        if param == "*":
                            items = []
                            for k, v in _CONFIG_GET_RESP.items():
                                items += [k, v]
                            conn.sendall(_array(items))
                        elif param in _CONFIG_GET_RESP:
                            conn.sendall(_array([param, _CONFIG_GET_RESP[param]]))
                        else:
                            conn.sendall(_array([]))
                    elif sub == "SET":
                        # Common RCE abuse: CONFIG SET dir/dbfilename + BGSAVE
                        param = rest[1] if len(rest) > 1 else ""
                        value = rest[2] if len(rest) > 2 else ""
                        config_set_attempts.append({"param": param, "value": value})
                        conn.sendall(_inline("OK"))
                        if log_attack:
                            log_attack(ip, 6379, "REDIS_CONFIG_SET_ABUSE", json.dumps({
                                "param": param, "value": value,
                                "note": "classic RCE technique via CONFIG SET dir+dbfilename+BGSAVE"
                            }))
                    elif sub == "RESETSTAT":
                        conn.sendall(_inline("OK"))
                    else:
                        conn.sendall(_err("unknown subcommand"))

                elif cmd in ("BGSAVE", "SAVE"):
                    conn.sendall(_inline("Background saving started" if cmd == "BGSAVE" else "OK"))
                    if config_set_attempts and log_attack:
                        log_attack(ip, 6379, "REDIS_RCE_BGSAVE_CHAIN", json.dumps({
                            "config_sets": config_set_attempts,
                            "trigger": cmd,
                            "note": "attacker tried CONFIG SET dir/dbfilename + BGSAVE for file write RCE"
                        }))

                elif cmd == "SLAVEOF":
                    # SLAVEOF attacker_ip port = replicate data exfil
                    slave_host = rest[0] if rest else ""
                    slave_port = rest[1] if len(rest) > 1 else ""
                    conn.sendall(_inline("OK"))
                    if log_attack:
                        log_attack(ip, 6379, "REDIS_SLAVEOF_ABUSE", json.dumps({
                            "slave_host": slave_host, "slave_port": slave_port,
                            "note": "SLAVEOF used to replicate data to attacker-controlled Redis"
                        }))

                elif cmd == "REPLICAOF":
                    conn.sendall(_inline("OK"))

                elif cmd == "FLUSHALL":
                    conn.sendall(_inline("OK"))
                    if log_attack:
                        log_attack(ip, 6379, "REDIS_FLUSHALL", json.dumps({"cmds_before": commands_seen[:-1]}))

                elif cmd == "FLUSHDB":
                    conn.sendall(_inline("OK"))

                elif cmd == "AUTH":
                    conn.sendall(_inline("OK"))

                elif cmd == "QUIT":
                    conn.sendall(_inline("OK"))
                    return

                elif cmd in ("MULTI", "EXEC", "DISCARD"):
                    conn.sendall(_inline("OK"))

                elif cmd == "COMMAND":
                    conn.sendall(_int(200))

                elif cmd == "DEBUG":
                    # Common in scanners
                    conn.sendall(_err("unknown command 'DEBUG'"))

                elif cmd == "EVAL":
                    # Lua RCE attempt
                    script = rest[0][:80] if rest else ""
                    conn.sendall(_err("NOSCRIPT No matching script. Please use EVAL."))
                    if log_attack:
                        log_attack(ip, 6379, "REDIS_EVAL_LUA_RCE", json.dumps({
                            "script_preview": script,
                            "note": "EVAL Lua RCE attempt"
                        }))

                elif cmd == "SUBSCRIBE":
                    # Respond with subscribe confirmation then hang (don't loop)
                    for channel in (rest or ["__common__"]):
                        resp = (f"*3\r\n$9\r\nsubscribe\r\n${len(channel)}\r\n{channel}\r\n:1\r\n").encode()
                        conn.sendall(resp)
                    break

                else:
                    conn.sendall(_err(f"unknown command '{cmd}'"))

    except (ConnectionResetError, BrokenPipeError, OSError):
        pass
    except Exception as e:
        logger.debug("Redis handler error from %s: %s", ip, e)
    finally:
        if commands_seen and log_attack:
            log_attack(ip, 6379, "REDIS_SESSION", json.dumps({
                "commands": commands_seen[:30],
                "config_set_attempts": config_set_attempts,
            }))
        try:
            conn.close()
        except Exception:
            pass


def start_redis_server(host="0.0.0.0", port=6379, log_attack=None, inc_counter=None):
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((host, port))
    srv.listen(50)
    logger.info("Redis honeypot listening on %s:%d", host, port)
    while True:
        try:
            conn, addr = srv.accept()
            t = threading.Thread(
                target=handle_redis,
                args=(conn, addr, log_attack, inc_counter),
                daemon=True,
            )
            t.start()
        except Exception as e:
            logger.error("Redis accept error: %s", e)
