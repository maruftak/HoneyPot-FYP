#!/usr/bin/env python3
"""
Tor Exit Node Detector — SENTINEL Honeypot
Downloads and caches the Tor exit node list.
"""

import time
import threading

class TorDetector:
    def __init__(self, cache_duration=3600):
        self.exit_nodes = set()
        self.last_update = 0
        self.cache_duration = cache_duration
        self.updating = False
        # Try to load on init in background
        threading.Thread(target=self._do_update, daemon=True).start()

    def _do_update(self):
        if self.updating:
            return
        self.updating = True
        try:
            import requests
            resp = requests.get(
                "https://check.torproject.org/torbulkexitlist",
                timeout=15
            )
            if resp.status_code == 200:
                nodes = {line.strip() for line in resp.text.splitlines()
                         if line.strip() and not line.startswith("#")}
                self.exit_nodes = nodes
                self.last_update = time.time()
                print(f"[Tor] ✓ Loaded {len(self.exit_nodes)} exit nodes")
        except Exception as e:
            print(f"[Tor] Could not fetch exit node list: {e}")
        finally:
            self.updating = False

    def is_tor_exit_node(self, ip: str) -> bool:
        if time.time() - self.last_update > self.cache_duration:
            threading.Thread(target=self._do_update, daemon=True).start()
        return ip in self.exit_nodes

    def get_exit_node_count(self) -> int:
        return len(self.exit_nodes)

    def get_last_update(self) -> str:
        if self.last_update == 0:
            return "Never"
        return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(self.last_update))
