#!/usr/bin/env python3
"""
log_monitor.py

Log monitor that:
 - tails a logfile (default user-provided)
 - OR tails a named pipe (FIFO)
 - OR runs in simulate mode and generates sample lines
Detects:
 - multiple failed password attempts (threshold within time window)
 - suspicious sudo uses (auth failures / session opened)
 - keywords: malware, hack, attack

No sudo required. Use --simulate for built-in test data, or --fifo to create/use a FIFO you can echo into.

Usage examples:
  # Simulate events (no external files)
  python3 log_monitor.py --simulate

  # Monitor a FIFO (create it first in another shell or let the script create it)
  python3 log_monitor.py --fifo ~/test_pipe

  # Monitor an actual logfile you can read
  python3 log_monitor.py --logfile ~/some_log.txt --alert-file ~/alerts.log
"""
import argparse
import time
import os
import re
import random
from collections import defaultdict, deque
from datetime import datetime, timedelta
from threading import Thread, Event

# ----------------------------
# Defaults
# ----------------------------
DEFAULT_POLL_INTERVAL = 0.5
DEFAULT_FAILED_THRESHOLD = 3
DEFAULT_WINDOW_SECONDS = 300
ALERT_COOLDOWN_SECONDS = 300

RE_FAILED_PW = re.compile(
    r'(Failed password for (?P<user1>\S+) from (?P<ip1>\S+))|'
    r'(authentication failure;.*rhost=(?P<ip2>\S+).*user=(?P<user2>\S+))',
    re.IGNORECASE
)
RE_SUDO_AUTH_FAIL = re.compile(r'sudo: .*authentication failure', re.IGNORECASE)
RE_SUDO_SESSION_OPEN = re.compile(r'sudo: .*session opened for user (?P<suser>\S+)', re.IGNORECASE)
KEYWORD_RE = re.compile(r'\b(malware|hack|attack)\b', re.IGNORECASE)

def now_ts():
    return datetime.now()
def format_ts(dt=None):
    if dt is None: dt = now_ts()
    return dt.strftime("%Y-%m-%d %H:%M:%S")
def alert_print(alert_file, msg):
    ts = format_ts()
    line = f"[ALERT {ts}] {msg}"
    print(line)
    if alert_file:
        try:
            with open(alert_file, "a") as f:
                f.write(line + "\n")
        except Exception as e:
            print(f"[!] Failed to write to alert file {alert_file}: {e}")

class LogMonitor:
    def __init__(self, logfile=None, fifo=None, alert_file=None,
                 poll_interval=DEFAULT_POLL_INTERVAL,
                 failed_threshold=DEFAULT_FAILED_THRESHOLD,
                 window_seconds=DEFAULT_WINDOW_SECONDS,
                 simulate=False):
        self.logfile = os.path.expanduser(logfile) if logfile else None
        self.fifo = os.path.expanduser(fifo) if fifo else None
        self.alert_file = os.path.expanduser(alert_file) if alert_file else None
        self.poll_interval = poll_interval
        self.failed_threshold = failed_threshold
        self.window_seconds = window_seconds
        self.simulate = simulate

        self.failed_tracker = defaultdict(deque)
        self.last_alert_time = {}
        self._fh = None
        self._stop_event = Event()

    def _open_and_seek_end(self):
        # Ensure alert dir exists
        if self.alert_file:
            os.makedirs(os.path.dirname(self.alert_file) or ".", exist_ok=True)

        if self.fifo:
            # Create FIFO if it doesn't exist
            if not os.path.exists(self.fifo):
                try:
                    os.mkfifo(self.fifo)
                    print(f"[+] Created FIFO at {self.fifo}")
                except Exception as e:
                    print(f"[!] Could not create FIFO {self.fifo}: {e}")
            # open FIFO for reading (blocking until writer opens)
            self._fh = open(self.fifo, "r", errors="ignore")
        elif self.logfile:
            if not os.path.exists(self.logfile):
                open(self.logfile, "a").close()
            self._fh = open(self.logfile, "r", errors="ignore")
            self._fh.seek(0, os.SEEK_END)

    def _cleanup_old(self, dq):
        cutoff = now_ts() - timedelta(seconds=self.window_seconds)
        while dq and dq[0] < cutoff:
            dq.popleft()

    def _maybe_alert_failed(self, key, dq):
        self._cleanup_old(dq)
        count = len(dq)
        if count >= self.failed_threshold:
            last = self.last_alert_time.get(key)
            if last and (now_ts() - last).total_seconds() < ALERT_COOLDOWN_SECONDS:
                return
            self.last_alert_time[key] = now_ts()
            alert_print(self.alert_file,
                        f"{count} failed password attempts for {key[1]} within {self.window_seconds}s (threshold {self.failed_threshold})")

    def _maybe_alert_generic(self, key_name, identifier, message):
        key = (key_name, identifier)
        last = self.last_alert_time.get(key)
        if last and (now_ts() - last).total_seconds() < ALERT_COOLDOWN_SECONDS:
            return
        self.last_alert_time[key] = now_ts()
        alert_print(self.alert_file, message)

    def _process_line(self, line):
        line = line.strip()
        if not line:
            return
        m = RE_FAILED_PW.search(line)
        if m:
            user = m.group("user1") or m.group("user2") or "-"
            ip = m.group("ip1") or m.group("ip2") or "-"
            key = ("failed", ip if ip != "-" else user)
            self.failed_tracker[key].append(now_ts())
            self._maybe_alert_failed(key, self.failed_tracker[key])
            return
        if RE_SUDO_AUTH_FAIL.search(line):
            self._maybe_alert_generic(("sudo","authfail"), "sudo_authfail",
                                      f"suspicious sudo authentication failure: {line}")
            return
        m2 = RE_SUDO_SESSION_OPEN.search(line)
        if m2:
            suser = m2.group("suser") or "(unknown)"
            self._maybe_alert_generic(("sudo","session_open"), suser,
                                      f"sudo session opened for user {suser}: {line}")
            return
        m3 = KEYWORD_RE.search(line)
        if m3:
            kw = m3.group(1)
            self._maybe_alert_generic(("keyword", kw.lower()), kw.lower(),
                                      f"keyword '{kw}' found in log line: {line}")
            return

    def _simulate_worker(self):
        users = ["alice","bob","carol","dave"]
        ips = ["10.0.0.5","192.168.1.10","172.16.5.4"]
        samples = [
            lambda: f"{format_ts()} myhost sshd[1234]: Failed password for invalid user {random.choice(users)} from {random.choice(ips)} port 4242 ssh2",
            lambda: f"{format_ts()} myhost sudo: pam_unix(sudo:auth): authentication failure; .* rhost=  user={random.choice(users)}",
            lambda: f"{format_ts()} myhost sudo: {random.choice(users)} : TTY=pts/0 ; PWD=/home/{random.choice(users)} ; USER=root ; COMMAND=/bin/ls ; SESSION opened for user root",
            lambda: f"{format_ts()} myhost app: possible malware signature detected",
            lambda: f"{format_ts()} myhost app: unexpected hack attempt blocked",
            lambda: f"{format_ts()} myhost app: normal informational line"
        ]
        while not self._stop_event.is_set():
            line = random.choice(samples)()
            print(f"[SIM] {line}")
            self._process_line(line)
            time.sleep(random.uniform(0.7, 1.8))

    def run(self):
        print(f"[{format_ts()}] Starting log monitor")
        if self.simulate:
            print("  Running in SIMULATE mode (generating sample log lines).")
            t = Thread(target=self._simulate_worker, daemon=True)
            t.start()
            try:
                while True:
                    time.sleep(0.2)
            except KeyboardInterrupt:
                self._stop_event.set()
                print("\n[+] Stopping simulator.")
            return

        # normal tailing mode (file / fifo / stdin)
        if self.fifo:
            print(f"  Tailing FIFO: {self.fifo}")
        elif self.logfile:
            print(f"  Tailing logfile: {self.logfile}")
        else:
            print("  Reading lines from STDIN (pipe input). Use --stdin or feed via pipe).")

        if self.fifo or self.logfile:
            self._open_and_seek_end()

        try:
            # If no fh (stdin mode), read from stdin
            if not self._fh:
                print("[+] Reading from STDIN. Type lines and press Enter (Ctrl+C to stop).")
                while True:
                    line = input()
                    self._process_line(line)
            else:
                while True:
                    where = self._fh.tell()
                    line = self._fh.readline()
                    if not line:
                        time.sleep(self.poll_interval)
                        self._fh.seek(where)
                    else:
                        self._process_line(line)
        except KeyboardInterrupt:
            print("\n[+] Stopping monitor (keyboard interrupt).")
        finally:
            if self._fh:
                self._fh.close()

def main():
    p = argparse.ArgumentParser(description="Simple log monitoring tool (no sudo required).")
    group = p.add_mutually_exclusive_group(required=False)
    group.add_argument("--logfile", help="Path to logfile to tail")
    group.add_argument("--fifo", help="Path to FIFO (named pipe) to read from")
    group.add_argument("--simulate", action="store_true", help="Run built-in simulator (no files needed)")
    p.add_argument("--alert-file", help="File to append alerts to (optional)", default=None)
    p.add_argument("--failed-threshold", type=int, default=DEFAULT_FAILED_THRESHOLD)
    p.add_argument("--window-seconds", type=int, default=DEFAULT_WINDOW_SECONDS)
    p.add_argument("--poll", type=float, default=DEFAULT_POLL_INTERVAL)
    args = p.parse_args()

    mon = LogMonitor(logfile=args.logfile, fifo=args.fifo, alert_file=args.alert_file,
                     poll_interval=args.poll, failed_threshold=args.failed_threshold,
                     window_seconds=args.window_seconds, simulate=args.simulate)
    mon.run()

if __name__ == "__main__":
    main()
