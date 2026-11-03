"""
test_functionality.py - functional requirement checks. DO NOT MODIFY.

This checks that your messaging system does what the coursework requires. It
does not look at how your security works: it starts your server and clients as
separate programs, types commands into the clients exactly as a user would, and
reads what they print. It therefore runs whatever cryptography or network
design you chose, as long as you followed the rules in the brief (keep the
command-line arguments, the /msg and /quit commands, and the ui_ output
formats; put files in the working directory; no input at start-up).

Each check prints which functional requirement (FR1-FR6) it is testing.

Run it from the directory containing your messaging_server.py and
messaging_client.py:

    python3 test_functionality.py

Your files are copied to a temporary directory first, so your own directory is
not changed. The full output of every program is saved there; the path is
printed at the end.
"""

import os
import re
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time

STARTUP_TIMEOUT = 20    # seconds for the server or a client to start
DELIVERY_TIMEOUT = 20   # seconds for a message to arrive
QUIET_PERIOD = 4        # seconds to wait when checking nothing extra arrives

ID_RE = re.compile(r"Your client ID: (\S+)")
MSG_RE = re.compile(r"\[from (\S+)\] (.*)$")
REJECT_RE = re.compile(r"\[rejected from (\S+)\] (.*)$")

TOTAL_CHECKS = 15   # checks that cannot run because an earlier step failed count as failures


# ---------------------------------------------------------------------------
# Running programs and reading their output
# ---------------------------------------------------------------------------


class Program:
    """A running server or client whose output is captured line by line."""

    def __init__(self, label, args, cwd, log_dir):
        self.label = label
        env = dict(os.environ, PYTHONUNBUFFERED="1", PYTHONIOENCODING="utf-8")
        self.log = open(os.path.join(log_dir, f"{label}.log"), "a", encoding="utf-8")
        self.log.write(f"===== started: {' '.join(args)}\n")
        self.lines = []
        self.cond = threading.Condition()
        self.proc = subprocess.Popen(
            [sys.executable, *args], cwd=cwd, env=env, stdin=subprocess.PIPE,
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
            encoding="utf-8", errors="replace", bufsize=1)
        threading.Thread(target=self._reader, daemon=True).start()

    def _reader(self):
        for raw in self.proc.stdout:
            line = raw.rstrip("\n")
            self.log.write(line + "\n")
            self.log.flush()
            with self.cond:
                self.lines.append(line)
                self.cond.notify_all()
        with self.cond:
            self.cond.notify_all()

    def mark(self):
        with self.cond:
            return len(self.lines)

    def wait_for(self, regex, start=0, timeout=DELIVERY_TIMEOUT, predicate=None):
        deadline = time.time() + timeout
        i = start
        with self.cond:
            while True:
                while i < len(self.lines):
                    m = regex.search(self.lines[i])
                    i += 1
                    if m and (predicate is None or predicate(m)):
                        return m
                remaining = deadline - time.time()
                if remaining <= 0 or (self.proc.poll() is not None and i >= len(self.lines)):
                    return None
                self.cond.wait(min(remaining, 0.5))

    def matches_since(self, regex, start):
        with self.cond:
            return [m for m in (regex.search(l) for l in self.lines[start:]) if m]

    def type(self, line):
        try:
            self.proc.stdin.write(line + "\n")
            self.proc.stdin.flush()
        except (BrokenPipeError, OSError):
            pass

    def tail(self, n=12):
        with self.cond:
            return self.lines[-n:]

    def stop(self):
        if self.proc.poll() is None:
            self.type("/quit")
            try:
                self.proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.proc.kill()
                self.proc.wait()
        self.log.write("===== stopped\n")
        self.log.flush()


# ---------------------------------------------------------------------------
# Test harness
# ---------------------------------------------------------------------------


class Tester:
    def __init__(self, workdir, log_dir, port):
        self.workdir, self.log_dir, self.port = workdir, log_dir, port
        self.results = []
        self.running = []
        self.all_programs = []

    def record(self, fr, description, passed, programs=()):
        self.results.append((fr, description, bool(passed)))
        print(f"  [{'PASS' if passed else 'FAIL'}] {fr}: {description}")
        if not passed:
            for p in programs:
                print(f"         last output from {p.label}:")
                for line in p.tail():
                    print(f"           | {line[:160]}")

    def start_server(self):
        server = Program("server", ["messaging_server.py", "--host", "localhost",
                                    "--port", str(self.port)], self.workdir, self.log_dir)
        self.running.append(server)
        self.all_programs.append(server)
        deadline = time.time() + STARTUP_TIMEOUT
        while time.time() < deadline and server.proc.poll() is None:
            try:
                with socket.create_connection(("localhost", self.port), timeout=1):
                    return server, True
            except OSError:
                time.sleep(0.3)
        return server, False

    def start_client(self, user, new=True):
        args = ["messaging_client.py", "--host", "localhost", "--port", str(self.port),
                "--state", f"fntest_{user}.state"]
        if new:
            args += ["--name", user]
        client = Program(user, args, self.workdir, self.log_dir)
        self.running.append(client)
        self.all_programs.append(client)
        m = client.wait_for(ID_RE, timeout=STARTUP_TIMEOUT)
        client.client_id = m.group(1) if m else None
        return client

    def stop(self, program):
        program.stop()
        if program in self.running:
            self.running.remove(program)

    def send_and_wait(self, sender, recipient, text):
        start = recipient.mark()
        sender.type(f"/msg {recipient.client_id} {text}")
        return recipient.wait_for(MSG_RE, start, predicate=lambda m: m.group(2) == text)

    def deliver(self, sender, recipient, text):
        m = self.send_and_wait(sender, recipient, text)
        return m is not None and m.group(1) == sender.client_id

    def stop_all(self):
        for p in reversed(list(self.running)):
            p.stop()


def free_port():
    with socket.socket() as s:
        s.bind(("localhost", 0))
        return s.getsockname()[1]


def run_tests(t: Tester):
    print("\nServer startup")
    server, ok = t.start_server()
    t.record("FR1", "the server starts and accepts connections", ok, [server])
    if not ok:
        return

    print("\nFR1  Connect and register")
    alice = t.start_client("alice")
    bob = t.start_client("bob")
    t.record("FR1", "a client connects, registers, and is given a client ID", alice.client_id, [alice, server])
    t.record("FR1", "a second client registers and is given a different ID",
             bob.client_id and bob.client_id != alice.client_id, [bob, server])
    impostor = Program("alice2", ["messaging_client.py", "--host", "localhost", "--port", str(t.port),
                                  "--state", "fntest_alice2.state", "--name", "alice"], t.workdir, t.log_dir)
    t.running.append(impostor)
    m = impostor.wait_for(ID_RE, timeout=STARTUP_TIMEOUT)
    t.record("FR1", "a username that is already taken is refused", m is None, [impostor])
    t.stop(impostor)
    if not (alice.client_id and bob.client_id):
        return

    print("\nFR2  Send a message, with the sender shown")
    m = t.send_and_wait(alice, bob, "Hello Bob, this is Alice.")
    t.record("FR2", "a client can send a message to another client by client ID", m is not None, [alice, bob])
    t.record("FR2", "the recipient sees which client the message came from",
             m is not None and m.group(1) == alice.client_id, [alice, bob])

    print("\nFR3  Server forwards to the intended recipient")
    carol = t.start_client("carol")
    if carol.client_id:
        bob_start = bob.mark()
        got = t.deliver(alice, carol, "For Carol only.")
        time.sleep(QUIET_PERIOD)
        leaked = [mm.group(2) for mm in bob.matches_since(MSG_RE, bob_start)
                  if mm.group(2) == "For Carol only."]
        t.record("FR3", "a message is forwarded to the intended recipient, and no one else",
                 got and not leaked, [alice, carol, bob])

    print("\nFR4  Message content arrives intact")
    t.record("FR4", "a message with punctuation arrives intact",
             t.deliver(alice, bob, "Hi! Cost: $5 & 50% off (today) - ok? \"yes\" #1 @home [x] {y} <z>"),
             [alice, bob])
    long_text = ("abcdefghij" * 30)   # 300 characters
    t.record("FR4", "a 300-character message arrives intact",
             t.deliver(alice, bob, long_text), [alice, bob])

    print("\nFR5  Timely delivery, including to an offline client")
    t.record("FR5", "a message arrives within a few seconds without recipient action",
             t.deliver(bob, alice, "Did this arrive promptly?"), [bob, alice])
    dave = t.start_client("dave")
    dave_id = dave.client_id
    if dave_id:
        t.stop(dave)
        before = alice.mark()
        offline_text = "Dave, read this when you are back."
        alice.type(f"/msg {dave_id} {offline_text}")
        time.sleep(3)
        sent_ok = not any(l.startswith("! ") for l in alice.lines[before:])
        t.record("FR5", "a client can send to a recipient whose client is not running", sent_ok, [alice])
        dave = t.start_client("dave", new=False)
        m = dave.wait_for(MSG_RE, predicate=lambda m: m.group(2) == offline_text)
        t.record("FR5", "the message is delivered when the recipient's client next starts",
                 m is not None and m.group(1) == alice.client_id, [dave, alice])

    print("\nFR6  Restart and carry on")
    old_id = alice.client_id
    t.stop(alice)
    alice = t.start_client("alice", new=False)
    t.record("FR6", "a restarted client keeps the same client ID", alice.client_id == old_id, [alice, server])
    if alice.client_id:
        t.record("FR6", "a restarted client can still send and receive",
                 t.deliver(alice, bob, "Back again.") and t.deliver(bob, alice, "Welcome back."),
                 [alice, bob])

    problems = []
    for p in t.all_programs:
        with p.cond:
            for line in p.lines:
                if "Traceback" in line:
                    problems.append(f"{p.label}: {line}")
    t.record("FR1", "no program crashed during the tests", not problems)
    for line in problems[:8]:
        print(f"           | {line[:160]}")


def main():
    source = os.path.abspath(".")
    for f in ("messaging_server.py", "messaging_client.py"):
        if not os.path.exists(os.path.join(source, f)):
            sys.exit(f"Cannot find {f} in {source}")

    base = tempfile.mkdtemp(prefix="fntest_")
    workdir = os.path.join(base, "solution")
    log_dir = os.path.join(base, "logs")
    shutil.copytree(source, workdir, ignore=shutil.ignore_patterns("__pycache__", "fntest_*"))
    os.makedirs(log_dir)

    t = Tester(workdir, log_dir, free_port())
    print(f"Testing the solution in {source}")
    try:
        run_tests(t)
    finally:
        t.stop_all()

    passed = sum(1 for _, _, ok in t.results if ok)
    not_run = TOTAL_CHECKS - len(t.results)
    if not_run > 0:
        print(f"\n  [FAIL] {not_run} check(s) could not run because an earlier step failed")
    print(f"\n{passed}/{TOTAL_CHECKS} functional checks passed")
    print(f"Program output logs: {log_dir}")
    sys.exit(0 if passed == TOTAL_CHECKS else 1)


if __name__ == "__main__":
    main()
