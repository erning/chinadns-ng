#!/usr/bin/env python3
import ipaddress
import os
import signal
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import time
import ssl


def free_port():
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.close()
    return port


def encode_name(name):
    return b"".join(bytes([len(label)]) + label.encode() for label in name.split(".")) + b"\0"


def make_query(name, qtype, ident):
    return struct.pack("!HHHHHH", ident, 0x0100, 1, 0, 0, 0) + encode_name(name) + struct.pack("!HH", qtype, 1)


def question_end(message):
    pos = 12
    while message[pos]:
        pos += 1 + message[pos]
    return pos + 5


def make_answer(query, address):
    end = question_end(query)
    ip = ipaddress.ip_address(address)
    qtype = 1 if ip.version == 4 else 28
    header = struct.pack("!HHHHHH", struct.unpack_from("!H", query)[0], 0x8180, 1, 1, 0, 0)
    answer = struct.pack("!HHHIH", 0xC00C, qtype, 1, 60, len(ip.packed)) + ip.packed
    return header + query[12:end] + answer


def recv_exact(sock, size):
    data = bytearray()
    while len(data) < size:
        chunk = sock.recv(size - len(data))
        if not chunk:
            raise EOFError("unexpected EOF")
        data.extend(chunk)
    return bytes(data)


class MockDNS:
    def __init__(self, address, drop_first=0):
        self.address = address
        self.drop_first = drop_first
        self.port = free_port()
        self.stop_event = threading.Event()
        self.counts = {"udp": 0, "tcp": 0}
        self.udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.udp.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.udp.bind(("127.0.0.1", self.port))
        self.udp.settimeout(0.1)
        self.tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.tcp.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.tcp.bind(("127.0.0.1", self.port))
        self.tcp.listen()
        self.tcp.settimeout(0.1)
        self.threads = [
            threading.Thread(target=self.udp_loop, daemon=True),
            threading.Thread(target=self.tcp_loop, daemon=True),
        ]

    def start(self):
        for thread in self.threads:
            thread.start()

    def close(self):
        self.stop_event.set()
        for thread in self.threads:
            thread.join(timeout=1)
        self.udp.close()
        self.tcp.close()

    def udp_loop(self):
        while not self.stop_event.is_set():
            try:
                query, peer = self.udp.recvfrom(4096)
            except TimeoutError:
                continue
            self.counts["udp"] += 1
            if self.drop_first:
                self.drop_first -= 1
                continue
            self.udp.sendto(make_answer(query, self.address), peer)

    def tcp_loop(self):
        while not self.stop_event.is_set():
            try:
                conn, _ = self.tcp.accept()
            except TimeoutError:
                continue
            conn.settimeout(1)
            threading.Thread(target=self.tcp_conn, args=(conn,), daemon=True).start()

    def tcp_conn(self, conn):
        with conn:
            while not self.stop_event.is_set():
                try:
                    length = struct.unpack("!H", recv_exact(conn, 2))[0]
                    query = recv_exact(conn, length)
                except (EOFError, OSError, TimeoutError):
                    return
                self.counts["tcp"] += 1
                if self.drop_first:
                    self.drop_first -= 1
                    continue
                answer = make_answer(query, self.address)
                conn.sendall(struct.pack("!H", len(answer)) + answer)


class MockDoT:
    def __init__(self, address):
        self.address = address
        self.port = free_port()
        self.stop_event = threading.Event()
        self.count = 0
        self.tempdir = tempfile.TemporaryDirectory()
        self.key = os.path.join(self.tempdir.name, "key.pem")
        self.cert = os.path.join(self.tempdir.name, "cert.pem")
        subprocess.run([
            "openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
            "-subj", "/CN=localhost", "-days", "1",
            "-addext", "subjectAltName=DNS:localhost",
            "-keyout", self.key, "-out", self.cert,
        ], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(self.cert, self.key)
        raw = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        raw.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        raw.bind(("127.0.0.1", self.port))
        raw.listen()
        raw.settimeout(0.1)
        self.raw = raw
        self.context = context
        self.thread = threading.Thread(target=self.loop, daemon=True)

    def start(self):
        self.thread.start()

    def close(self):
        self.stop_event.set()
        self.thread.join(timeout=1)
        self.raw.close()
        self.tempdir.cleanup()

    def loop(self):
        while not self.stop_event.is_set():
            try:
                conn, _ = self.raw.accept()
            except TimeoutError:
                continue
            try:
                tls = self.context.wrap_socket(conn, server_side=True)
            except ssl.SSLError:
                conn.close()
                continue
            tls.settimeout(1)
            threading.Thread(target=self.conn, args=(tls,), daemon=True).start()

    def conn(self, conn):
        with conn:
            while not self.stop_event.is_set():
                try:
                    length = struct.unpack("!H", recv_exact(conn, 2))[0]
                    query = recv_exact(conn, length)
                except (EOFError, OSError, TimeoutError):
                    return
                self.count += 1
                answer = make_answer(query, self.address)
                conn.sendall(struct.pack("!H", len(answer)) + answer)


class ChinaDNS:
    def __init__(self, binary, *args):
        self.port = free_port()
        command = [
            binary,
            "--bind-addr", "127.0.0.1",
            "--bind-port", str(self.port),
            *args,
        ]
        self.process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        self.wait_ready()

    def wait_ready(self):
        deadline = time.monotonic() + 3
        while time.monotonic() < deadline:
            if self.process.poll() is not None:
                output = self.process.stdout.read()
                raise RuntimeError(f"chinadns-ng exited early:\n{output}")
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.05)
            try:
                sock.connect(("127.0.0.1", self.port))
                sock.close()
                return
            except OSError:
                sock.close()
                time.sleep(0.02)
        raise TimeoutError("chinadns-ng did not start")

    def close(self):
        if self.process.poll() is None:
            self.process.send_signal(signal.SIGTERM)
            try:
                self.process.wait(timeout=2)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait()
        if self.process.returncode != 0:
            output = self.process.stdout.read()
            raise RuntimeError(f"chinadns-ng exited with {self.process.returncode}:\n{output}")

    def query(self, name, qtype=1, tcp=False, ident=0x1234):
        query = make_query(name, qtype, ident)
        if tcp:
            sock = socket.create_connection(("127.0.0.1", self.port), timeout=2)
            with sock:
                sock.sendall(struct.pack("!H", len(query)) + query)
                length = struct.unpack("!H", recv_exact(sock, 2))[0]
                return recv_exact(sock, length)
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(2)
        with sock:
            sock.sendto(query, ("127.0.0.1", self.port))
            return sock.recv(4096)

    def query_many_tcp(self, queries):
        messages = [make_query(name, qtype, ident) for name, qtype, ident in queries]
        sock = socket.create_connection(("127.0.0.1", self.port), timeout=2)
        with sock:
            sock.sendall(b"".join(struct.pack("!H", len(message)) + message for message in messages))
            replies = []
            for _ in messages:
                length = struct.unpack("!H", recv_exact(sock, 2))[0]
                replies.append(recv_exact(sock, length))
            return replies

    def query_tcp_half_close(self, name, qtype=1, ident=0x1234):
        query = make_query(name, qtype, ident)
        sock = socket.create_connection(("127.0.0.1", self.port), timeout=2)
        with sock:
            sock.sendall(struct.pack("!H", len(query)) + query)
            sock.shutdown(socket.SHUT_WR)
            length = struct.unpack("!H", recv_exact(sock, 2))[0]
            return recv_exact(sock, length)

    def invalid_query(self, tcp=False):
        query = struct.pack("!HHHHHH", 0x7788, 0x0100, 1, 0, 0, 0)
        if tcp:
            sock = socket.create_connection(("127.0.0.1", self.port), timeout=2)
            with sock:
                sock.sendall(struct.pack("!H", len(query)) + query)
                length = struct.unpack("!H", recv_exact(sock, 2))[0]
                return recv_exact(sock, length)
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(2)
        with sock:
            sock.sendto(query, ("127.0.0.1", self.port))
            return sock.recv(4096)


def answer_ip(message):
    end = question_end(message)
    _, rtype, _, _, size = struct.unpack_from("!HHHIH", message, end)
    data = message[end + 12:end + 12 + size]
    return str(ipaddress.ip_address(data)), rtype


def assert_nodata(message):
    flags = struct.unpack_from("!H", message, 2)[0]
    answers = struct.unpack_from("!H", message, 6)[0]
    assert flags & 0x8000
    assert flags & 0x000F == 0
    assert answers == 0


def check_local(binary):
    server = ChinaDNS(binary, "--default-tag", "chn", "--dns-rr-ip", "test.local=192.0.2.1,2001:db8::1")
    try:
        assert answer_ip(server.query("test.local"))[0] == "192.0.2.1"
        assert answer_ip(server.query("test.local", qtype=28))[0] == "2001:db8::1"
        assert answer_ip(server.query("test.local", tcp=True))[0] == "192.0.2.1"
        assert answer_ip(server.query("test.local", qtype=28, tcp=True))[0] == "2001:db8::1"
        replies = server.query_many_tcp([
            ("test.local", 1, 1),
            ("test.local", 28, 2),
        ])
        assert [answer_ip(reply)[0] for reply in replies] == ["192.0.2.1", "2001:db8::1"]
        assert answer_ip(server.query_tcp_half_close("test.local"))[0] == "192.0.2.1"
        for reply in (server.invalid_query(), server.invalid_query(tcp=True)):
            assert len(reply) == 12
            assert struct.unpack_from("!H", reply)[0] == 0x7788
            assert struct.unpack_from("!H", reply, 2)[0] & 0x8000
    finally:
        server.close()


def check_raw_upstream(binary):
    mock = MockDNS("203.0.113.7")
    mock.start()
    server = ChinaDNS(binary, "--default-tag", "chn", "--china-dns", f"127.0.0.1#{mock.port}?count=0?life=0")
    try:
        assert answer_ip(server.query("raw.example"))[0] == "203.0.113.7"
        assert answer_ip(server.query("raw.example", tcp=True))[0] == "203.0.113.7"
        replies = server.query_many_tcp([
            ("raw-one.example", 1, 1),
            ("raw-two.example", 1, 2),
        ])
        assert all(answer_ip(reply)[0] == "203.0.113.7" for reply in replies)
        assert mock.counts == {"udp": 1, "tcp": 3}, mock.counts
    finally:
        server.close()
        mock.close()


def check_explicit_protocols(binary):
    tcp_mock = MockDNS("198.51.100.9")
    tcp_mock.start()
    tcp_server = ChinaDNS(binary, "--default-tag", "chn", "--china-dns", f"tcp://127.0.0.1#{tcp_mock.port}?count=0?life=0")
    try:
        assert answer_ip(tcp_server.query("tcp.example"))[0] == "198.51.100.9"
        assert tcp_mock.counts == {"udp": 0, "tcp": 1}, tcp_mock.counts
    finally:
        tcp_server.close()
        tcp_mock.close()

    udp_mock = MockDNS("198.51.100.10")
    udp_mock.start()
    udp_server = ChinaDNS(binary, "--default-tag", "chn", "--china-dns", f"udp://127.0.0.1#{udp_mock.port}?count=0?life=0")
    try:
        assert answer_ip(udp_server.query("udp.example", tcp=True))[0] == "198.51.100.10"
        assert udp_mock.counts == {"udp": 1, "tcp": 0}, udp_mock.counts
    finally:
        udp_server.close()
        udp_mock.close()


def check_cache(binary):
    mock = MockDNS("192.0.2.55")
    mock.start()
    server = ChinaDNS(binary, "--default-tag", "chn", "--china-dns", f"udp://127.0.0.1#{mock.port}?count=0?life=0", "--cache", "8")
    try:
        assert answer_ip(server.query("cache.example", ident=1))[0] == "192.0.2.55"
        assert answer_ip(server.query("cache.example", ident=2))[0] == "192.0.2.55"
        assert mock.counts["udp"] == 1, mock.counts
    finally:
        server.close()
        mock.close()


def check_config_and_groups(binary):
    with tempfile.TemporaryDirectory() as directory:
        config = os.path.join(directory, "chinadns.conf")
        with open(config, "w", encoding="utf-8") as file:
            file.write("default-tag chn\n")
            file.write("dns-rr-ip config.local=192.0.2.88\n")
        server = ChinaDNS(binary, "--config", config)
        try:
            assert answer_ip(server.query("config.local"))[0] == "192.0.2.88"
        finally:
            server.close()

        server = ChinaDNS(
            binary,
            "--group", "null",
            "--default-tag", "null",
            "--dns-rr-ip", "allowed.local=192.0.2.90",
        )
        try:
            assert answer_ip(server.query("allowed.local"))[0] == "192.0.2.90"
            assert_nodata(server.query("blocked.example"))
        finally:
            server.close()

        blocked = os.path.join(directory, "blocked.txt")
        with open(blocked, "w", encoding="utf-8") as file:
            file.write("blocked.example\n")
        server = ChinaDNS(
            binary,
            "--default-tag", "chn",
            "--group", "null",
            "--group-dnl", blocked,
        )
        try:
            assert_nodata(server.query("blocked.example"))
        finally:
            server.close()

        domains = os.path.join(directory, "group.txt")
        with open(domains, "w", encoding="utf-8") as file:
            file.write("group.example\n")
        mock = MockDNS("192.0.2.89")
        mock.start()
        server = ChinaDNS(
            binary,
            "--default-tag", "chn",
            "--group", "custom",
            "--group-dnl", domains,
            "--group-upstream", f"udp://127.0.0.1#{mock.port}?count=0?life=0",
        )
        try:
            assert answer_ip(server.query("group.example"))[0] == "192.0.2.89"
            assert mock.counts["udp"] == 1, mock.counts
        finally:
            server.close()
            mock.close()

        server = ChinaDNS(
            binary,
            "--default-tag", "chn",
            "--dns-rr-ip", "filtered.local=2001:db8::9",
            "--no-ipv6", "tag:chn",
        )
        try:
            reply = server.query("filtered.local", qtype=28)
            assert struct.unpack_from("!H", reply, 6)[0] == 0
        finally:
            server.close()


def check_rotation_and_timeout(binary):
    rotating = MockDNS("192.0.2.66")
    rotating.start()
    server = ChinaDNS(
        binary,
        "--default-tag", "chn",
        "--china-dns", f"tcp://127.0.0.1#{rotating.port}?count=1?life=0",
    )
    try:
        for ident in range(1, 21):
            assert answer_ip(server.query("rotate.example", ident=ident))[0] == "192.0.2.66"
        assert rotating.counts["tcp"] == 20, rotating.counts
    finally:
        server.close()
        rotating.close()

    delayed = MockDNS("192.0.2.67", drop_first=1)
    delayed.start()
    server = ChinaDNS(
        binary,
        "--default-tag", "chn", "--timeout-sec", "1",
        "--china-dns", f"tcp://127.0.0.1#{delayed.port}?count=0?life=0",
    )
    try:
        try:
            server.query("timeout.example", ident=1)
            raise AssertionError("the intentionally dropped query unexpectedly received a reply")
        except TimeoutError:
            pass
        assert answer_ip(server.query("timeout.example", ident=2))[0] == "192.0.2.67"
    finally:
        server.close()
        delayed.close()


def check_verdict(binary):
    suffix = str(os.getpid())
    route4 = f"cdns_r4_{suffix}"
    route6 = f"cdns_r6_{suffix}"
    add4 = f"cdns_a4_{suffix}"
    add6 = f"cdns_a6_{suffix}"
    subprocess.run(["ipset", "create", route4, "hash:net", "family", "inet"], check=True)
    subprocess.run(["ipset", "create", route6, "hash:net", "family", "inet6"], check=True)
    subprocess.run(["ipset", "create", add4, "hash:ip", "family", "inet"], check=True)
    subprocess.run(["ipset", "create", add6, "hash:ip", "family", "inet6"], check=True)
    try:
        subprocess.run(["ipset", "add", route4, "10.0.0.0/8"], check=True)

        china = MockDNS("10.1.2.3")
        trust = MockDNS("203.0.113.99")
        china.start()
        trust.start()
        server = ChinaDNS(
            binary,
            "--ipset-name4", route4, "--ipset-name6", route6,
            "--china-dns", f"udp://127.0.0.1#{china.port}?count=0?life=0",
            "--trust-dns", f"udp://127.0.0.1#{trust.port}?count=0?life=0",
        )
        try:
            assert answer_ip(server.query("china.example"))[0] == "10.1.2.3"
        finally:
            server.close()
            china.close()
            trust.close()

        china = MockDNS("198.51.100.8")
        trust = MockDNS("203.0.113.99")
        china.start()
        trust.start()
        server = ChinaDNS(
            binary,
            "--ipset-name4", route4, "--ipset-name6", route6,
            "--china-dns", f"udp://127.0.0.1#{china.port}?count=0?life=0",
            "--trust-dns", f"udp://127.0.0.1#{trust.port}?count=0?life=0",
        )
        try:
            assert answer_ip(server.query("trust.example"))[0] == "203.0.113.99"
        finally:
            server.close()
            china.close()
            trust.close()

        china = MockDNS("10.9.8.7")
        china.start()
        server = ChinaDNS(
            binary,
            "--default-tag", "chn",
            "--china-dns", f"udp://127.0.0.1#{china.port}?count=0?life=0",
            "--add-tagchn-ip", f"{add4},{add6}",
        )
        try:
            assert answer_ip(server.query("add.example"))[0] == "10.9.8.7"
            subprocess.run(["ipset", "test", add4, "10.9.8.7"], check=True,
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        finally:
            server.close()
            china.close()
    finally:
        for name in (route4, route6, add4, add6):
            subprocess.run(["ipset", "destroy", name], check=False,
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def check_dot(binary):
    dot = MockDoT("192.0.2.77")
    dot.start()
    server = ChinaDNS(
        binary,
        "--default-tag", "chn",
        "--china-dns", f"tls://localhost@127.0.0.1#{dot.port}?count=1?life=0",
        "--cert-verify", "--ca-certs", dot.cert,
    )
    try:
        for ident in range(1, 11):
            assert answer_ip(server.query("dot.example", ident=ident))[0] == "192.0.2.77"
        assert dot.count == 10, dot.count
    finally:
        server.close()
        dot.close()


def main():
    binary = os.path.abspath(sys.argv[1] if len(sys.argv) > 1 else "build/chinadns-ng")
    check_local(binary)
    check_raw_upstream(binary)
    check_explicit_protocols(binary)
    check_cache(binary)
    check_config_and_groups(binary)
    check_rotation_and_timeout(binary)
    if os.environ.get("CHINADNS_TEST_VERDICT") == "1":
        check_verdict(binary)
    if os.environ.get("CHINADNS_TEST_DOT") == "1":
        check_dot(binary)
    print("e2e: local records, UDP/TCP, raw routing, cache, rotation, timeout: PASS")


if __name__ == "__main__":
    main()
