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
    if name == ".":
        return b"\0"
    return b"".join(bytes([len(label)]) + label.encode() for label in name.split(".")) + b"\0"


def make_query(name, qtype, ident):
    return struct.pack("!HHHHHH", ident, 0x0100, 1, 0, 0, 0) + encode_name(name) + struct.pack("!HH", qtype, 1)


def question_end(message):
    pos = 12
    while message[pos]:
        pos += 1 + message[pos]
    return pos + 5


def make_answer(query, address, ttl=60):
    end = question_end(query)
    ip = ipaddress.ip_address(address)
    qtype = 1 if ip.version == 4 else 28
    header = struct.pack("!HHHHHH", struct.unpack_from("!H", query)[0], 0x8180, 1, 1, 0, 0)
    answer = struct.pack("!HHHIH", 0xC00C, qtype, 1, ttl, len(ip.packed)) + ip.packed
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
    def __init__(self, address, drop_first=0, close_after_reply=False, ttl=60, drop=False, mangle=False):
        self.address = address
        self.drop_first = drop_first
        self.drop = drop  # runtime toggle: silently discard every query
        self.mangle = mangle  # runtime toggle: reply with a malformed message
        self.close_after_reply = close_after_reply
        self.ttl = ttl
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

    def mangled_reply(self, query, sock, peer=None):
        # a reply with the query's qid but a corrupted question section
        mangled = struct.pack("!HH", struct.unpack_from("!H", query)[0], 0x8180) + b"\xff" * 16
        if peer is None:
            sock.sendall(struct.pack("!H", len(mangled)) + mangled)
        else:
            sock.sendto(mangled, peer)

    def udp_loop(self):
        while not self.stop_event.is_set():
            try:
                query, peer = self.udp.recvfrom(4096)
            except TimeoutError:
                continue
            self.counts["udp"] += 1
            if self.drop:
                continue
            if self.drop_first:
                self.drop_first -= 1
                continue
            if self.mangle:
                self.mangled_reply(query, self.udp, peer)
                continue
            self.udp.sendto(make_answer(query, self.address, self.ttl), peer)

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
                if self.drop:
                    continue
                if self.drop_first:
                    self.drop_first -= 1
                    continue
                if self.mangle:
                    self.mangled_reply(query, conn)
                    continue
                answer = make_answer(query, self.address, self.ttl)
                conn.sendall(struct.pack("!H", len(answer)) + answer)
                if self.close_after_reply:
                    conn.shutdown(socket.SHUT_WR)
                    return


class FlappingTCP:
    """accepts a connection, reads whatever arrives, closes it immediately"""
    def __init__(self):
        self.port = free_port()
        self.stop_event = threading.Event()
        self.connections = 0
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(("127.0.0.1", self.port))
        self.sock.listen()
        self.sock.settimeout(0.1)

    def start(self):
        threading.Thread(target=self.loop, daemon=True).start()

    def close(self):
        self.stop_event.set()
        self.sock.close()

    def loop(self):
        while not self.stop_event.is_set():
            try:
                conn, _ = self.sock.accept()
            except TimeoutError:
                continue
            except OSError:
                return
            self.connections += 1
            conn.close()


class MismatchedDNS(MockDNS):
    def __init__(self):
        super().__init__("192.0.2.77", mangle=True)

    def mangled_reply(self, query, sock, peer=None):
        ident = struct.unpack_from("!H", query)[0]
        wrong_name = make_query("wrong.example", 1, ident)
        wrong_type = bytearray(query)
        struct.pack_into("!H", wrong_type, question_end(query) - 4, 28)
        wrong_class = bytearray(query)
        struct.pack_into("!H", wrong_class, question_end(query) - 2, 3)
        valid = bytearray(query)
        valid[12:question_end(query) - 4] = valid[12:question_end(query) - 4].upper()
        for question in (wrong_name, wrong_type, wrong_class, valid):
            reply = make_answer(question, self.address if question is valid else "192.0.2.66")
            if peer is None:
                sock.sendall(struct.pack("!H", len(reply)) + reply)
            else:
                sock.sendto(reply, peer)


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
    def __init__(self, binary, *args, bind_protocol=None, nofile_limit=None):
        self.port = free_port()
        bind_port = str(self.port)
        if bind_protocol:
            bind_port += f"@{bind_protocol}"
        command = [
            binary,
            "--bind-addr", "127.0.0.1",
            "--bind-port", bind_port,
            *args,
        ]
        if nofile_limit is not None:
            command = [
                "sh", "-c", 'ulimit -n "$1"; shift; exec "$@"',
                "sh", str(nofile_limit), *command,
            ]
        self.process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        self.wait_ready(bind_protocol)

    def wait_ready(self, bind_protocol):
        deadline = time.monotonic() + 3
        while time.monotonic() < deadline:
            if self.process.poll() is not None:
                output = self.process.stdout.read()
                raise RuntimeError(f"chinadns-ng exited early:\n{output}")
            sock_type = socket.SOCK_DGRAM if bind_protocol == "udp" else socket.SOCK_STREAM
            sock = socket.socket(socket.AF_INET, sock_type)
            sock.settimeout(0.05)
            try:
                if bind_protocol == "udp":
                    sock.bind(("127.0.0.1", self.port))
                    sock.close()
                    time.sleep(0.02)
                    continue
                sock.connect(("127.0.0.1", self.port))
                sock.close()
                return
            except OSError:
                sock.close()
                if bind_protocol == "udp":
                    return
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
        output = self.process.stdout.read()
        if self.process.returncode != 0:
            raise RuntimeError(f"chinadns-ng exited with {self.process.returncode}:\n{output}")
        return output

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

    def query_after_pending_udp(self, count, final_name):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(2)
        with sock:
            for ident in range(count):
                query = make_query(f"pending-{ident}.example", 1, ident & 0xFFFF)
                sock.sendto(query, ("127.0.0.1", self.port))
                if (ident + 1) % 128 == 0:
                    time.sleep(0.002)
            time.sleep(0.02)
            query = make_query(final_name, 1, 0x7777)
            sock.sendto(query, ("127.0.0.1", self.port))
            return sock.recv(4096)

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

    with tempfile.TemporaryDirectory() as directory:
        hosts = os.path.join(directory, "large-hosts")
        with open(hosts, "w", encoding="utf-8") as file:
            for value in range(4096):
                address = f"10.0.{value >> 8}.{value & 0xFF}"
                file.write(f"{address} huge.local\n")
        try:
            ChinaDNS(binary, "--hosts", hosts, "--default-tag", "chn")
            raise AssertionError("oversized local RR set unexpectedly started")
        except RuntimeError as error:
            assert "too many local A records for huge.local" in str(error), error


def check_root_query(binary):
    mock = MockDNS("192.0.2.2")
    mock.start()
    try:
        with tempfile.TemporaryDirectory() as directory:
            domains = os.path.join(directory, "domains")
            with open(domains, "w", encoding="utf-8") as file:
                file.write("blocked.example\n")
            server = ChinaDNS(
                binary, "--default-tag", "chn",
                "--china-dns", f"127.0.0.1#{mock.port}",
                "--group", "null", "--group-dnl", domains,
            )
            try:
                for tcp in (False, True):
                    reply = server.query(".", tcp=tcp, ident=0x5678)
                    assert answer_ip(reply)[0] == "192.0.2.2"
                    assert struct.unpack_from("!H", reply)[0] == 0x5678
                    assert_nodata(server.query("blocked.example", tcp=tcp))
                assert mock.counts == {"udp": 1, "tcp": 1}, mock.counts
            finally:
                server.close()
    finally:
        mock.close()


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

    closing_tcp_mock = MockDNS("198.51.100.11", close_after_reply=True)
    closing_tcp_mock.start()
    closing_tcp_server = ChinaDNS(
        binary,
        "--default-tag", "chn",
        "--china-dns", f"tcp://127.0.0.1#{closing_tcp_mock.port}?count=0?life=0",
    )
    try:
        assert answer_ip(closing_tcp_server.query("tcp-close.example"))[0] == "198.51.100.11"
        assert closing_tcp_mock.counts == {"udp": 0, "tcp": 1}, closing_tcp_mock.counts
    finally:
        closing_tcp_server.close()
        closing_tcp_mock.close()

    udp_mock = MockDNS("198.51.100.10")
    udp_mock.start()
    udp_server = ChinaDNS(binary, "--default-tag", "chn", "--china-dns", f"udp://127.0.0.1#{udp_mock.port}?count=0?life=0")
    try:
        assert answer_ip(udp_server.query("udp.example", tcp=True))[0] == "198.51.100.10"
        assert udp_mock.counts == {"udp": 1, "tcp": 0}, udp_mock.counts
    finally:
        udp_server.close()
        udp_mock.close()


def check_reply_matching(binary):
    mock = MismatchedDNS()
    mock.start()
    try:
        for protocol in ("udp", "tcp"):
            server = ChinaDNS(
                binary, "--default-tag", "chn", "--cache", "8",
                "--china-dns", f"{protocol}://127.0.0.1#{mock.port}?count=0?life=0",
            )
            try:
                reply = server.query("right.example")
                assert answer_ip(reply)[0] == "192.0.2.77"
                assert reply[12:question_end(reply) - 4] == encode_name("RIGHT.EXAMPLE")
                assert struct.unpack_from("!HH", reply, question_end(reply) - 4) == (1, 1)
            finally:
                server.close()
    finally:
        mock.close()

    # A valid response from a configured but unrelated session must not
    # consume the query owned by the other group.
    with tempfile.TemporaryDirectory() as directory, \
            socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as first, \
            socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as second, \
            socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
        for sock in (first, second, client):
            sock.bind(("127.0.0.1", 0))
            sock.settimeout(2)
        domains = os.path.join(directory, "domains")
        with open(domains, "w", encoding="utf-8") as file:
            file.write("pending.example\n")
        server = ChinaDNS(
            binary, "--default-tag", "chn", "--gfwlist-file", domains,
            "--china-dns", f"udp://127.0.0.1#{first.getsockname()[1]}?count=0?life=0",
            "--trust-dns", f"udp://127.0.0.1#{second.getsockname()[1]}?count=0?life=0",
        )
        try:
            target = ("127.0.0.1", server.port)
            client.sendto(make_query("warm.example", 1, 1), target)
            query, first_peer = first.recvfrom(4096)
            first.sendto(make_answer(query, "192.0.2.1"), first_peer)
            client.recv(4096)
            client.sendto(make_query("pending.example", 1, 2), target)
            query, second_peer = second.recvfrom(4096)
            first.sendto(make_answer(query, "192.0.2.66"), first_peer)
            client.settimeout(0.1)
            try:
                client.recv(4096)
                raise AssertionError("accepted response from an unrelated session")
            except TimeoutError:
                pass
            second.sendto(make_answer(query, "192.0.2.77"), second_peer)
            client.settimeout(2)
            assert answer_ip(client.recv(4096))[0] == "192.0.2.77"
        finally:
            server.close()


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

    with tempfile.TemporaryDirectory() as directory:
        cache_db = os.path.join(directory, "invalid-cache.db")
        header = struct.pack(
            "=qIiiHBx",
            int(time.time()), 0, 60, 12, 17, 200,
        )
        with open(cache_db, "wb") as file:
            file.write(header)
            file.write(bytes(17))
        server = ChinaDNS(
            binary,
            "--default-tag", "chn",
            "--cache", "8",
            "--cache-db", cache_db,
        )
        output = server.close()
        assert f"0 entries from {cache_db}" in output, output

    with tempfile.TemporaryDirectory() as directory:
        cache_db = os.path.join(directory, "large-ttl-cache.db")
        mock = MockDNS("192.0.2.56", ttl=0x7FFFFFFF)
        mock.start()
        server = ChinaDNS(
            binary,
            "--default-tag", "chn",
            "--china-dns", f"udp://127.0.0.1#{mock.port}?count=0?life=0",
            "--cache", "8",
            "--cache-refresh", "20",
            "--cache-db", cache_db,
        )
        try:
            assert answer_ip(server.query("large-ttl.example"))[0] == "192.0.2.56"
        finally:
            server.close()
            mock.close()
        with open(cache_db, "rb") as file:
            header = file.read(struct.calcsize("=qIiiHBx"))
        _, _, ttl, refresh_ttl, _, _ = struct.unpack("=qIiiHBx", header)
        assert ttl == 0x7FFFFFFF
        assert refresh_ttl == 0x7FFFFFFF * 20 // 100


def check_case_insensitive(binary):
    mock = MockDNS("192.0.2.40")
    mock.start()
    try:
        with tempfile.TemporaryDirectory() as directory:
            domains = os.path.join(directory, "domains")
            hosts = os.path.join(directory, "hosts")
            cache_db = os.path.join(directory, "cache.db")
            with open(domains, "w", encoding="utf-8") as file:
                file.write("Blocked.Example\n")
            with open(hosts, "w", encoding="utf-8") as file:
                file.write("192.0.2.42 Mixed.Host\n")
            args = (
                "--default-tag", "chn", "--china-dns", f"udp://127.0.0.1#{mock.port}",
                "--group", "null", "--group-dnl", domains,
                "--dns-rr-ip", "Test.Local=192.0.2.41", "--hosts", hosts,
                "--cache", "8", "--cache-db", cache_db, "--cache-ignore", "Ignore.Example",
            )
            server = ChinaDNS(binary, *args)
            try:
                for tcp in (False, True):
                    for name in ("blocked.example", "SUB.BLOCKED.EXAMPLE"):
                        assert_nodata(server.query(name, tcp=tcp))
                    assert answer_ip(server.query("TEST.LOCAL", tcp=tcp))[0] == "192.0.2.41"
                    assert answer_ip(server.query("mixed.host", tcp=tcp))[0] == "192.0.2.42"
                assert mock.counts["udp"] == 0
                for name in ("Mixed.Cache.Example", "mixed.cache.example", "MIXED.CACHE.EXAMPLE"):
                    reply = server.query(name)
                    assert answer_ip(reply)[0] == "192.0.2.40"
                    assert reply[12:question_end(reply) - 4] == encode_name(name)
                assert mock.counts["udp"] == 1
                for name in ("skip.ignore.example", "SKIP.IGNORE.EXAMPLE"):
                    server.query(name)
                assert mock.counts["udp"] == 3
                # Type codes 65 and 97 must not be case-folded with the name.
                for qtype in (65, 97):
                    server.query("types.example", qtype=qtype)
                assert mock.counts["udp"] == 5
            finally:
                server.close()

            # Stored hashes from older versions must not prevent a match.
            with open(cache_db, "r+b") as file:
                offset = 0
                while header := file.read(24):
                    msg_len = struct.unpack_from("=H", header, 20)[0]
                    file.seek(offset + 8)
                    file.write(struct.pack("=I", 0))
                    offset += 24 + msg_len
                    file.seek(offset)
            mock.drop = True
            server = ChinaDNS(binary, *args)
            try:
                reply = server.query("mIxEd.cAcHe.eXaMpLe")
                assert answer_ip(reply)[0] == "192.0.2.40"
                assert reply[12:question_end(reply) - 4] == encode_name("mIxEd.cAcHe.eXaMpLe")
                assert mock.counts["udp"] == 5
            finally:
                server.close()
    finally:
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
            file.write(" \t\n")
            file.write("#" + "x" * 4096 + " full-comment.example\n")
            file.write(" \tgroup.example \t# " + "x" * 4096 + " inline-comment.example\n")
            file.write("first.example second.example\n")
        default = MockDNS("192.0.2.87")
        mock = MockDNS("192.0.2.89")
        default.start()
        mock.start()
        server = ChinaDNS(
            binary,
            "--default-tag", "chn",
            "--china-dns", f"udp://127.0.0.1#{default.port}?count=0?life=0",
            "--group", "custom",
            "--group-dnl", domains,
            "--group-upstream", f"udp://127.0.0.1#{mock.port}?count=0?life=0",
        )
        try:
            assert answer_ip(server.query("group.example"))[0] == "192.0.2.89"
            assert mock.counts["udp"] == 1, mock.counts
            for name in ("full-comment.example", "inline-comment.example",
                         "first.example", "second.example"):
                assert answer_ip(server.query(name))[0] == "192.0.2.87"
            assert default.counts["udp"] == 4, default.counts
            assert mock.counts["udp"] == 1, mock.counts
        finally:
            server.close()
            default.close()
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

        mock = MockDNS("192.0.2.91")
        mock.start()
        server = ChinaDNS(
            binary,
            "--default-tag", "chn",
            "--china-dns", f"udp://127.0.0.1#{mock.port}?count=0?life=0",
            "--filter-qtype", "1,1,65535",
        )
        try:
            assert_nodata(server.query("filtered-a.example"))
            assert_nodata(server.query("filtered-max.example", qtype=65535))
            assert mock.counts == {"udp": 0, "tcp": 0}, mock.counts
        finally:
            server.close()
            mock.close()


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


def check_fallback(binary):
    # a group with ?fallback upstream(s) must also have a primary upstream
    mock = MockDNS("192.0.2.1")
    mock.start()
    try:
        ChinaDNS(binary, "--default-tag", "chn",
                 "--china-dns", f"udp://127.0.0.1#{mock.port}?fallback")
        raise AssertionError("group without a primary upstream unexpectedly started")
    except RuntimeError as error:
        assert "fallback upstream without primary upstream" in str(error), error
    finally:
        mock.close()

    primary = MockDNS("203.0.113.1")
    backup = MockDNS("198.51.100.1")
    primary.start()
    backup.start()
    server = ChinaDNS(
        binary,
        "--default-tag", "chn",
        "--timeout-sec", "1",
        "--verbose",
        "--china-dns",
        f"udp://127.0.0.1#{primary.port}?count=0?life=0,"
        f"udp://127.0.0.1#{backup.port}?count=0?life=0?fallback",
    )
    try:
        # steady state: only the primary upstream is queried
        assert answer_ip(server.query("fallback-healthy.example"))[0] == "203.0.113.1"
        assert backup.counts["udp"] == 0, backup.counts

        # primary goes silent: the pending query times out, then the group also
        # queries the ?fallback upstream, which answers
        primary.drop = True
        try:
            server.query("fallback-down.example")
            raise AssertionError("query to the dead primary unexpectedly received a reply")
        except TimeoutError:
            pass
        assert answer_ip(server.query("fallback-takeover.example"))[0] == "198.51.100.1"
        assert backup.counts["udp"] >= 1, backup.counts

        # primary recovers: a primary reply marks the group healthy again, so the
        # next query goes to the primary only and the fallback is left alone
        primary.drop = False
        assert answer_ip(server.query("fallback-recover.example"))[0] in ("203.0.113.1", "198.51.100.1")
        time.sleep(0.3)
        received = backup.counts["udp"]
        assert answer_ip(server.query("fallback-back.example"))[0] == "203.0.113.1"
        assert backup.counts["udp"] == received, backup.counts

        # malformed primary replies must not count as a recovery signal, nor
        # block a later good reply from recovering the group
        primary.mangle = True
        try:
            server.query("fallback-mangle.example")
            raise AssertionError("query answered by a mangled reply")
        except TimeoutError:
            pass
        assert answer_ip(server.query("fallback-mangle-fb.example"))[0] == "198.51.100.1"
        primary.mangle = False
        assert answer_ip(server.query("fallback-unmangle.example"))[0] in ("203.0.113.1", "198.51.100.1")
        time.sleep(0.3)
        received = backup.counts["udp"]
        assert answer_ip(server.query("fallback-unmangle-back.example"))[0] == "203.0.113.1"
        assert backup.counts["udp"] == received, backup.counts
    finally:
        output = server.close()
        primary.close()
        backup.close()
        assert "passive health-check enabled" in output, output
        assert "unresponsive, also querying ?fallback" in output, output
        assert "recovered, stop querying ?fallback" in output, output


def check_fallback_tcp_primary(binary):
    primary = MockDNS("203.0.113.3")
    backup = MockDNS("198.51.100.3")
    primary.start()
    backup.start()
    server = ChinaDNS(
        binary,
        "--default-tag", "chn",
        "--timeout-sec", "1",
        "--china-dns",
        f"tcp://127.0.0.1#{primary.port}?count=0?life=0,"
        f"udp://127.0.0.1#{backup.port}?count=0?life=0?fallback",
    )
    try:
        assert answer_ip(server.query("fb-tcp.example"))[0] == "203.0.113.3"
        assert backup.counts == {"udp": 0, "tcp": 0}, backup.counts
        primary.drop = True
        try:
            server.query("fb-tcp-down.example")
            raise AssertionError("query to the dead primary unexpectedly received a reply")
        except TimeoutError:
            pass
        assert answer_ip(server.query("fb-tcp-over.example"))[0] == "198.51.100.3"
        assert backup.counts["udp"] >= 1, backup.counts
        primary.drop = False
        assert answer_ip(server.query("fb-tcp-recover.example"))[0] in ("203.0.113.3", "198.51.100.3")
        time.sleep(0.3)
        received = backup.counts["udp"]
        assert answer_ip(server.query("fb-tcp-back.example"))[0] == "203.0.113.3"
        assert backup.counts["udp"] == received, backup.counts
    finally:
        server.close()
        primary.close()
        backup.close()


def check_fallback_groups(binary):
    # trust-dns group
    primary = MockDNS("203.0.113.4")
    backup = MockDNS("198.51.100.4")
    primary.start()
    backup.start()
    server = ChinaDNS(
        binary,
        "--default-tag", "gfw",
        "--timeout-sec", "1",
        "--trust-dns",
        f"udp://127.0.0.1#{primary.port}?count=0?life=0,"
        f"udp://127.0.0.1#{backup.port}?count=0?life=0?fallback",
    )
    try:
        assert answer_ip(server.query("fb-trust.example"))[0] == "203.0.113.4"
        assert backup.counts["udp"] == 0, backup.counts
        primary.drop = True
        try:
            server.query("fb-trust-down.example")
            raise AssertionError("query to the dead primary unexpectedly received a reply")
        except TimeoutError:
            pass
        assert answer_ip(server.query("fb-trust-over.example"))[0] == "198.51.100.4"
    finally:
        server.close()
        primary.close()
        backup.close()

    # user-defined group via --group-upstream
    primary = MockDNS("203.0.113.5")
    backup = MockDNS("198.51.100.5")
    primary.start()
    backup.start()
    with tempfile.TemporaryDirectory() as directory:
        domains = os.path.join(directory, "group.txt")
        with open(domains, "w", encoding="utf-8") as file:
            file.write("fb-grp.example\nfb-grp-down.example\nfb-grp-over.example\n")
        server = ChinaDNS(
            binary,
            "--default-tag", "chn",
            "--timeout-sec", "1",
            "--group", "custom",
            "--group-dnl", domains,
            "--group-upstream",
            f"udp://127.0.0.1#{primary.port}?count=0?life=0,"
            f"udp://127.0.0.1#{backup.port}?count=0?life=0?fallback",
        )
        try:
            assert answer_ip(server.query("fb-grp.example"))[0] == "203.0.113.5"
            assert backup.counts["udp"] == 0, backup.counts
            primary.drop = True
            try:
                server.query("fb-grp-down.example")
                raise AssertionError("query to the dead primary unexpectedly received a reply")
            except TimeoutError:
                pass
            assert answer_ip(server.query("fb-grp-over.example"))[0] == "198.51.100.5"
        finally:
            server.close()
            primary.close()
            backup.close()


def check_no_fallback_log_noise(binary):
    # a plain group without any ?fallback upstream must never report fallback
    # health transitions (regression: spurious "recovered" log)
    mock = MockDNS("203.0.113.6")
    mock.start()
    server = ChinaDNS(
        binary,
        "--default-tag", "chn",
        "--verbose",
        "--china-dns", f"udp://127.0.0.1#{mock.port}?count=0?life=0",
    )
    try:
        assert answer_ip(server.query("plain.example"))[0] == "203.0.113.6"
    finally:
        output = server.close()
        mock.close()
    assert "?fallback" not in output, output


def check_fallback_no_amplification(binary):
    # regression: a TCP upstream must not re-send a request whose query already
    # completed elsewhere (another upstream won the race). without ?fallback the
    # request is released with the query; inside a ?fallback group it lingers as
    # an orphan for late-reply matching, but a reconnect drops it rather than
    # retransmitting it -- a reply can only arrive on the connection it was sent
    # on, and while a group is unhealthy fresh queries already probe the primary
    for extra in ([], ["udp://127.0.0.1#1?fallback"]):
        fast = MockDNS("198.51.100.7")
        flap = FlappingTCP()
        fast.start()
        flap.start()
        upstreams = [
            f"udp://127.0.0.1#{fast.port}?count=0?life=0",
            f"tcp://127.0.0.1#{flap.port}?count=0?life=0",
        ] + extra
        server = ChinaDNS(
            binary,
            "--default-tag", "chn",
            "--china-dns", ",".join(upstreams),
        )
        try:
            assert answer_ip(server.query("no-amplify.example"))[0] == "198.51.100.7"
            # the flapping upstream sees the initial connection only; every retry
            # attempt within the timeout window would be another accept
            time.sleep(1.5)
            assert flap.connections <= 2, (extra, flap.connections)
        finally:
            server.close()
            fast.close()
            flap.close()


def check_resource_exhaustion(binary):
    server = ChinaDNS(
        binary,
        "--default-tag", "chn",
        "--china-dns", f"udp://127.0.0.1#{free_port()}?count=0?life=0",
        bind_protocol="udp",
        nofile_limit=6,
    )
    try:
        try:
            server.query("no-fd.example")
            raise AssertionError("resource-exhausted query unexpectedly received a reply")
        except TimeoutError:
            pass
        assert server.process.poll() is None
    finally:
        server.close()


def check_hash_growth(binary):
    with tempfile.TemporaryDirectory() as directory:
        hosts = os.path.join(directory, "many-hosts")
        with open(hosts, "w", encoding="utf-8") as file:
            for value in range(600):
                file.write(f"192.0.2.{value % 250 + 1} host-{value}.local\n")
        server = ChinaDNS(binary, "--hosts", hosts, "--default-tag", "chn")
        try:
            assert answer_ip(server.query("host-599.local"))[0] == "192.0.2.100"
        finally:
            server.close()

    server = ChinaDNS(
        binary,
        "--default-tag", "chn",
        "--china-dns", f"udp://127.0.0.1#{free_port()}?count=0?life=0",
        "--dns-rr-ip", "ready.local=192.0.2.101",
    )
    try:
        reply = server.query_after_pending_udp(2500, "ready.local")
        assert answer_ip(reply)[0] == "192.0.2.101"
    finally:
        server.close()


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
    check_root_query(binary)
    check_raw_upstream(binary)
    check_explicit_protocols(binary)
    check_reply_matching(binary)
    check_cache(binary)
    check_case_insensitive(binary)
    check_config_and_groups(binary)
    check_rotation_and_timeout(binary)
    check_fallback(binary)
    check_fallback_tcp_primary(binary)
    check_fallback_groups(binary)
    check_no_fallback_log_noise(binary)
    check_fallback_no_amplification(binary)
    if os.environ.get("CHINADNS_TEST_SKIP_RESOURCE") != "1":
        check_resource_exhaustion(binary)
    check_hash_growth(binary)
    if os.environ.get("CHINADNS_TEST_VERDICT") == "1":
        check_verdict(binary)
    if os.environ.get("CHINADNS_TEST_DOT") == "1":
        check_dot(binary)
    print("e2e: local records, UDP/TCP, raw routing, cache, rotation, timeout, fallback: PASS")


if __name__ == "__main__":
    main()
