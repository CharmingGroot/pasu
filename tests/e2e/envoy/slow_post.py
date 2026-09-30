"""POST a JSON body as a chunked request, in pieces with a pause between them.

curl sends a body in one write, and the data plane then hands it to pasu in one
piece — so a mode that forwards pieces before the whole body is judged is never
tested. This sends the first `split` bytes, waits, then the rest, the way a
slow client or a proxy in front would.

usage: slow_post.py <host> <port> <path> <body-file> <status-out> <body-out>
"""

import socket
import sys
import time

host, port, path, body_file, status_out, body_out = sys.argv[1:7]
body = open(body_file, "rb").read()
split = min(4096, len(body))
pieces = [body[:split], body[split:]]

status, response = "000", b""
try:
    with socket.create_connection((host, int(port)), timeout=30) as s:
        s.sendall(
            b"POST %s HTTP/1.1\r\nhost: %s\r\ncontent-type: application/json\r\n"
            b"transfer-encoding: chunked\r\nconnection: close\r\n\r\n"
            % (path.encode(), host.encode())
        )
        for piece in pieces:
            if piece:
                s.sendall(b"%x\r\n%s\r\n" % (len(piece), piece))
            time.sleep(0.3)
        s.sendall(b"0\r\n\r\n")
        while True:
            data = s.recv(65536)
            if not data:
                break
            response += data
except OSError:
    pass

head, _, rest = response.partition(b"\r\n\r\n")
if head.startswith(b"HTTP/"):
    status = head.split(b" ")[1].decode()
    if b"transfer-encoding: chunked" in head.lower():
        out, buf = b"", rest
        while buf:
            line, _, buf = buf.partition(b"\r\n")
            n = int(line.split(b";")[0] or b"0", 16)
            if n == 0:
                break
            out, buf = out + buf[:n], buf[n + 2 :]
        rest = out
open(status_out, "w").write(status)
open(body_out, "wb").write(rest)
