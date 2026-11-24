# SPDX-License-Identifier: Apache-2.0
"""A stateful stand-in for ``docker`` for the endpoint-forensics role's tests (CI is unprivileged).

It plays the one container the role runs: ``compose up`` writes the server configuration on the
first start only (a configuration that is there is kept, which is what the real start guard does)
and rotates its authority on ``restart`` only when asked (``FAKE_ROTATE``, the unguarded
entrypoint's behaviour); ``exec`` answers the few commands the role and the host script send
(account and policy commands, the client configuration, the queries). State lives in the file
named by ``FAKE_STATE``; the data root's ``etc/`` directory is named by ``FAKE_ETC``.
"""

from __future__ import annotations

import sys

BODY = r"""
import json, os, sys

STATE = os.environ["FAKE_STATE"]
ETC = os.environ["FAKE_ETC"]
HOST = os.environ.get("FAKE_HOST", "frontend.example.internal")
SVC = os.environ["FAKE_SERVICE"]
st = json.load(open(STATE)) if os.path.exists(STATE) else {"up": False, "restarts": 0, "ca_n": 0,
                                                            "principals": {}, "calls": []}
a = sys.argv[1:]
st["calls"].append(" ".join(a))

def save():
    json.dump(st, open(STATE, "w"))

def pem(n):
    return "-----BEGIN CERTIFICATE-----\n" + ("QUJD" * 60 + "\n") * 3 + f"{n:04d}\n-----END CERTIFICATE-----\n"

def write_config(n):
    os.makedirs(ETC, exist_ok=True)
    path = os.path.join(ETC, "server.config.yaml")
    with open(path, "w") as f:
        json.dump({"Client": {"ca_certificate": pem(n), "nonce": "nonce-value",
                              "server_urls": [f"wss://{HOST}:8000/", f"https://{HOST}:8000/"]}}, f)
    os.chmod(path, 0o600)

def host(p):
    return os.path.join(ETC, os.path.basename(p))

def out(text):
    sys.stdout.write(text if text.endswith("\n") or not text else text + "\n")

def done(rc=0):
    save()
    sys.exit(rc)

if a[:1] == ["info"]:
    out("systemd")
    done()
if a[:1] != ["compose"]:
    done(0)
i = a.index("-f") + 2
sub = a[i]
rest = a[i + 1:]
if sub == "config":
    done()
if sub == "up":
    st["up"] = True
    if not os.path.exists(os.path.join(ETC, "server.config.yaml")):
        st["ca_n"] = 1
        write_config(1)
    done()
if sub == "stop":
    st["up"] = False
    done()
if sub == "restart":
    st["restarts"] += 1
    if os.environ.get("FAKE_ROTATE"):
        st["ca_n"] += 1
        write_config(st["ca_n"] + 1)
    done()
if sub == "ps":
    out(json.dumps({"Service": SVC, "State": "running" if st["up"] else "exited",
                    "Health": "healthy"}))
    done()
if sub != "exec":
    done()
cmd = rest[rest.index(SVC) + 1:]
if cmd[:1] == ["nc"]:
    done(0 if st["up"] else 1)
if cmd[:2] == ["sh", "-c"]:
    done(0 if st["up"] and os.path.exists(os.path.join(ETC, "server.config.yaml")) else 1)
assert cmd[0] == "/bin/" + SVC, cmd
cmd = cmd[1:]
api = cmd[0] == "--api_config"
if cmd[0] in ("--config", "--api_config"):
    cmd = cmd[2:]
if cmd[:2] == ["config", "api_client"]:
    name = cmd[cmd.index("--name") + 1]
    role = cmd[cmd.index("--role") + 1]
    path = host(cmd[-1])
    with open(path, "w") as f:
        f.write("api_connection_string: api\nname: " + name + "\n")
    os.chmod(path, 0o600)
    st["principals"][name] = {"roles": [role]}
    done()
if cmd[:2] == ["acl", "show"]:
    p = st["principals"].get(cmd[2], {})
    out(json.dumps(p.get("policy") if "policy" in p else {"roles": p.get("roles", [])}))
    done()
if cmd[:2] == ["acl", "grant"]:
    st["principals"][cmd[2]]["policy"] = json.loads(cmd[3])
    done()
if cmd[:2] == ["config", "client"]:
    conf = json.load(open(os.path.join(ETC, "server.config.yaml")))
    out(json.dumps(conf))
    done()
if cmd[0] == "query":
    q = cmd[1]
    rows = []
    if "FROM clients()" in q:
        rows = st.get("clients", [])
    elif "artifact_definitions" in q:
        rows = st.get("definitions", [{"name": n, "required_permissions": [], "implied_permissions": []}
                                      for n in os.environ.get("FAKE_ARTIFACTS", "").split(",") if n])
    elif "gui_users()" in q:
        name = q.split("name = '")[1].split("'")[0]
        pol = st["principals"].get(name, {}).get("policy", {})
        rows = [{"name": name, "effective_policy": pol}]
    elif "execve" in q:
        rows = [{"Stdout": "ran"}] if os.environ.get("FAKE_EXEC_OPEN") else []
    elif "artifact_set" in q:
        rows = [{"r": {"name": "x"} if os.environ.get("FAKE_UPLOAD_OPEN") else None}]
    elif "/server.pem" in q:
        rows = [{"Response": 200, "Content": pem(st["ca_n"] + 1)}]
    elif ":8889/" in q:
        rows = [{"Response": int(os.environ.get("FAKE_GUI_STATUS", "401"))}]
    elif "hunt(description" in q:
        rows = [{"r": {"HuntId": "H.TESTHUNT1"}}]
    for r in rows:
        out(json.dumps(r))
    done()
done(0)
"""


def body() -> str:
    return BODY


if __name__ == "__main__":
    sys.stdout.write(BODY)
