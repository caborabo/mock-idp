#!/usr/bin/env python3
"""AI-agent evaluation: can a coding agent use mock-idp through MCP alone?

Each task runs a headless Claude Code session that has ONLY the mock-idp MCP
server (no shell, no files, no user settings). The task is phrased the way a
developer would say it. Afterwards the script checks mock-idp's real state
through the API, so a confident wrong answer still fails.

Usage: interop/agent/run.py [--models sonnet,haiku] [--tasks t1,t3]
Needs: the `claude` CLI logged in, and mock-idp at MOCKIDP_URL (default :7070).
It resets mock-idp's data before each task.
"""
import argparse, base64, json, os, subprocess, sys, tempfile, time, urllib.request

BASE = os.environ.get("MOCKIDP_URL", "http://localhost:7070")
HERE = os.path.dirname(os.path.abspath(__file__))


def api(method, path, body=None):
    req = urllib.request.Request(BASE + "/api" + path, method=method,
                                 data=json.dumps(body).encode() if body is not None else None,
                                 headers={"content-type": "application/json"})
    try:
        with urllib.request.urlopen(req) as r:
            return json.loads(r.read() or b"null")
    except urllib.error.HTTPError as e:
        return {"_status": e.code, **json.loads(e.read() or b"{}")}


def jwt_claims(tok):
    p = tok.split(".")[1]
    return json.loads(base64.urlsafe_b64decode(p + "=" * (-len(p) % 4)))


def find_jwts(text):
    import re
    return re.findall(r"eyJ[\w-]+\.eyJ[\w-]+\.[\w-]*", text)


# ---------- tasks: prepare() sets the scene, check(answer) -> (ok, why) ----------

def t1_prepare():
    pass


def t1_check(answer):
    t = api("GET", "/tenants/entra")
    apps = [a for a in t["apps"] if a["type"] == "oidc" and "http://localhost:3000/auth/callback" in (a.get("redirectUris") or [])]
    if not apps:
        return False, "no Entra OIDC app with redirect http://localhost:3000/auth/callback"
    a = apps[0]
    missing = [k for k, v in {"client id": a["clientId"], "client secret": a.get("clientSecret") or "(public)",
                              "issuer": BASE + "/t/entra"}.items() if v not in answer and v != "(public)"]
    return (not missing), ("answer has issuer, client id and secret" if not missing else f"answer is missing: {', '.join(missing)}")


def t2_prepare():
    pass


def t2_check(answer):
    s = api("GET", "/tenants/okta/simulations")
    on = {k for k, v in s.items() if v}
    if on != {"samlExpired", "once"}:
        return False, f"okta simulations on: {sorted(on)}; want exactly samlExpired + once"
    others = [t["id"] for t in api("GET", "/tenants") if t["activeSimulations"] and t["id"] != "okta"]
    return (not others), ("only okta touched" if not others else f"also changed: {others}")


def t3_prepare():
    api("POST", "/tenants/okta/apps", {"type": "oidc", "name": "Billing", "redirectUris": ["https://billing.example/cb"]})
    app = [a for a in api("GET", "/tenants/okta")["apps"] if a["name"] == "Billing"][0]
    url = f"{BASE}/t/okta/authorize?client_id={app['clientId']}&redirect_uri=https%3A%2F%2Fbilling.example%2Fauth%2Fcallback&response_type=code&scope=openid&state=x&nonce=y"
    try:
        urllib.request.urlopen(url)
    except urllib.error.HTTPError:
        pass  # the 400 is the point: it lands in the log


def t3_check(answer):
    app = [a for a in api("GET", "/tenants/okta")["apps"] if a["name"] == "Billing"][0]
    if "https://billing.example/auth/callback" not in app["redirectUris"]:
        return False, f"redirect URIs still {app['redirectUris']}"
    if "redirect" not in answer.lower():
        return False, "fixed it, but the answer does not explain the redirect_uri mismatch"
    return True, "found the mismatch in the logs and registered the URI"


def t4_prepare():
    pass


def t4_check(answer):
    dave = [u for u in api("GET", "/tenants/google/users") if u["userName"].startswith("dave@")][0]
    toks = [c for c in map(jwt_claims, find_jwts(answer)) if "email" in c or "sub" in c]
    if not any(c.get("sub") == dave["id"] for c in toks):
        return False, "no ID token for dave in the answer"
    low = answer.lower()
    if not any(w in low for w in ["not verified", "unverified", "email_verified: false", "\"email_verified\": false", "email_verified is false", "is false"]):
        return False, "token present but the answer does not say dave's email is unverified"
    return True, "gave dave's token and said the email is unverified"


def t5_prepare():
    pass


def t5_check(answer):
    t = api("GET", "/tenants/entra")
    tg = [g for g in t["scimTargets"] if "scim.example.invalid" in g["baseUrl"]]
    if not tg:
        return False, "no SCIM target for https://scim.example.invalid/scim/v2"
    run = tg[0].get("lastResult")
    if not run or run["kind"] != "conformance":
        return False, "target created but no conformance run"
    low = answer.lower()
    if not any(w in low for w in ["could not connect", "couldn't connect", "cannot be reached", "unreachable", "no such host", "dns", "not reachable", "failed to connect", "connection", "resolve"]):
        return False, "ran it, but the answer does not say the server was unreachable"
    return True, "ran conformance as Entra and reported the server is unreachable"


TASKS = {
    "t1": ("Set up an app",
           "I'm building a web app on http://localhost:3000 that signs in with Microsoft Entra ID over OIDC. "
           "The callback is /auth/callback. Set this up in mock-idp and give me exactly what I paste into my app config.",
           t1_prepare, t1_check),
    "t2": ("Inject one fault",
           "QA wants the NEXT SAML sign-in on the Okta mock to fail with an expired assertion, and only that one; "
           "sign-ins after it must be normal again. Set that up. Don't change anything else.",
           t2_prepare, t2_check),
    "t3": ("Debug a failure",
           "Our Billing app can't log in through the Okta mock: users land on an error page. "
           "Find out why from mock-idp and fix it on the mock-idp side so the app's current request works.",
           t3_prepare, t3_check),
    "t4": ("Headless test data",
           "For a unit test I need a real ID token from the Google Workspace mock for the user Dave. "
           "Give me the token and tell me whether his email is verified.",
           t4_prepare, t4_check),
    "t5": ("SCIM against a dead server",
           "Run the SCIM conformance checks the way Entra ID would against https://scim.example.invalid/scim/v2 "
           "with bearer token abc123, and tell me how it went.",
           t5_prepare, t5_check),
}


def run(model, key):
    title, prompt, prepare, check = TASKS[key]
    api("POST", "/reset")
    api("DELETE", "/logs")
    prepare()
    work = tempfile.mkdtemp(prefix="agent-")
    cmd = ["claude", "-p", prompt, "--mcp-config", os.path.join(HERE, "mcp.json"), "--strict-mcp-config",
           "--setting-sources", "", "--tools", "", "--allowedTools", "mcp__mock-idp",
           "--output-format", "stream-json", "--verbose", "--model", model,
           "--no-session-persistence", "--max-budget-usd", "1"]
    start = time.time()
    p = subprocess.run(cmd, cwd=work, capture_output=True, text=True, stdin=subprocess.DEVNULL, timeout=600)
    secs = time.time() - start
    calls, errors, answer, cost, turns = [], [], "", 0.0, 0
    for line in p.stdout.splitlines():
        try:
            m = json.loads(line)
        except ValueError:
            continue
        if m.get("type") == "assistant":
            for c in m["message"].get("content", []):
                if c.get("type") == "tool_use":
                    calls.append(c["name"].replace("mcp__mock-idp__", ""))
        if m.get("type") == "user":
            for c in m["message"].get("content", []):
                if isinstance(c, dict) and c.get("type") == "tool_result" and c.get("is_error"):
                    txt = c["content"] if isinstance(c["content"], str) else json.dumps(c["content"])
                    errors.append(txt[:160])
        if m.get("type") == "result":
            answer, cost, turns = m.get("result", ""), m.get("total_cost_usd", 0), m.get("num_turns", 0)
    ok, why = check(answer)
    with open(os.path.join(HERE, "transcripts", f"{key}-{model}.jsonl"), "w") as f:
        f.write(p.stdout)
    return {"task": key, "title": title, "model": model, "ok": ok, "why": why, "calls": calls, "errors": errors,
            "secs": round(secs), "cost": round(cost, 3), "turns": turns, "answer": answer}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--models", default="sonnet,haiku")
    ap.add_argument("--tasks", default=",".join(TASKS))
    a = ap.parse_args()
    os.makedirs(os.path.join(HERE, "transcripts"), exist_ok=True)
    results = []
    for model in a.models.split(","):
        for key in a.tasks.split(","):
            r = run(model, key)
            results.append(r)
            print(f"{'PASS' if r['ok'] else 'FAIL'}  {model:7} {key} {r['title']:26} {len(r['calls']):2} calls {len(r['errors'])} errors "
                  f"{r['secs']:3}s ${r['cost']:.2f}  {r['why']}", flush=True)
    with open(os.path.join(HERE, "results.json"), "w") as f:
        json.dump(results, f, indent=2)
    api("POST", "/reset")
    passed = sum(r["ok"] for r in results)
    print(f"\n{passed}/{len(results)} passed, total ${sum(r['cost'] for r in results):.2f}")
    sys.exit(0 if passed == len(results) else 1)


if __name__ == "__main__":
    main()
