#!/usr/bin/env python3
"""Web UI for outlook-junk-triage.

Serves the rules editor + live junk-folder view. Binds 127.0.0.1:8210,
put a reverse proxy in front to reach it from your LAN. Reuses auth.py's
token cache. The page has no login of its own -- see README.
"""
import json, os, subprocess, sys, time, unicodedata
from datetime import datetime

import requests
from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse
from pydantic import BaseModel

BASE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, BASE)
from auth import get_token, account, start_login, login_status, sign_out
from triage import detect_spoof, count_deleted, non_english

GRAPH = "https://graph.microsoft.com/v1.0"
RULES_PATH = os.path.join(BASE, "rules.json")
STATE_PATH = os.path.join(BASE, "state.json")
COUNTERS_PATH = os.path.join(BASE, "counters.json")
SPOOF_CATCH_PATH = os.path.join(BASE, "spoof_catches.json")
STATS_PATH = os.path.join(BASE, "stats.json")
LOG_PATH = os.path.join(BASE, "triage.log")
VENV_PY = os.path.join(BASE, "venv", "bin", "python")
TRIAGE = os.path.join(BASE, "triage.py")

RULE_KEYS = ["always_rescue", "never_rescue", "delete_now",
             "rescue_subject_keywords", "delete_subject_keywords"]

app = FastAPI()

def load_json(path, default):
    if os.path.exists(path):
        with open(path) as f:
            return json.load(f)
    return default

def save_json(path, obj):
    with open(path + ".tmp", "w") as f:
        json.dump(obj, f, indent=1)
    os.replace(path + ".tmp", path)

def gsession():
    s = requests.Session()
    try:
        tok = get_token()
    except SystemExit as e:            # no/expired token -> page shows the sign-in bar
        raise HTTPException(401, str(e))
    s.headers["Authorization"] = "Bearer " + tok
    return s

@app.get("/api/auth")
def auth_state():
    user, ok, err = account(), False, None
    if user:
        try:
            get_token(); ok = True
        except SystemExit as e:
            err = str(e)
    p = login_status()
    pending = p if p.get("code") and not p.get("done") \
        and p.get("expires_at", 0) > time.time() else None
    return {"user": user, "ok": ok, "pending": pending,
            "error": None if ok else (p.get("error") or err)}

@app.post("/api/auth/start")
def auth_start():
    try:
        p = start_login()
    except RuntimeError as e:
        raise HTTPException(502, str(e))
    weblog("UI SIGN-IN started")
    return p

@app.post("/api/auth/signout")
def auth_signout():
    weblog(f"UI SIGN-OUT {account() or ''}")
    sign_out()
    return {"ok": True}

@app.get("/")
def index():
    return FileResponse(os.path.join(BASE, "index.html"))

@app.get("/api/state")
def state():
    s = gsession()
    r = s.get(GRAPH + "/me/mailFolders/junkemail/messages"
              "?$select=id,subject,from,receivedDateTime&$top=100"
              "&$orderby=receivedDateTime desc", timeout=60)
    r.raise_for_status()
    junk = []
    raw_rules = load_json(RULES_PATH, {})
    for m in r.json().get("value", []):
        ea = (m.get("from") or {}).get("emailAddress", {})
        addr = (ea.get("address") or "?").lower()
        domain = addr.split("@")[-1]
        strip_inv = lambda s: "".join(c for c in s if unicodedata.category(c) != "Cf")
        name = strip_inv(ea.get("name") or "")
        sp = detect_spoof(name, domain, raw_rules.get("brand_domains"),
                          raw_rules.get("spoof_ignore"))
        junk.append({
            "id": m["id"],
            "from": addr,
            "name": name,
            "domain": domain,
            "subject": strip_inv(m.get("subject") or "(no subject)"),
            "received": m.get("receivedDateTime", ""),
            "spoof": sp and sp[1],
            "foreign": non_english(m.get("subject") or ""),
        })
    triage_state = load_json(STATE_PATH, {})
    log_tail, last_summary = [], ""
    if os.path.exists(LOG_PATH):
        with open(LOG_PATH, errors="replace") as f:
            log_tail = f.readlines()[-200:]
        for ln in reversed(log_tail):
            if "SUMMARY" in ln:
                last_summary = ln.strip()
                break
    return {
        "junk": junk,
        "rules": {**{k: raw_rules.get(k, []) for k in RULE_KEYS},
                  "brand_domains": raw_rules.get("brand_domains", {}),
                  "spoof_ignore": raw_rules.get("spoof_ignore", [])},
        "settings": {"delete_non_english": bool(raw_rules.get("delete_non_english", False))},
        "spoof_catches": load_json(SPOOF_CATCH_PATH, {}),
        "rule_hits": load_json(COUNTERS_PATH, {}),
        "stats": load_json(STATS_PATH, {}),
        "unsubbed_domains": triage_state.get("unsubbed_domains", []),
        "log_tail": "".join(log_tail[-80:]),
        "last_summary": last_summary,
    }

class Rules(BaseModel):
    always_rescue: list[str]
    never_rescue: list[str]
    delete_now: list[str]
    rescue_subject_keywords: list[str]
    delete_subject_keywords: list[str] = []
    brand_domains: dict[str, list[str]] = {}
    spoof_ignore: list[str] = []

@app.post("/api/rules")
def put_rules(rules: Rules):
    clean = {k: sorted({x.strip().lower() for x in getattr(rules, k) if x.strip()})
             for k in RULE_KEYS}
    brands = {}
    for b, doms in rules.brand_domains.items():
        b = b.strip().lower()
        ds = sorted({d.strip().lower() for d in doms if d.strip()})
        if b and ds:
            brands[b] = ds
    ignore = sorted({d.strip().lower() for d in rules.spoof_ignore if d.strip()})
    existing = load_json(RULES_PATH, {})
    existing.update(clean)
    existing["brand_domains"] = brands
    existing["spoof_ignore"] = ignore
    save_json(RULES_PATH, existing)
    counters = load_json(COUNTERS_PATH, {})  # drop counts for removed entries
    pruned = {k: {e: n for e, n in counters.get(k, {}).items() if e in clean[k]}
              for k in RULE_KEYS}
    # keep spoof counts for brand rules and un-ignored domain-mismatch hits
    pruned["brand_spoofs"] = {e: n for e, n in counters.get("brand_spoofs", {}).items()
                              if e in brands or ("." in e and e not in ignore)}
    if "non_english" in counters:
        pruned["non_english"] = counters["non_english"]
    if pruned != counters:
        save_json(COUNTERS_PATH, pruned)
    catches = load_json(SPOOF_CATCH_PATH, {})
    kept = {e: v for e, v in catches.items()
            if e in brands or ("." in e and e not in ignore)}
    if kept != catches:
        save_json(SPOOF_CATCH_PATH, kept)
    return {**clean, "brand_domains": brands, "spoof_ignore": ignore}

class Settings(BaseModel):
    delete_non_english: bool

@app.post("/api/settings")
def put_settings(st: Settings):
    rules = load_json(RULES_PATH, {})
    rules["delete_non_english"] = st.delete_non_english
    save_json(RULES_PATH, rules)
    weblog(f"UI SETTING delete_non_english={st.delete_non_english}")
    return {"delete_non_english": st.delete_non_english}

class MsgAction(BaseModel):
    id: str
    action: str          # rescue | delete
    remember: bool = False
    sender: str = ""     # exact address (rescue) or domain (delete) to add as rule
    rule_key: str = ""   # when the action was driven by a rule entry, count the hit
    rule_value: str = ""
    note: str = ""       # "addr | subject" for the activity log

def weblog(msg):
    with open(LOG_PATH, "a") as f:
        f.write(f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S')} {msg}\n")

@app.post("/api/message-action")
def message_action(a: MsgAction):
    s = gsession()
    if a.action == "rescue":
        r = s.post(f"{GRAPH}/me/messages/{a.id}/move",
                   json={"destinationId": "inbox"}, timeout=60)
    elif a.action == "delete":
        r = s.delete(f"{GRAPH}/me/messages/{a.id}", timeout=60)
    else:
        raise HTTPException(400, "unknown action")
    if r.status_code >= 400:
        raise HTTPException(r.status_code, f"graph error: {r.text[:200]}")
    if a.action == "delete":
        count_deleted("manual")
    if a.note:
        why = f" [rule {a.rule_key}: {a.rule_value}]" if a.rule_key.strip() \
              else (" [+rule]" if a.remember else "")
        weblog(f"UI {a.action.upper():7}{a.note}{why}")
    if a.rule_key in RULE_KEYS + ["brand_spoofs"] and a.rule_value.strip():
        counters = load_json(COUNTERS_PATH, {})
        d = counters.setdefault(a.rule_key, {})
        v = a.rule_value.strip().lower()
        d[v] = d.get(v, 0) + 1
        save_json(COUNTERS_PATH, counters)
    if a.remember and a.sender:
        rules = load_json(RULES_PATH, {k: [] for k in RULE_KEYS})
        key = "always_rescue" if a.action == "rescue" else "delete_now"
        entry = a.sender.strip().lower()
        if entry and entry not in rules.get(key, []):
            rules.setdefault(key, []).append(entry)
            rules[key].sort()
            save_json(RULES_PATH, rules)
    return {"ok": True}

@app.post("/api/run")
def run_now():
    with open(LOG_PATH, "a") as logf:
        logf.write(f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S')} manual run from web UI\n")
        logf.flush()
        p = subprocess.run([VENV_PY, TRIAGE], stdout=logf, stderr=logf, timeout=600)
    if p.returncode != 0:
        raise HTTPException(500, "triage run failed - see log")
    with open(LOG_PATH, errors="replace") as f:
        lines = f.readlines()
    summary = next((ln.strip() for ln in reversed(lines) if "SUMMARY" in ln), "done")
    return {"summary": summary}
