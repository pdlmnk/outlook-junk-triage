#!/usr/bin/env python3
"""Nightly Outlook junk-mail triage.

Three-way sort of the Junk Email folder:
  1. RESCUE   - sender is a known correspondent (sent mail / contacts) -> move to Inbox
  2. UNSUB    - DKIM-authenticated mail with RFC 8058 one-click unsubscribe -> fire POST
  3. EXPIRE   - everything else: permanently deleted once older than GRACE_HOURS

Digest of every action goes to ntfy if NTFY_URL is set. State in state.json prevents re-reporting.
Run with --dry-run to log actions without moving/deleting/unsubscribing.
"""
import json, os, re, shutil, sys, time, unicodedata
from datetime import datetime, timedelta, timezone

import requests

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from auth import get_token

BASE = os.path.dirname(os.path.abspath(__file__))
GRAPH = "https://graph.microsoft.com/v1.0"
NTFY_URL = os.environ.get("NTFY_URL", "")  # e.g. https://ntfy.sh/your-topic; empty = no push
GRACE_HOURS = 48
STATE_PATH = os.path.join(BASE, "state.json")
RULES_PATH = os.path.join(BASE, "rules.json")
if not os.path.exists(RULES_PATH):  # first run: start from the example rules
    shutil.copy(os.path.join(BASE, "rules.example.json"), RULES_PATH)
COUNTERS_PATH = os.path.join(BASE, "counters.json")
SPOOF_CATCH_PATH = os.path.join(BASE, "spoof_catches.json")
STATS_PATH = os.path.join(BASE, "stats.json")  # lifetime deletions; never pruned by rule edits
CORR_PATH = os.path.join(BASE, "correspondents.json")
CORR_MAX_AGE_DAYS = 7
DRY = "--dry-run" in sys.argv

def log(msg):
    print(f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S')} {msg}", flush=True)

def graph_get_all(session, url, limit=1000):
    items = []
    while url and len(items) < limit:
        r = session.get(url, timeout=60)
        r.raise_for_status()
        d = r.json()
        items += d.get("value", [])
        url = d.get("@odata.nextLink")
    return items

def load_json(path, default):
    if os.path.exists(path):
        with open(path) as f:
            return json.load(f)
    return default

def save_json(path, obj):
    with open(path + ".tmp", "w") as f:
        json.dump(obj, f, indent=1)
    os.replace(path + ".tmp", path)

def build_correspondents(session):
    """Addresses the user has written to (sent items) or saved (contacts)."""
    corr = load_json(CORR_PATH, None)
    if corr and time.time() - corr.get("built_at", 0) < CORR_MAX_AGE_DAYS * 86400:
        return set(corr["addresses"])
    log("refreshing correspondents cache...")
    addrs = set()
    sent = graph_get_all(session, GRAPH + "/me/mailFolders/sentitems/messages"
                         "?$select=toRecipients,ccRecipients&$top=100", limit=1000)
    for m in sent:
        for field in ("toRecipients", "ccRecipients"):
            for r in m.get(field) or []:
                a = r.get("emailAddress", {}).get("address", "").lower()
                if a:
                    addrs.add(a)
    try:  # needs Contacts.Read, which the granted token may not include
        contacts = graph_get_all(session, GRAPH + "/me/contacts?$select=emailAddresses&$top=100",
                                 limit=500)
        for c in contacts:
            for e in c.get("emailAddresses") or []:
                a = (e.get("address") or "").lower()
                if a:
                    addrs.add(a)
    except requests.HTTPError as e:
        log(f"contacts unavailable ({e.response.status_code}), using sent mail only")
    save_json(CORR_PATH, {"built_at": time.time(), "addresses": sorted(addrs)})
    log(f"correspondents: {len(addrs)} addresses")
    return addrs

def load_rules():
    """User-editable overrides. Senders match exact address or bare domain."""
    rules = load_json(RULES_PATH, {})
    return {
        "always_rescue": [x.lower() for x in rules.get("always_rescue", [])],
        "never_rescue": [x.lower() for x in rules.get("never_rescue", [])],
        "delete_now": [x.lower() for x in rules.get("delete_now", [])],
        "rescue_subject_keywords": [x.lower() for x in rules.get("rescue_subject_keywords", [])],
        "delete_subject_keywords": [x.lower() for x in rules.get("delete_subject_keywords", [])],
        "brand_domains": rules.get("brand_domains", {}),
        "spoof_ignore": [x.lower() for x in rules.get("spoof_ignore", [])],
        "delete_non_english": bool(rules.get("delete_non_english", False)),
    }

def count_deleted(kind, n=1):
    """Lifetime junk-deleted counter shared with web.py. kind: spoof | rule | expired | manual."""
    if DRY or not n:
        return
    st = load_json(STATS_PATH, {"since": time.strftime("%Y-%m-%d"), "deleted": {}})
    st["deleted"][kind] = st["deleted"].get(kind, 0) + n
    save_json(STATS_PATH, st)

def rule_match(entries, addr, domain):
    return addr in entries or domain in entries

def rule_hit(entries, addr, domain):
    """The specific entry that matched, for hit counting."""
    if addr in entries:
        return addr
    if domain in entries:
        return domain
    return None

def norm_kw(s):
    """Lowercase, punctuation -> space, collapse runs — so multi-word phrase
    rules match subjects regardless of punctuation/spacing. Mirror of
    normText() in index.html; keep the two in sync."""
    return " ".join(re.sub(r"[^\w$]+", " ", s.lower()).replace("_", " ").split())

def kw_hit(keywords, text):
    t = norm_kw(text)
    return next((k for k in keywords if norm_kw(k) in t), None)

def strip_invisible(s):
    """Drop zero-width/format chars spammers stuff into names to dodge keyword filters."""
    return "".join(c for c in s if unicodedata.category(c) != "Cf")

# --- non-English subject detection (2026-09-30) ---
# Junk here is overwhelmingly English; foreign junk so far is Portuguese
# (Correios/pedágio scams), which is Latin-script, so a script check alone
# misses it. Heuristic, no dependency: mostly non-Latin letters -> foreign;
# otherwise foreign stopwords/diacritics with zero English stopwords -> foreign.
EN_WORDS = set(
"""the and for you your with this that are from our have has was will not can all new
now get more what how why who when out off just about its it's here free only today
order account please need save see into of to in on is at by an be or my me us if do
so as it i a""".split())
FOREIGN_WORDS = set("""
o os as um uma de da na nos ou à é seu sua seus suas voce você não nao para com por pelo pela dos das
em foi está esta são sao ao aos até ate também mais mas pagamento encomenda aviso
el la los las del al es y que su sus usted por para con una unos gratis pedido
le les du des et est vous votre vos pour avec sur une au aux dans pas
der die das und ist sie ihr ihre mit für fur von auf bei nicht ein eine den dem zu
il di che per gli sono della alla
het een van voor niet zijn
""".split()) - EN_WORDS - {"die", "pour", "sale", "den", "son"}

def non_english(text):
    """True when the subject is clearly not English. Undecidable (no letters,
    e.g. all emoji/digits) counts as English -- only positive evidence deletes."""
    text = strip_invisible(text or "")
    letters = [c for c in text if c.isalpha()]
    if not letters:
        return False
    latin = [c for c in letters if "LATIN" in unicodedata.name(c, "")]
    if len(latin) < 0.5 * len(letters):
        return True
    words = re.findall(r"[^\W\d_]+(?:'[^\W\d_]+)?", text.lower())
    en = sum(w in EN_WORDS for w in words)
    if en:
        return False
    foreign = sum(w in FOREIGN_WORDS for w in words)
    accented = any(ord(c) > 127 for c in latin)
    # bilingual subjects ("Class action notice re beef purchases/Aviso de demanda
    # colectiva ...") keep an English half: any 3+-word segment with no foreign
    # words and no diacritics means English is present
    for seg in re.split(r"\s*[/|—–]\s*|\s+-\s+", text.lower()):
        sw = re.findall(r"[^\W\d_]+", seg)
        if len(sw) >= 3 and not any(w in FOREIGN_WORDS for w in sw) and seg.isascii():
            return False
    # foreign words must be a real share of the subject
    if foreign < 0.25 * len(words):
        return False
    return foreign >= 2 or (foreign >= 1 and accented)

# Brand -> legit-domain rules live entirely in rules.json "brand_domains"
# (seeded 2026-09-15 from the old hardcoded BRANDS dict; all user-editable now).

_NAME_DOMAIN_RE = re.compile(
    r"(?<![a-z0-9])([a-z0-9][a-z0-9-]*\.(?:com|net|org|io|us|shop|store|info|biz|co))(?![a-z0-9])")

def detect_spoof(name, domain, brand_rules=None, spoof_ignore=None):
    """Display name claims a brand (or embeds a domain) the sender domain doesn't match.

    Returns (key, reason) — key is the brand (or shown domain) for hit counting."""
    n = strip_invisible(name).lower().replace("'", "").replace("’", "")
    if not n:
        return None
    brands = {k.lower(): [d.lower() for d in v] for k, v in (brand_rules or {}).items()}
    ignore = {x.lower() for x in (spoof_ignore or [])}
    domain = domain.lower()
    for brand, doms in brands.items():
        if re.search(r"(?<![a-z0-9])" + re.escape(brand) + r"(?![a-z0-9])", n):
            if not any(domain == d or domain.endswith("." + d) for d in doms):
                return (brand, f"claims '{brand}' but sent from {domain}")
    m = _NAME_DOMAIN_RE.search(n)
    if m:
        d = m.group(1)
        if d not in ignore and domain != d and not domain.endswith("." + d) and not d.endswith("." + domain):
            return (d, f"name shows {d} but sent from {domain}")
    return None

def hdr(msg, name):
    for h in msg.get("internetMessageHeaders") or []:
        if h["name"].lower() == name.lower():
            return h["value"]
    return None

def dkim_pass(msg):
    ar = hdr(msg, "Authentication-Results") or ""
    return "dkim=pass" in ar.lower()

def oneclick_url(msg):
    """https unsubscribe URL if the message supports RFC 8058 one-click."""
    lu = hdr(msg, "List-Unsubscribe") or ""
    lup = hdr(msg, "List-Unsubscribe-Post") or ""
    if "one-click" not in lup.lower():
        return None
    m = re.search(r"<(https://[^>]+)>", lu)
    return m.group(1) if m else None

def main():
    tok = get_token()
    s = requests.Session()
    s.headers["Authorization"] = "Bearer " + tok

    rules = load_rules()
    state = load_json(STATE_PATH, {"seen_ids": [], "unsubbed_domains": []})
    seen = set(state["seen_ids"])
    unsubbed = set(state["unsubbed_domains"])
    corr = build_correspondents(s)
    counters = load_json(COUNTERS_PATH, {})

    def bump(key, entry):
        d = counters.setdefault(key, {})
        d[entry] = d.get(entry, 0) + 1

    junk = graph_get_all(session=s, url=GRAPH + "/me/mailFolders/junkemail/messages"
                         "?$select=id,subject,from,receivedDateTime,internetMessageHeaders&$top=50",
                         limit=1000)
    log(f"junk folder: {len(junk)} messages")

    now = datetime.now(timezone.utc)
    cutoff = now - timedelta(hours=GRACE_HOURS)
    rescued, unsub_ok, unsub_fail, deleted, new_arrivals, spoofed = [], [], [], [], [], []
    n_rule = n_expired = 0
    current_ids = set()

    for m in junk:
        mid = m["id"]
        current_ids.add(mid)
        addr = ((m.get("from") or {}).get("emailAddress", {}).get("address") or "?").lower()
        domain = addr.split("@")[-1]
        subj = (m.get("subject") or "(no subject)")[:80]
        rcvd = datetime.fromisoformat(m["receivedDateTime"].replace("Z", "+00:00"))
        line = f"{addr} | {subj}"
        is_new = mid not in seen
        if is_new:
            new_arrivals.append(line)

        # 1. rescue: explicit rule > subject keyword > known correspondent (unless never_rescue)
        # keywords match subject AND sender display name (spammers spoof names like "Disney+")
        from_name = ((m.get("from") or {}).get("emailAddress", {}).get("name") or "")
        subj_l = strip_invisible(subj + " " + from_name).lower()
        rescue_rule = rule_hit(rules["always_rescue"], addr, domain)
        rescue_kw = kw_hit(rules["rescue_subject_keywords"], subj_l)
        want_rescue = (
            rescue_rule or rescue_kw
            or (addr in corr and not rule_match(rules["never_rescue"], addr, domain))
        )
        if want_rescue:
            if rescue_rule:
                bump("always_rescue", rescue_rule)
            elif rescue_kw:
                bump("rescue_subject_keywords", rescue_kw)
            log(f"RESCUE  {line}")
            if not DRY:
                s.post(f"{GRAPH}/me/messages/{mid}/move",
                       json={"destinationId": "inbox"}, timeout=60).raise_for_status()
            rescued.append(line)
            continue

        # 1a. brand spoof (name claims a brand/domain the sender domain isn't) -> delete now
        spoof = detect_spoof(from_name, domain, rules["brand_domains"], rules["spoof_ignore"])
        if spoof:
            spoof_key, spoof_why = spoof
            bump("brand_spoofs", spoof_key)
            catches = load_json(SPOOF_CATCH_PATH, {})
            catches.setdefault(spoof_key, []).insert(0, {
                "when": time.strftime("%Y-%m-%d %H:%M"),
                "from": addr, "name": from_name, "subject": subj, "why": spoof_why})
            catches[spoof_key] = catches[spoof_key][:5]
            save_json(SPOOF_CATCH_PATH, catches)
            log(f"SPOOF   {line} [{spoof_why}]")
            if not DRY:
                s.delete(f"{GRAPH}/me/messages/{mid}", timeout=60).raise_for_status()
            spoofed.append(f"{line} [{spoof_why}]")
            current_ids.discard(mid)
            continue

        # 1b. explicit delete rules (sender or subject keyword) skip the grace window
        delete_rule = rule_hit(rules["delete_now"], addr, domain)
        delete_kw = None if delete_rule else kw_hit(rules["delete_subject_keywords"], subj_l)
        if delete_rule or delete_kw:
            bump("delete_now" if delete_rule else "delete_subject_keywords",
                 delete_rule or delete_kw)
            log(f"DELETE  (rule) {line}")
            if not DRY:
                s.delete(f"{GRAPH}/me/messages/{mid}", timeout=60).raise_for_status()
            deleted.append(line)
            n_rule += 1
            current_ids.discard(mid)
            continue

        # 1c. non-English subject (toggle on the web page) skips the grace window
        if rules["delete_non_english"] and non_english(subj):
            bump("non_english", "subject")
            log(f"DELETE  (non-english) {line}")
            if not DRY:
                s.delete(f"{GRAPH}/me/messages/{mid}", timeout=60).raise_for_status()
            deleted.append(line)
            n_rule += 1
            current_ids.discard(mid)
            continue

        # 2. one-click unsubscribe for authenticated marketing mail (once per domain)
        url = oneclick_url(m)
        if url and is_new and dkim_pass(m) and domain not in unsubbed:
            log(f"UNSUB   {domain} -> {url[:90]}")
            if not DRY:
                try:
                    r = requests.post(url, data="List-Unsubscribe=One-Click",
                                      headers={"Content-Type": "application/x-www-form-urlencoded"},
                                      timeout=20)
                    if r.status_code < 400:
                        unsub_ok.append(domain)
                    else:
                        unsub_fail.append(f"{domain} (http {r.status_code})")
                except requests.RequestException as e:
                    unsub_fail.append(f"{domain} ({type(e).__name__})")
                unsubbed.add(domain)  # one attempt per domain either way
            else:
                unsub_ok.append(domain)

        # 3. delete anything past the grace window
        if rcvd < cutoff:
            log(f"DELETE  {rcvd.date()} {line}")
            if not DRY:
                s.delete(f"{GRAPH}/me/messages/{mid}", timeout=60).raise_for_status()
            deleted.append(line)
            n_expired += 1
            current_ids.discard(mid)

    # state: remember only ids still sitting in junk (grace window), capped
    state["seen_ids"] = list(current_ids)[:2000]
    state["unsubbed_domains"] = sorted(unsubbed)
    if not DRY:
        save_json(STATE_PATH, state)
        save_json(COUNTERS_PATH, counters)
    count_deleted("spoof", len(spoofed))
    count_deleted("rule", n_rule)
    count_deleted("expired", n_expired)

    summary = (f"{len(new_arrivals)} new junk | rescued {len(rescued)} | "
               f"unsubscribed {len(unsub_ok)} | deleted {len(deleted)} | spoofs {len(spoofed)}")
    log("SUMMARY " + summary)

    if not (new_arrivals or rescued or deleted or spoofed):
        return
    body = []
    if rescued:
        body.append("RESCUED TO INBOX:")
        body += ["  " + x for x in rescued]
    if spoofed:
        body.append("BRAND SPOOFS DELETED:")
        body += ["  " + x for x in spoofed]
    if unsub_ok:
        body.append("unsubscribed: " + ", ".join(sorted(set(unsub_ok))))
    if unsub_fail:
        body.append("unsub failed: " + ", ".join(unsub_fail))
    if new_arrivals:
        body.append(f"new arrivals ({len(new_arrivals)}):")
        body += ["  " + x for x in new_arrivals[:60]]
        if len(new_arrivals) > 60:
            body.append(f"  ... and {len(new_arrivals) - 60} more")
    text = "\n".join(body)
    if DRY or not NTFY_URL:
        print("\n--- digest ---\n" + summary + "\n" + text)
        return
    try:
        requests.post(NTFY_URL, data=text.encode(),
                      headers={"Title": "Junk triage: " + summary,
                               "Tags": "email,wastebasket",
                               "Priority": "3" if rescued else "2"},
                      timeout=15)
    except requests.RequestException as e:
        log(f"ntfy failed: {e}")

if __name__ == "__main__":
    main()
