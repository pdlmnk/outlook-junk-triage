import json, os, sys, threading, time
import msal

CLIENT_ID = "14d82eec-204b-4c2f-b7e8-296a70dab67e"  # Microsoft Graph Command Line Tools (public client)
AUTHORITY = "https://login.microsoftonline.com/consumers"
SCOPES = ["Mail.ReadWrite", "Mail.Send", "User.Read"]
CACHE_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "token_cache.json")

def get_app():
    cache = msal.SerializableTokenCache()
    if os.path.exists(CACHE_PATH):
        with open(CACHE_PATH) as f:
            cache.deserialize(f.read())
    app = msal.PublicClientApplication(CLIENT_ID, authority=AUTHORITY, token_cache=cache)
    return app, cache

def save_cache(cache):
    if cache.has_state_changed:
        with open(CACHE_PATH, "w") as f:
            f.write(cache.serialize())
        os.chmod(CACHE_PATH, 0o600)

def get_token(interactive=False):
    app, cache = get_app()
    result = None
    accounts = app.get_accounts()
    if accounts:
        result = app.acquire_token_silent(SCOPES, account=accounts[0])
    if not result and interactive:
        flow = app.initiate_device_flow(scopes=SCOPES)
        if "user_code" not in flow:
            print(json.dumps(flow, indent=2), file=sys.stderr)
            sys.exit(1)
        print(flow["message"], flush=True)
        result = app.acquire_token_by_device_flow(flow)
    save_cache(cache)
    if not result or "access_token" not in result:
        err = result.get("error_description", "no cached token") if result else "no cached token"
        raise SystemExit(f"AUTH FAILED: {err}")
    return result["access_token"]

# ---- web sign-in (from the web page) ----------------------------------------
# Same device-code flow as `auth.py --login`, but started from the page:
# the page shows the code, a background thread waits for Microsoft to
# confirm, then the token lands in token_cache.json like a CLI login.
_lock = threading.Lock()
_pending = {}   # code, url, expires_at, done, error

def account():
    app, _ = get_app()
    accts = app.get_accounts()
    return accts[0].get("username") if accts else None

def start_login():
    with _lock:
        if _pending.get("code") and not _pending.get("done") \
                and _pending.get("expires_at", 0) > time.time():
            return dict(_pending)          # one sign-in at a time
        app, cache = get_app()
        flow = app.initiate_device_flow(scopes=SCOPES)
        if "user_code" not in flow:
            raise RuntimeError(flow.get("error_description", "could not start sign-in"))
        _pending.clear()
        _pending.update(code=flow["user_code"], url=flow["verification_uri"],
                        expires_at=flow.get("expires_at", time.time() + 900),
                        done=False, error=None)

        def wait():
            result = app.acquire_token_by_device_flow(flow)
            if result and "access_token" in result:
                who = (result.get("id_token_claims") or {}).get("preferred_username")
                for a in app.get_accounts():   # keep only the account just signed in
                    if who and a.get("username") != who:
                        app.remove_account(a)
                save_cache(cache)
                _pending.update(done=True, error=None)
            else:
                _pending.update(done=True, error=(result or {}).get(
                    "error_description", "sign-in failed or timed out"))
        threading.Thread(target=wait, daemon=True).start()
        return dict(_pending)

def login_status():
    return dict(_pending)

def sign_out():
    app, cache = get_app()
    for a in app.get_accounts():
        app.remove_account(a)
    save_cache(cache)
    _pending.clear()

if __name__ == "__main__":
    import requests
    tok = get_token(interactive="--login" in sys.argv)
    me = requests.get("https://graph.microsoft.com/v1.0/me",
                      headers={"Authorization": "Bearer " + tok}).json()
    print("authenticated as:", me.get("userPrincipalName"))
