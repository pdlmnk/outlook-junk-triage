# Outlook Junkmail Triage

Cleans out the Junk Email folder of a personal Outlook.com / Hotmail / Live mailbox every night, and gives you a small web page to watch it and tune the rules.

Each run sorts every message in Junk:

1. **Rescue**: the sender is someone you've emailed before (from your Sent Items), or matches one of your rescue rules → moved to Inbox.
2. **Delete now**: brand spoofs (the display name says "PayPal" but the mail comes from some other domain), your delete rules and keywords, and optionally non-English junk → permanently deleted.
3. **Unsubscribe**: legitimate senders (DKIM passes) that support RFC 8058 one-click unsubscribe → unsubscribed, once per domain. True spam is never unsubscribed, because that only confirms your address is live.
4. **Expire**: everything else is permanently deleted once it's older than 48 hours, so you have two days to spot a false positive.

A digest of each run can be pushed to your phone with [ntfy](https://ntfy.sh) (optional).

## The web page

- A **sign-in bar** at the top. Click *Sign in with Microsoft*, go to microsoft.com/link, and enter the code shown. No Azure app registration is needed.
- **Sitting in junk**: the live Junk folder with rescue / delete / +allow sender / +block domain buttons. Click words in a subject to build a keyword or phrase rule.
- **Rules**: grouped by type, with hit counts.
- Stats, the activity log, and a *Run triage now* button.

## Requirements

- Linux (or anything that runs Python 3.10+ and cron)
- A personal Microsoft account (outlook.com, hotmail.com, live.com)

## Install

```sh
git clone https://github.com/<you>/outlook-junk-triage.git ~/junk-triage
cd ~/junk-triage
python3 -m venv venv
venv/bin/pip install -r requirements.txt
```

Start the web page:

```sh
venv/bin/uvicorn web:app --host 127.0.0.1 --port 8210
```

Open http://127.0.0.1:8210 and sign in. Then try a dry run, which logs what it *would* do without touching anything:

```sh
venv/bin/python triage.py --dry-run
```

When you're happy with it, run it nightly with cron (`crontab -e`):

```
30 7 * * * cd $HOME/junk-triage && venv/bin/python triage.py >> triage.log 2>&1
```

To keep the web page running, see [`deploy/junk-triage-web.service`](deploy/junk-triage-web.service) for a systemd unit.

You can also sign in from a terminal instead of the page: `venv/bin/python auth.py --login`.

## Phone notifications (optional)

Set `NTFY_URL` to an ntfy topic, and each run posts its digest there. Install the ntfy app and subscribe to the same topic.

```
30 7 * * * cd $HOME/junk-triage && NTFY_URL=https://ntfy.sh/pick-a-long-random-topic venv/bin/python triage.py >> triage.log 2>&1
```

Anyone who knows a topic name on the public ntfy.sh server can read it, so pick a long random name or [self-host ntfy](https://docs.ntfy.sh/install/).

## Security: read this

- **The web page has no login of its own.** Anyone who can open it can read your junk folder, delete mail, change rules, and sign the mailbox in or out. It listens on 127.0.0.1 by default. If you expose it on your network, put it behind a reverse proxy that requires authentication (Authelia, basic auth, etc.), and never expose it to the internet.
- `token_cache.json` holds your Microsoft refresh token, which is a key to your mailbox. It is written with mode 0600 and listed in `.gitignore`; keep it that way.
- Sign-in uses Microsoft's own public client ID for "Microsoft Graph Command Line Tools", because personal Microsoft accounts can't register their own Azure apps. Scopes requested: `Mail.ReadWrite`, `Mail.Send`, `User.Read`.
- The refresh token stays valid as long as the nightly job keeps using it. If it ever expires, the page shows a red bar; sign in again.

## Files it creates

All of these are personal and are ignored by git:

| File | What |
|---|---|
| `token_cache.json` | Microsoft sign-in |
| `rules.json` | your rules (created from `rules.example.json` on first run) |
| `correspondents.json` | addresses from your Sent Items, refreshed weekly |
| `state.json`, `counters.json`, `stats.json`, `spoof_catches.json` | run state and counters |
| `triage.log` | activity log |

## License

MIT
