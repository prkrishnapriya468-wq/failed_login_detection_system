# Failed Login Detection System

A small Python and Flask web app that reads an authentication log, counts failed logins per source IP address, and raises an alert when an IP reaches a configurable threshold (default: 5 failures).

It is a learning project for SOC (Security Operations Center) and Blue Team basics: log parsing, grouping events, threshold-based detection, and presenting results in a dashboard. It runs entirely on your own computer and works only with files you upload. It never connects to a login system.

> **An alert is a signal to investigate, not proof of an attack.** A forgotten password, a misconfigured service, or a shared office IP can all look like repeated failures.

## Features

- Upload a `.txt` or `.log` file (up to 1 MB)
- Parses each event into timestamp, IP address, username, and status
- Counts `FAILED` events per IP and alerts at or above a threshold you choose
- Summary cards: total events, failed, successful, IPs needing investigation
- Bar chart of failed attempts by IP and a doughnut chart of successful vs failed
- Table of the most frequently failing IPs
- Searchable events table with status, IP, and date filters
- Lists malformed log lines separately instead of crashing
- CSV export of the per-IP report and of all events
- Reset button and a sample-log download button
- Friendly handling of empty, binary, oversized, and malformed uploads

## How it works

```
Upload  ->  validate file  ->  parse lines  ->  count FAILED per IP  ->  compare with threshold  ->  dashboard / CSV
(app.py)    (app.py)           (detector.py)    (detector.py)            (detector.py)               (templates + JS)
```

1. `app.py` checks the file extension, size, and CSRF token, then reads the upload into memory (it is never saved to disk).
2. `detector.py` validates the threshold, parses each line, and reports bad lines as malformed entries.
3. `FAILED` events are counted per IP. `SUCCESS` events are counted separately and never as failures.
4. Any IP with a count **greater than or equal to** the threshold becomes an alert.
5. The dashboard shows numbers calculated by the backend. The browser only draws charts and filters the table.

### Important limitation: no rolling time window

Failures are counted across the **whole uploaded file**. Five failures spread over five days count the same as five failures in one minute. Real detection rules usually look at a time window (for example, 5 failures in 10 minutes). This is listed under future improvements.

## Log format

One event per line, four fields separated by `|`:

```
2026-10-15 09:01:00 | 198.51.100.23 | admin | FAILED
```

- Timestamp: `YYYY-MM-DD HH:MM:SS`
- IP: IPv4 or IPv6
- Username: 1 to 64 characters from letters, digits, `.`, `_`, `@`, `-`
- Status: `SUCCESS` or `FAILED` (case-insensitive)
- Blank lines and lines starting with `#` are ignored

The sample data uses documentation-only IP addresses (`192.0.2.x`, `198.51.100.x`, `203.0.113.x`), so it points at no real systems.

## Technologies

Python 3, Flask, HTML5, CSS3, JavaScript, Chart.js (loaded from a CDN), and `unittest`. No database.

## Project files

| File | Purpose |
|------|---------|
| `app.py` | Flask routes, upload validation, CSRF, security headers |
| `detector.py` | Parsing, detection, and CSV export (no web code) |
| `test_detector.py` | Automated tests |
| `sample_logs.txt` | Fictional demo log |
| `templates/base.html` | Shared page layout and sidebar (extra file) |
| `templates/index.html` | Upload page |
| `templates/results.html` | Dashboard |
| `static/css/style.css` | Dark theme |
| `static/js/dashboard.js` | Charts, table filters, upload size check |
| `requirements.txt` | Dependencies for local use |
| `requirements-deploy.txt` | Adds `gunicorn` for cloud hosting (extra file) |
| `.gitignore` | Keeps virtual environments and cache files out of Git (extra file) |

## Installation on Windows

Open PowerShell in the project folder.

```powershell
python -m venv .venv
.venv\Scripts\activate
python -m pip install -r requirements.txt
python -m unittest -v
python app.py
```

Then open **http://127.0.0.1:5000** in your browser. Press `Ctrl+C` in the terminal to stop the server.

If PowerShell blocks `activate`, run `Set-ExecutionPolicy -Scope Process -ExecutionPolicy RemoteSigned` first, then activate again.

The charts load Chart.js from the internet. Without a connection, the tables still work and the page tells you the charts could not load.

## Try it

1. Select **Download sample log** in the sidebar (or use `sample_logs.txt`).
2. Upload it with the default threshold of 5.

### Expected output for `sample_logs.txt` at threshold 5

| Total events | Failed | Successful | IPs needing investigation | Malformed lines |
|---|---|---|---|---|
| 34 | 24 | 10 | 3 | 4 |

Report CSV:

```
ip,failed_attempts,successful_attempts,needs_investigation,first_failed,last_failed,usernames_targeted
198.51.100.23,9,0,YES,2026-10-15 09:01:13,2026-10-15 09:17:13,admin; administrator; guest; oracle; root; test
192.0.2.77,6,1,YES,2026-10-15 09:40:30,2026-10-15 09:45:30,jsmith
203.0.113.44,5,0,YES,2026-10-15 09:20:05,2026-10-15 09:24:05,svc_backup
192.0.2.10,3,3,NO,2026-10-15 09:05:41,2026-10-15 09:23:41,alice
198.51.100.5,1,3,NO,2026-10-15 09:35:00,2026-10-15 09:35:00,bob
192.0.2.150,0,3,NO,,,
```

Things to notice when you explain it: `203.0.113.44` alerts at **exactly** 5 failures; `192.0.2.10` stays below the threshold; `192.0.2.77` failed 6 times and then signed in once, which is the kind of pattern an analyst would look at first.

## Screenshots

Add your own screenshots to a `docs/` folder after you run the app, then link them here.

| Dashboard | Alerts | Events table |
|---|---|---|
| `docs/dashboard.png` (placeholder) | `docs/alerts.png` (placeholder) | `docs/events.png` (placeholder) |

## Testing

```powershell
python -m unittest -v
```

The 37 tests cover valid parsing, malformed lines, successes not counted as failures, alerts at, above, and below the threshold, empty files, invalid thresholds, CSV export (including formula neutralising), oversized and binary uploads, CSRF, HTML escaping, and path-traversal file names.

## Security considerations

- Uploads are read into memory, parsed as text, and never saved or executed
- Only `.txt` and `.log` files up to 1 MB are accepted; file names are sanitised with `secure_filename`
- Jinja2 escapes all rendered values, and `dashboard.js` uses `textContent` rather than `innerHTML`
- A Content-Security-Policy header, `X-Frame-Options`, and `nosniff` are set on every response
- POST forms use a CSRF token
- CSV cells that start with `=`, `+`, `-`, or `@` get a leading apostrophe so spreadsheets do not run them as formulas
- Debug mode is off unless you set `FLASK_DEBUG=1`, and the local server listens only on `127.0.0.1`
- No passwords, tokens, or credentials are collected. Do not upload logs that contain them

### Limitations

- No rolling time window (see above)
- Results are kept in server memory per browser session and vanish on restart
- No user accounts, so this is not meant to be exposed to the public internet as it stands
- Chart.js is loaded from a CDN without a Subresource Integrity hash; for a stricter setup, download it into `static/js/` and update the CSP
- Only the single log format above is supported

## Future improvements

- Rolling time-window detection (for example, 5 failures in 10 minutes)
- Support for real formats such as Linux `auth.log` or Windows Event Log exports
- Detect "many failures followed by a success" as its own alert
- Group by username to spot password spraying across accounts
- Persistent storage (SQLite) and login for the dashboard
- Vendored Chart.js with Subresource Integrity

## Optional: deploy to a Python host (for example Render)

This is optional and only for demonstration with fictional logs. Because results live in memory, run **one** worker process.

1. Push the project to GitHub (below).
2. Create a new **Web Service** on your host and connect the repository.
3. Build command: `pip install -r requirements-deploy.txt`
4. Start command: `gunicorn app:app --workers 1 --threads 4`
5. Environment variables:
   - `SECRET_KEY`: a long random value, for example from `python -c "import secrets; print(secrets.token_hex(32))"`. Never commit it
   - `COOKIE_SECURE=1`: send the session cookie only over HTTPS
6. Do **not** set `FLASK_DEBUG` in production.
7. Because there are no accounts, anyone with the URL can use the app. Share the link carefully, or skip cloud deployment and show the project locally.

## Publish on GitHub

1. Create an empty repository on github.com (no README, since you already have one).
2. In the project folder:

```powershell
git init
git add .
git commit -m "Initial commit: failed login detection system"
git branch -M main
git remote add origin https://github.com/<your-username>/failed-login-detection-system.git
git push -u origin main
```

3. Add your screenshots to `docs/`, and choose a license if you want one (MIT is common for portfolio projects).
