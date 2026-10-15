"""
app.py - Flask web application for the Failed Login Detection System.

Responsibilities of this file (and nothing more):
    * receive and VALIDATE the uploaded file
    * call detector.py to do the analysis
    * show the results and offer CSV downloads

Security notes (good interview talking points):
    * Uploaded files are read into memory and parsed as text. They are never
      saved to disk and never executed, so path traversal is not possible.
    * Upload size is capped (MAX_UPLOAD_BYTES) and only .txt / .log are accepted.
    * Jinja2 auto-escapes everything it renders (protects against XSS), and
      dashboard.js uses textContent instead of innerHTML.
    * A CSRF token protects the POST forms.
    * A Content-Security-Policy header limits where scripts can come from.
    * Debug mode is OFF unless you set FLASK_DEBUG=1 for local development.
"""

from __future__ import annotations

import hmac
import os
import secrets
import threading
from collections import OrderedDict

from flask import (Flask, Response, abort, flash, redirect, render_template,
                   request, send_from_directory, session, url_for)
from werkzeug.utils import secure_filename

import detector

BASE_DIR = os.path.abspath(os.path.dirname(__file__))
ALLOWED_EXTENSIONS = {".txt", ".log"}
MAX_UPLOAD_BYTES = 1 * 1024 * 1024   # 1 MB is plenty for a learning project
MAX_STORED_ANALYSES = 25             # oldest results are dropped after this many

CONTENT_SECURITY_POLICY = (
    "default-src 'self'; "
    "script-src 'self' https://cdn.jsdelivr.net; "   # Chart.js is loaded from this CDN
    "style-src 'self'; img-src 'self' data:; connect-src 'self'; "
    "object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'"
)


class AnalysisStore:
    """
    Keeps recent results in server memory (no database needed). Each browser
    session gets a random id stored in a signed cookie. Results disappear when
    the server restarts or when the user clicks Reset.
    """

    def __init__(self, limit: int = MAX_STORED_ANALYSES):
        self._items = OrderedDict()
        self._limit = limit
        self._lock = threading.Lock()

    def save(self, analysis: dict) -> str:
        analysis_id = secrets.token_urlsafe(16)
        with self._lock:
            self._items[analysis_id] = analysis
            while len(self._items) > self._limit:
                self._items.popitem(last=False)
        return analysis_id

    def get(self, analysis_id):
        with self._lock:
            return self._items.get(analysis_id)

    def delete(self, analysis_id) -> None:
        with self._lock:
            self._items.pop(analysis_id, None)


def create_app(test_config: dict | None = None) -> Flask:
    app = Flask(__name__)
    app.config.update(
        # Set SECRET_KEY in the environment for any real deployment.
        SECRET_KEY=os.environ.get("SECRET_KEY") or secrets.token_hex(32),
        MAX_CONTENT_LENGTH=MAX_UPLOAD_BYTES,
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Lax",
        SESSION_COOKIE_SECURE=os.environ.get("COOKIE_SECURE") == "1",  # set to 1 on HTTPS hosts
    )
    if test_config:
        app.config.update(test_config)

    store = AnalysisStore()
    app.extensions["analysis_store"] = store

    # ---------------------------------------------------------------- helpers
    def get_csrf_token() -> str:
        token = session.get("csrf_token")
        if not token:
            token = secrets.token_hex(16)
            session["csrf_token"] = token
        return token

    def check_csrf() -> None:
        sent = request.form.get("csrf_token", "").encode()
        expected = session.get("csrf_token", "").encode()
        if not expected or not hmac.compare_digest(sent, expected):
            abort(400)

    def current_analysis():
        analysis_id = session.get("analysis_id")
        return store.get(analysis_id) if analysis_id else None

    def limit_text() -> str:
        return f"{app.config['MAX_CONTENT_LENGTH'] / (1024 * 1024):.1f} MB"

    def show_index(message: str, category: str, status: int):
        flash(message, category)
        return render_template("index.html"), status

    @app.context_processor
    def template_globals():
        return {
            "csrf_token": get_csrf_token,
            "has_analysis": current_analysis() is not None,
            "default_threshold": detector.DEFAULT_THRESHOLD,
            "max_upload_bytes": app.config["MAX_CONTENT_LENGTH"],
            "max_upload_text": limit_text(),
        }

    @app.after_request
    def add_security_headers(response):
        response.headers["Content-Security-Policy"] = CONTENT_SECURITY_POLICY
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "no-referrer"
        if response.mimetype == "text/html":
            response.headers["Cache-Control"] = "no-store"
        return response

    # ----------------------------------------------------------------- routes
    @app.get("/")
    def index():
        return render_template("index.html")

    @app.post("/analyze")
    def analyze():
        check_csrf()
        upload = request.files.get("logfile")
        if upload is None or not upload.filename:
            flash("Choose a .txt or .log file, then select Analyze log.", "error")
            return redirect(url_for("index"))

        # secure_filename strips path parts such as "../". The name is only used
        # for display; the file is never written to disk.
        filename = secure_filename(upload.filename) or "uploaded.log"
        if os.path.splitext(filename)[1].lower() not in ALLOWED_EXTENSIONS:
            flash("Only .txt and .log files are supported.", "error")
            return redirect(url_for("index"))

        try:
            raw_threshold = request.form.get("threshold", "").strip()
            threshold = detector.validate_threshold(raw_threshold or detector.DEFAULT_THRESHOLD)

            limit = app.config["MAX_CONTENT_LENGTH"]
            data = upload.read(limit + 1)  # read at most one byte past the limit
            if len(data) > limit:
                flash(f"That file is larger than the {limit_text()} limit.", "error")
                return redirect(url_for("index"))

            analysis = detector.analyze_log(detector.decode_log_bytes(data), threshold)
        except detector.LogAnalysisError as error:
            flash(str(error), "error")  # messages from detector.py are safe to show
            return redirect(url_for("index"))
        except Exception:  # last-resort safety net: log details, show a calm message
            app.logger.exception("Unexpected error while analysing an upload")
            flash("Something unexpected went wrong while analysing that file. "
                  "Check that it is a plain-text log and try again.", "error")
            return redirect(url_for("index"))

        analysis["filename"] = filename
        store.delete(session.get("analysis_id"))  # drop the previous result
        session["analysis_id"] = store.save(analysis)
        if analysis["total_events"] == 0:
            flash("No valid events were found. Review the malformed entries below.", "warning")
        return redirect(url_for("dashboard"))

    @app.get("/dashboard")
    def dashboard():
        analysis = current_analysis()
        if analysis is None:
            flash("There is no analysis yet. Upload a log file to begin.", "info")
            return redirect(url_for("index"))
        chart_data = {
            "threshold": analysis["threshold"],
            "failed_total": analysis["failed_total"],
            "success_total": analysis["success_total"],
            "top_ips": [{"ip": r["ip"], "failed": r["failed"]} for r in analysis["top_ips"]],
            "events": analysis["events"],
        }
        return render_template("results.html", analysis=analysis, chart_data=chart_data)

    def csv_response(builder, filename: str):
        analysis = current_analysis()
        if analysis is None:
            flash("There is nothing to export yet. Upload a log file first.", "info")
            return redirect(url_for("index"))
        return Response(
            builder(analysis),
            mimetype="text/csv",
            headers={"Content-Disposition": f'attachment; filename="{filename}"'},
        )

    @app.get("/export/report.csv")
    def export_report():
        return csv_response(detector.report_to_csv, "failed_login_report.csv")

    @app.get("/export/events.csv")
    def export_events():
        return csv_response(detector.events_to_csv, "login_events.csv")

    @app.post("/reset")
    def reset():
        check_csrf()
        store.delete(session.pop("analysis_id", None))
        flash("Analysis cleared.", "success")
        return redirect(url_for("index"))

    @app.get("/sample-logs.txt")
    def sample_logs():
        # Fixed file name: no user input ever reaches the file path.
        return send_from_directory(BASE_DIR, "sample_logs.txt", as_attachment=True,
                                   download_name="sample_logs.txt", mimetype="text/plain")

    # ---------------------------------------------------------- error handlers
    @app.errorhandler(400)
    def bad_request(_error):
        return show_index("The request could not be processed. Reload the page and try again.", "error", 400)

    @app.errorhandler(404)
    def not_found(_error):
        return show_index("That page does not exist.", "error", 404)

    @app.errorhandler(413)
    def too_large(_error):
        return show_index(f"That file is larger than the {limit_text()} limit.", "error", 413)

    @app.errorhandler(500)
    def server_error(_error):
        return show_index("Something went wrong on the server. Please try again.", "error", 500)

    return app


app = create_app()  # module-level app so hosts can run "gunicorn app:app"

if __name__ == "__main__":
    # Local use only: binds to 127.0.0.1 so only your own computer can connect.
    app.run(host="127.0.0.1", port=int(os.environ.get("PORT", "5000")),
            debug=os.environ.get("FLASK_DEBUG") == "1")
