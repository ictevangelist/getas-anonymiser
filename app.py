"""Web portal for anonymising Global EdTech Awards entries."""

import csv
import hmac
import io
import json
import os
import shutil
import threading
import time
import zipfile
from datetime import datetime, timedelta
from functools import wraps
from pathlib import Path

import pymupdf
from flask import (Flask, abort, flash, redirect, render_template, request,
                   send_file, session, url_for)

import engine

DATA = Path(os.environ.get("DATA_DIR", "data")) / "entries"
DATA.mkdir(parents=True, exist_ok=True)
PREFIX = os.environ.get("CODE_PREFIX", "GETA26")

app = Flask(__name__)
app.config.update(
    SECRET_KEY=os.environ["SECRET_KEY"],
    MAX_CONTENT_LENGTH=200 * 1024 * 1024,
    PERMANENT_SESSION_LIFETIME=timedelta(hours=12),
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=not os.environ.get("DEV"),
)
lock = threading.Lock()


# ---------- storage ----------

def entry_dir(code):
    path = DATA / code
    if not code.startswith(PREFIX) or not path.is_dir():
        abort(404)
    return path


def load(code):
    return json.loads((entry_dir(code) / "meta.json").read_text())


def save(meta):
    with lock:
        (DATA / meta["code"] / "meta.json").write_text(json.dumps(meta, indent=2))


def all_entries():
    metas = [json.loads(p.read_text()) for p in DATA.glob("*/meta.json")]
    return sorted(metas, key=lambda m: m["code"])


def next_code():
    numbers = [int(p.name.rsplit("-", 1)[1]) for p in DATA.iterdir()
               if p.is_dir() and p.name.rsplit("-", 1)[-1].isdigit()]
    return f"{PREFIX}-{max(numbers, default=0) + 1:03d}"


def lines(text):
    return [line.strip() for line in text.splitlines() if line.strip()]


# ---------- processing ----------

def apply(meta):
    """Redact every file using saved findings plus the entry's name lists."""
    base = DATA / meta["code"]
    for f in meta["files"]:
        findings = json.loads((base / "findings" / f"{f['stem']}.json").read_text())
        f["report"] = engine.redact(
            base / "originals" / f"{f['stem']}.pdf", findings,
            meta["names"], meta["keep"],
            base / "judges" / f"{f['stem']}.pdf",
            base / "preview" / f"{f['stem']}.pdf")


def process(code):
    """Background job: ask Claude about any file without findings, then redact."""
    meta = load(code)
    base = DATA / code
    try:
        for f in meta["files"]:
            findings_path = base / "findings" / f"{f['stem']}.json"
            if not findings_path.exists():
                findings = engine.find_identifiers(
                    base / "originals" / f"{f['stem']}.pdf", meta["names"])
                findings_path.write_text(json.dumps(findings, indent=2))
        apply(meta)
        meta.update(status="ready", error="")
    except Exception as exc:  # shown to Liz on the entry page
        meta.update(status="error", error=str(exc))
    save(meta)


def start(code):
    threading.Thread(target=process, args=(code,), daemon=True).start()


# ---------- login ----------

def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if not session.get("user"):
            return redirect(url_for("login", next=request.path))
        return view(*args, **kwargs)
    return wrapped


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        user_ok = hmac.compare_digest(request.form.get("username", "").strip().lower(),
                                      os.environ["PORTAL_USERNAME"].lower())
        pass_ok = hmac.compare_digest(request.form.get("password", ""),
                                      os.environ["PORTAL_PASSWORD"])
        if user_ok and pass_ok:
            session.clear()
            session.permanent = True
            session["user"] = os.environ["PORTAL_USERNAME"]
            target = request.args.get("next", "")
            return redirect(target if target.startswith("/") else url_for("index"))
        time.sleep(1)  # slows down password guessing
        flash("That username and password don't match.")
    return render_template("login.html")


@app.route("/logout", methods=["POST"])
def logout():
    session.clear()
    return redirect(url_for("login"))


# ---------- pages ----------

@app.route("/")
@login_required
def index():
    return render_template("index.html", entries=all_entries())


@app.route("/entries", methods=["POST"])
@login_required
def create():
    uploads = [f for f in request.files.getlist("pdfs") if f.filename]
    if not uploads:
        flash("Please add at least one PDF.")
        return redirect(url_for("index"))
    if any(not f.filename.lower().endswith(".pdf") for f in uploads):
        flash("Only PDF files can be added.")
        return redirect(url_for("index"))

    with lock:
        code = next_code()
        base = DATA / code
        for sub in ("originals", "findings", "judges", "preview"):
            (base / sub).mkdir(parents=True)
    files = []
    for i, upload in enumerate(uploads, 1):
        stem = f"{code}-{i}"
        upload.save(base / "originals" / f"{stem}.pdf")
        files.append({"name": upload.filename, "stem": stem, "report": None})
    save({"code": code, "label": request.form.get("label", "").strip() or "Untitled",
          "names": lines(request.form.get("names", "")), "keep": [],
          "status": "processing", "error": "", "checked": False,
          "created": datetime.now().strftime("%d %b %Y %H:%M"), "files": files})
    start(code)
    return redirect(url_for("entry", code=code))


@app.route("/entries/<code>")
@login_required
def entry(code):
    return render_template("entry.html", e=load(code))


@app.route("/entries/<code>/update", methods=["POST"])
@login_required
def update(code):
    meta = load(code)
    meta["names"] = lines(request.form.get("names", ""))
    meta["keep"] = lines(request.form.get("keep", ""))
    meta["checked"] = False
    apply(meta)
    save(meta)
    flash("Changes applied. Please check the pages again.")
    return redirect(url_for("entry", code=code))


@app.route("/entries/<code>/rescan", methods=["POST"])
@login_required
def rescan(code):
    meta = load(code)
    for path in (entry_dir(code) / "findings").glob("*.json"):
        path.unlink()
    meta.update(status="processing", error="", checked=False)
    save(meta)
    start(code)
    return redirect(url_for("entry", code=code))


@app.route("/entries/<code>/checked", methods=["POST"])
@login_required
def mark_checked(code):
    meta = load(code)
    meta["checked"] = request.form.get("checked") == "1"
    save(meta)
    return redirect(url_for("entry", code=code))


@app.route("/entries/<code>/delete", methods=["POST"])
@login_required
def delete(code):
    shutil.rmtree(entry_dir(code))
    flash(f"{code} deleted.")
    return redirect(url_for("index"))


@app.route("/entries/<code>/page/<stem>/<int:number>/<which>.png")
@login_required
def page_image(code, stem, number, which):
    if which not in ("preview", "judges") or "/" in stem or ".." in stem:
        abort(404)
    path = entry_dir(code) / which / f"{stem}.pdf"
    if not path.exists():
        abort(404)
    with pymupdf.open(path) as doc:
        if not 1 <= number <= len(doc):
            abort(404)
        png = doc[number - 1].get_pixmap(dpi=110).tobytes("png")
    return send_file(io.BytesIO(png), mimetype="image/png")


# ---------- downloads ----------

def zip_judges(metas, filename):
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as z:
        for meta in metas:
            for f in meta["files"]:
                z.write(DATA / meta["code"] / "judges" / f"{f['stem']}.pdf",
                        f"{meta['code']}/{f['stem']}.pdf")
    buffer.seek(0)
    return send_file(buffer, mimetype="application/zip",
                     as_attachment=True, download_name=filename)


@app.route("/entries/<code>/download")
@login_required
def download_entry(code):
    meta = load(code)
    if meta["status"] != "ready":
        abort(404)
    return zip_judges([meta], f"{code}.zip")


@app.route("/download/judges.zip")
@login_required
def download_all():
    ready = [m for m in all_entries() if m["status"] == "ready" and m["checked"]]
    if not ready:
        flash("No entries are marked as checked yet.")
        return redirect(url_for("index"))
    return zip_judges(ready, f"{PREFIX}-judges.zip")


@app.route("/download/key.csv")
@login_required
def download_key():
    out = io.StringIO()
    writer = csv.writer(out)
    writer.writerow(["code", "entry", "original files", "added"])
    for m in all_entries():
        writer.writerow([m["code"], m["label"],
                         "; ".join(f["name"] for f in m["files"]), m["created"]])
    return send_file(io.BytesIO(out.getvalue().encode()), mimetype="text/csv",
                     as_attachment=True, download_name=f"{PREFIX}-key.csv")
