import os
import sqlite3
import subprocess
import zipstream
from datetime import datetime
from pathlib import Path
from typing import Optional
from fastapi.responses import FileResponse, StreamingResponse, JSONResponse
from fastapi import FastAPI, Request, Form
from fastapi.responses import HTMLResponse, RedirectResponse, PlainTextResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

APP_DATA = Path("/data")
DB_PATH = APP_DATA / "le_manager.sqlite"
CHALLENGE_WEBROOT = Path("/var/www/acme-challenges")

DEFAULT_EMAIL = os.getenv("LE_DEFAULT_EMAIL", "admin@example.com")
DEFAULT_STAGING = os.getenv("LE_DEFAULT_STAGING", "1") == "1"
CRON_TOKEN = os.getenv("CRON_TOKEN", "")

app = FastAPI(title="LE Manager")
templates = Jinja2Templates(directory="/app/templates")

# -------- DB --------
def db():
    APP_DATA.mkdir(parents=True, exist_ok=True)
    con = sqlite3.connect(DB_PATH)
    con.row_factory = sqlite3.Row
    return con

def init_db():
    con = db()
    cur = con.cursor()
    cur.execute("""
    CREATE TABLE IF NOT EXISTS accounts (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT NOT NULL,
      email TEXT NOT NULL,
      staging INTEGER NOT NULL DEFAULT 1,
      created_at TEXT NOT NULL
    )""")
    cur.execute("""
    CREATE TABLE IF NOT EXISTS jobs (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      kind TEXT NOT NULL,
      status TEXT NOT NULL,
      created_at TEXT NOT NULL,
      finished_at TEXT,
      account_id INTEGER,
      domains TEXT,
      stdout TEXT,
      stderr TEXT
    )""")
    con.commit()
    con.close()

@app.on_event("startup")
def _startup():
    init_db()
    # crea dir challenge (deve esistere)
    CHALLENGE_WEBROOT.mkdir(parents=True, exist_ok=True)

# -------- Helpers --------
def account_dirs(account_id: int):
    base = APP_DATA / "accounts" / str(account_id)
    return {
        "config": base / "config",
        "work": base / "work",
        "logs": base / "logs",
    }

def run_certbot(args: list[str], timeout=900):
    p = subprocess.run(args, capture_output=True, text=True, timeout=timeout)
    return p.returncode, p.stdout, p.stderr

def list_live_certs():
    """
    Scansiona i certificati emessi per ogni account:
    /data/accounts/<id>/config/live/<certname>/
    """
    out = []
    accounts_root = APP_DATA / "accounts"
    if not accounts_root.exists():
        return out

    for acc_dir in sorted(accounts_root.iterdir()):
        if not acc_dir.is_dir():
            continue
        acc_id = acc_dir.name
        live = acc_dir / "config" / "live"
        if not live.exists():
            continue

        for d in sorted(live.iterdir()):
            if not d.is_dir():
                continue

            fullchain = d / "fullchain.pem"
            privkey = d / "privkey.pem"
            cert = d / "cert.pem"
            if not fullchain.exists() or not privkey.exists() or not cert.exists():
                continue

            expires_str = None
            days_left = None
            try:
                p = subprocess.run(
                    ["openssl", "x509", "-in", str(cert), "-noout", "-enddate"],
                    capture_output=True, text=True, timeout=5
                )
                if p.returncode == 0 and "notAfter=" in p.stdout:
                    expires_str = p.stdout.strip().split("notAfter=", 1)[1].strip()
                    dt = datetime.strptime(expires_str, "%b %d %H:%M:%S %Y %Z")
                    days_left = (dt - datetime.utcnow()).days
            except Exception:
                pass

            out.append({
                "name": d.name,
                "account_id": acc_id,
                "path": str(d),
                "expires": expires_str,
                "days_left": days_left,
            })

    return out



# -------- Views --------
@app.get("/health")
def health():
    return {"ok": True}

@app.get("/", response_class=HTMLResponse)
def home(request: Request):
    con = db()
    accounts = con.execute("SELECT * FROM accounts ORDER BY id DESC").fetchall()
    jobs = con.execute("SELECT * FROM jobs ORDER BY id DESC LIMIT 20").fetchall()
    con.close()
    certs = list_live_certs()
    return templates.TemplateResponse("home.html", {
        "request": request,
        "accounts": accounts,
        "jobs": jobs,
        "certs": certs,
    })

@app.post("/accounts/create")
def accounts_create(
    name: str = Form(...),
    email: str = Form(...),
    staging: int = Form(1),
):
    con = db()
    cur = con.cursor()
    cur.execute(
        "INSERT INTO accounts(name,email,staging,created_at) VALUES(?,?,?,?)",
        (name, email, int(staging), datetime.utcnow().isoformat())
    )
    account_id = cur.lastrowid
    con.commit()
    con.close()

    # crea dir account
    dirs = account_dirs(account_id)
    for p in dirs.values():
        p.mkdir(parents=True, exist_ok=True)

    return RedirectResponse("/", status_code=303)

@app.post("/certs/issue_http")
def certs_issue_http(
    account_id: int = Form(...),
    domains: str = Form(...),  # comma o spazio
):
    doms = [d.strip() for d in domains.replace(",", " ").split() if d.strip()]
    if not doms:
        return RedirectResponse("/", status_code=303)

    con = db()
    acc = con.execute("SELECT * FROM accounts WHERE id=?", (account_id,)).fetchone()
    if not acc:
        con.close()
        return RedirectResponse("/", status_code=303)

    # job record
    cur = con.cursor()
    cur.execute(
        "INSERT INTO jobs(kind,status,created_at,account_id,domains) VALUES(?,?,?,?,?)",
        ("issue_http", "running", datetime.utcnow().isoformat(), account_id, " ".join(doms))
    )
    job_id = cur.lastrowid
    con.commit()

    dirs = account_dirs(account_id)
    for p in dirs.values():
        p.mkdir(parents=True, exist_ok=True)

    cmd = [
        "certbot", "certonly",
        "--non-interactive", "--agree-tos", "--no-eff-email",
        "--email", acc["email"],
        "--webroot", "-w", str(CHALLENGE_WEBROOT),
        "--config-dir", str(dirs["config"]),
        "--work-dir", str(dirs["work"]),
        "--logs-dir", str(dirs["logs"]),
    ]
    if int(acc["staging"]) == 1:
        cmd += ["--staging"]
    for d in doms:
        cmd += ["-d", d]

    try:
        rc, out, err = run_certbot(cmd, timeout=1200)
        status = "ok" if rc == 0 else "failed"
    except Exception as e:
        rc, out, err = 1, "", f"Exception: {e}"
        status = "failed"

    con.execute(
        "UPDATE jobs SET status=?, finished_at=?, stdout=?, stderr=? WHERE id=?",
        (status, datetime.utcnow().isoformat(), out, err, job_id)
    )
    con.commit()
    con.close()

    return RedirectResponse("/", status_code=303)

@app.post("/certs/renew_all")
def certs_renew_all():
    con = db()
    cur = con.cursor()
    cur.execute(
        "INSERT INTO jobs(kind,status,created_at) VALUES(?,?,?)",
        ("renew_all", "running", datetime.utcnow().isoformat())
    )
    job_id = cur.lastrowid
    con.commit()

    cmd = ["certbot", "renew", "--webroot", "-w", str(CHALLENGE_WEBROOT)]
    try:
        rc, out, err = run_certbot(cmd, timeout=1200)
        status = "ok" if rc == 0 else "failed"
    except Exception as e:
        rc, out, err = 1, "", f"Exception: {e}"
        status = "failed"

    con.execute(
        "UPDATE jobs SET status=?, finished_at=?, stdout=?, stderr=? WHERE id=?",
        (status, datetime.utcnow().isoformat(), out, err, job_id)
    )
    con.commit()
    con.close()
    return RedirectResponse("/", status_code=303)

@app.get("/jobs/{job_id}", response_class=HTMLResponse)
def job_detail(request: Request, job_id: int):
    con = db()
    job = con.execute("SELECT * FROM jobs WHERE id=?", (job_id,)).fetchone()
    con.close()
    if not job:
        return RedirectResponse("/", status_code=303)
    return templates.TemplateResponse("job.html", {"request": request, "job": job})

@app.get("/export/{account_id}/{name}/{which}")
def export_file(account_id: str, name: str, which: str):
    base = APP_DATA / "accounts" / str(account_id) / "config" / "live" / name
    mapping = {
        "fullchain": base / "fullchain.pem",
        "privkey": base / "privkey.pem",
        "cert": base / "cert.pem",
        "chain": base / "chain.pem",
    }
    p = mapping.get(which)
    if not p or not p.exists():
        return PlainTextResponse("not found", status_code=404)

    return FileResponse(
        path=str(p),
        media_type="application/x-pem-file",
        filename=f"{name}-{which}.pem",
    )

@app.get("/export/{account_id}/{name}/bundle.zip")
def export_bundle_zip(account_id: str, name: str):
    base = APP_DATA / "accounts" / str(account_id) / "config" / "live" / name
    files = {
        "fullchain.pem": base / "fullchain.pem",
        "privkey.pem": base / "privkey.pem",
        "cert.pem": base / "cert.pem",
        "chain.pem": base / "chain.pem",
    }
    for k, p in files.items():
        if not p.exists():
            return PlainTextResponse(f"missing {k}", status_code=404)

    z = zipstream.ZipStream(compress_type=zipstream.ZIP_DEFLATED)
    for arcname, p in files.items():
        z.add(str(p), arcname=arcname)

    return StreamingResponse(
        z,
        media_type="application/zip",
        headers={"Content-Disposition": f'attachment; filename="{name}-bundle.zip"'},
    )


@app.get("/export/{account_id}/{name}/combined.pem")
def export_combined_pem(account_id: str, name: str):
    base = APP_DATA / "accounts" / str(account_id) / "config" / "live" / name
    fullchain = base / "fullchain.pem"
    privkey = base / "privkey.pem"
    if not fullchain.exists() or not privkey.exists():
        return PlainTextResponse("not found", status_code=404)

    combined = fullchain.read_text() + "\n" + privkey.read_text()
    headers = {"Content-Disposition": f'attachment; filename="{name}-combined.pem"'}
    return PlainTextResponse(combined, headers=headers, media_type="application/x-pem-file")


@app.post("/certs/renew_one")
def certs_renew_one(name: str = Form(...)):
    con = db()
    cur = con.cursor()
    cur.execute(
        "INSERT INTO jobs(kind,status,created_at,domains) VALUES(?,?,?,?)",
        ("renew_one", "running", datetime.utcnow().isoformat(), name)
    )
    job_id = cur.lastrowid
    con.commit()

    cmd = ["certbot", "renew", "--cert-name", name, "--webroot", "-w", str(CHALLENGE_WEBROOT)]
    try:
        rc, out, err = run_certbot(cmd, timeout=1200)
        status = "ok" if rc == 0 else "failed"
    except Exception as e:
        out, err = "", f"Exception: {e}"
        status = "failed"

    con.execute(
        "UPDATE jobs SET status=?, finished_at=?, stdout=?, stderr=? WHERE id=?",
        (status, datetime.utcnow().isoformat(), out, err, job_id)
    )
    con.commit()
    con.close()
    return RedirectResponse("/", status_code=303)

@app.get("/api/cron/renew")
def api_cron_renew(token: str = ""):
    if not CRON_TOKEN or token != CRON_TOKEN:
        return JSONResponse({"ok": False, "error": "unauthorized"}, status_code=401)

    con = db()
    cur = con.cursor()
    cur.execute(
        "INSERT INTO jobs(kind,status,created_at) VALUES(?,?,?)",
        ("cron_renew_all", "running", datetime.utcnow().isoformat())
    )
    job_id = cur.lastrowid
    con.commit()

    cmd = ["certbot", "renew", "--webroot", "-w", str(CHALLENGE_WEBROOT)]
    try:
        rc, out, err = run_certbot(cmd, timeout=1200)
        status = "ok" if rc == 0 else "failed"
    except Exception as e:
        out, err = "", f"Exception: {e}"
        status = "failed"

    con.execute(
        "UPDATE jobs SET status=?, finished_at=?, stdout=?, stderr=? WHERE id=?",
        (status, datetime.utcnow().isoformat(), out, err, job_id)
    )
    con.commit()
    con.close()

    return {"ok": True, "job_id": job_id, "status": status}
