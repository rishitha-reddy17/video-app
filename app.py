import base64
import datetime as dt
import hashlib
import hmac
import json
import os
import secrets
import time
from dataclasses import dataclass
from typing import Any, Optional

import requests
from flask import (
    Flask,
    Response,
    abort,
    make_response,
    redirect,
    request,
    url_for,
)

APP_NAME = "Azure Cost Mini App"

# --- Login: one unique username/password (change these) ---
APP_USERNAME = os.getenv("APP_USERNAME", "admin")
APP_PASSWORD = os.getenv("APP_PASSWORD", "admin123")

# --- Flask cookie signing secret (change in production) ---
APP_SECRET = os.getenv("APP_SECRET", "change-me-to-a-long-random-secret")

# --- Azure app registration (Service Principal) credentials ---
# Create an App Registration + Client Secret in Entra ID (Azure AD), then set:
AZURE_TENANT_ID = os.getenv("AZURE_TENANT_ID", "")
AZURE_CLIENT_ID = os.getenv("AZURE_CLIENT_ID", "")
AZURE_CLIENT_SECRET = os.getenv("AZURE_CLIENT_SECRET", "")
AZURE_SUBSCRIPTION_ID = os.getenv("AZURE_SUBSCRIPTION_ID", "")

# Optional: if you want to query a Resource Group scope instead of subscription,
# set AZURE_SCOPE to:
#   /subscriptions/<subId>/resourceGroups/<rgName>
AZURE_SCOPE = os.getenv("AZURE_SCOPE", "")  # default uses subscription scope

# Time window for cost query
DEFAULT_DAYS = int(os.getenv("COST_LOOKBACK_DAYS", "30"))


app = Flask(__name__)


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("utf-8").rstrip("=")


def _b64url_decode(s: str) -> bytes:
    pad = "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode((s + pad).encode("utf-8"))


def _sign(data: bytes) -> str:
    mac = hmac.new(APP_SECRET.encode("utf-8"), data, hashlib.sha256).digest()
    return _b64url(mac)


def _make_session_cookie(payload: dict[str, Any], max_age_seconds: int = 8 * 60 * 60) -> str:
    issued_at = int(time.time())
    exp = issued_at + max_age_seconds
    body = {"iat": issued_at, "exp": exp, **payload}
    body_bytes = json.dumps(body, separators=(",", ":"), sort_keys=True).encode("utf-8")
    sig = _sign(body_bytes)
    return f"{_b64url(body_bytes)}.{sig}"


def _read_session_cookie(cookie_value: str) -> Optional[dict[str, Any]]:
    try:
        token, sig = cookie_value.split(".", 1)
        body_bytes = _b64url_decode(token)
        expected = _sign(body_bytes)
        if not hmac.compare_digest(sig, expected):
            return None
        body = json.loads(body_bytes.decode("utf-8"))
        if int(body.get("exp", 0)) < int(time.time()):
            return None
        return body
    except Exception:
        return None


def _is_logged_in() -> bool:
    cookie = request.cookies.get("session", "")
    session = _read_session_cookie(cookie) if cookie else None
    return bool(session and session.get("user") == APP_USERNAME)


def login_required() -> None:
    if not _is_logged_in():
        abort(401)


def _html_page(title: str, body: str, *, show_nav: bool = True) -> str:
    nav = ""
    if show_nav and _is_logged_in():
        nav = f"""
        <nav class="nav">
          <div class="brand">{APP_NAME}</div>
          <div class="links">
            <a href="{url_for("dashboard")}">Dashboard</a>
            <a href="{url_for("azure_status")}">Azure</a>
            <a href="{url_for("actual_cost")}">Actual</a>
            <a href="{url_for("amortized_cost")}">Amortized</a>
            <a class="danger" href="{url_for("logout")}">Logout</a>
          </div>
        </nav>
        """

    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>{title}</title>
  <style>
    :root {{
      --bg: #0b1220;
      --panel: rgba(255,255,255,0.06);
      --panel2: rgba(255,255,255,0.08);
      --text: #eaf0ff;
      --muted: rgba(234,240,255,0.70);
      --border: rgba(234,240,255,0.14);
      --accent: #6ea8ff;
      --good: #3ddc97;
      --warn: #ffcc66;
      --bad: #ff6b6b;
    }}
    * {{ box-sizing: border-box; }}
    body {{
      margin: 0;
      font-family: ui-sans-serif, system-ui, -apple-system, Segoe UI, Roboto, Arial, "Apple Color Emoji", "Segoe UI Emoji";
      background: radial-gradient(1200px 600px at 20% 10%, rgba(110,168,255,0.25), transparent 60%),
                  radial-gradient(900px 500px at 80% 30%, rgba(61,220,151,0.18), transparent 60%),
                  var(--bg);
      color: var(--text);
    }}
    a {{ color: inherit; text-decoration: none; }}
    .wrap {{ max-width: 980px; margin: 0 auto; padding: 28px 18px 40px; }}
    .nav {{
      position: sticky; top: 0;
      backdrop-filter: blur(10px);
      background: rgba(11,18,32,0.6);
      border-bottom: 1px solid var(--border);
      display: flex; align-items: center; justify-content: space-between;
      padding: 14px 18px;
      z-index: 5;
    }}
    .brand {{ font-weight: 700; letter-spacing: 0.3px; }}
    .links a {{
      display: inline-block;
      padding: 8px 10px;
      margin-left: 6px;
      border: 1px solid transparent;
      border-radius: 10px;
      color: var(--muted);
    }}
    .links a:hover {{ border-color: var(--border); color: var(--text); background: rgba(255,255,255,0.04); }}
    .links a.danger:hover {{ border-color: rgba(255,107,107,0.35); }}
    .card {{
      background: var(--panel);
      border: 1px solid var(--border);
      border-radius: 16px;
      padding: 18px;
      box-shadow: 0 14px 50px rgba(0,0,0,0.35);
    }}
    .row {{ display: grid; grid-template-columns: 1fr; gap: 14px; }}
    @media (min-width: 880px) {{
      .row.cols3 {{ grid-template-columns: repeat(3, 1fr); }}
      .row.cols2 {{ grid-template-columns: repeat(2, 1fr); }}
    }}
    .title {{
      font-size: 22px;
      font-weight: 750;
      margin: 6px 0 8px;
      letter-spacing: 0.2px;
    }}
    .subtitle {{ color: var(--muted); margin: 0 0 12px; line-height: 1.45; }}
    .kpi {{
      display: grid;
      grid-template-columns: 1fr 1fr;
      gap: 10px;
    }}
    .kpi > div {{
      background: var(--panel2);
      border: 1px solid var(--border);
      border-radius: 14px;
      padding: 12px;
    }}
    .label {{ color: var(--muted); font-size: 12px; }}
    .value {{ font-size: 18px; font-weight: 750; margin-top: 4px; }}
    .btn {{
      display: inline-flex;
      align-items: center;
      justify-content: center;
      gap: 10px;
      padding: 10px 12px;
      border-radius: 12px;
      border: 1px solid var(--border);
      background: rgba(110,168,255,0.12);
      color: var(--text);
      cursor: pointer;
      font-weight: 650;
    }}
    .btn:hover {{ background: rgba(110,168,255,0.18); }}
    .input {{
      width: 100%;
      padding: 12px 12px;
      border-radius: 12px;
      border: 1px solid var(--border);
      background: rgba(255,255,255,0.04);
      color: var(--text);
      outline: none;
    }}
    .input::placeholder {{ color: rgba(234,240,255,0.45); }}
    .formrow {{ display: grid; grid-template-columns: 1fr; gap: 12px; }}
    .hint {{ color: var(--muted); font-size: 12px; margin-top: 10px; line-height: 1.45; }}
    .pill {{
      display: inline-block;
      padding: 4px 10px;
      border-radius: 999px;
      border: 1px solid var(--border);
      color: var(--muted);
      font-size: 12px;
    }}
    .ok {{ color: var(--good); border-color: rgba(61,220,151,0.35); }}
    .warn {{ color: var(--warn); border-color: rgba(255,204,102,0.35); }}
    .bad {{ color: var(--bad); border-color: rgba(255,107,107,0.35); }}
    .gridicon {{
      width: 34px; height: 34px;
      border-radius: 12px;
      display: grid; place-items: center;
      background: rgba(255,255,255,0.06);
      border: 1px solid var(--border);
    }}
    .clickcard {{
      transition: transform 120ms ease, background 120ms ease;
    }}
    .clickcard:hover {{
      transform: translateY(-2px);
      background: rgba(255,255,255,0.08);
    }}
    .mono {{ font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, "Liberation Mono", monospace; }}
    pre {{
      overflow: auto;
      padding: 14px;
      border-radius: 14px;
      border: 1px solid var(--border);
      background: rgba(0,0,0,0.25);
      color: rgba(234,240,255,0.92);
      margin: 12px 0 0;
    }}
  </style>
</head>
<body>
  {nav}
  <div class="wrap">
    {body}
  </div>
</body>
</html>"""


def _login_page(error: str | None = None) -> str:
    err_html = ""
    if error:
        err_html = f'<div class="pill bad">Login failed: {error}</div>'
    return _html_page(
        "Login",
        f"""
        <div class="row">
          <div class="card">
            <div class="title">Login</div>
            <p class="subtitle">Sign in with your one configured username/password.</p>
            {err_html}
            <form method="post" action="{url_for("login")}">
              <div class="formrow" style="margin-top: 12px;">
                <input class="input" name="username" placeholder="Username" autocomplete="username" required />
                <input class="input" name="password" type="password" placeholder="Password" autocomplete="current-password" required />
                <button class="btn" type="submit">Sign in</button>
              </div>
            </form>
            <div class="hint">
              You can set credentials via env vars:
              <span class="mono">APP_USERNAME</span>, <span class="mono">APP_PASSWORD</span>.
            </div>
          </div>
        </div>
        """,
        show_nav=False,
    )


@app.get("/")
def index() -> Response:
    if _is_logged_in():
        return redirect(url_for("dashboard"))
    return redirect(url_for("login"))


@app.get("/login")
def login_get() -> str:
    return _login_page()


@app.post("/login")
def login() -> Response:
    username = (request.form.get("username") or "").strip()
    password = request.form.get("password") or ""

    # Constant-time comparison to reduce timing signals
    ok_user = hmac.compare_digest(username, APP_USERNAME)
    ok_pass = hmac.compare_digest(password, APP_PASSWORD)
    if not (ok_user and ok_pass):
        return make_response(_login_page("invalid credentials"), 401)

    cookie = _make_session_cookie({"user": APP_USERNAME})
    resp = redirect(url_for("dashboard"))
    resp.set_cookie("session", cookie, httponly=True, samesite="Lax", max_age=8 * 60 * 60)
    return resp


@app.get("/logout")
def logout() -> Response:
    resp = redirect(url_for("login"))
    resp.delete_cookie("session")
    return resp


def _icon(svg_path_d: str) -> str:
    return f"""
      <svg width="18" height="18" viewBox="0 0 24 24" fill="none" aria-hidden="true">
        <path d="{svg_path_d}" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/>
      </svg>
    """


@app.get("/dashboard")
def dashboard() -> str:
    login_required()
    sub = AZURE_SUBSCRIPTION_ID or "(not set)"
    scope = AZURE_SCOPE or f"/subscriptions/{sub}"

    return _html_page(
        "Dashboard",
        f"""
        <div class="row">
          <div class="card">
            <div class="title">Dashboard</div>
            <p class="subtitle">
              Choose a page. Each icon card is clickable and routes to that page.
            </p>
            <div class="kpi">
              <div>
                <div class="label">Azure scope</div>
                <div class="value mono" style="font-size: 13px; font-weight: 650;">{scope}</div>
              </div>
              <div>
                <div class="label">Lookback window</div>
                <div class="value">{DEFAULT_DAYS} days</div>
              </div>
            </div>
          </div>
          <div class="row cols3">
            <a class="card clickcard" href="{url_for("azure_status")}">
              <div style="display:flex; align-items:center; gap:12px;">
                <div class="gridicon">{_icon("M3 12h18M12 3v18")}</div>
                <div>
                  <div style="font-weight:750;">Azure connection</div>
                  <div class="subtitle" style="margin:6px 0 0;">Check credentials + token.</div>
                </div>
              </div>
            </a>
            <a class="card clickcard" href="{url_for("actual_cost")}">
              <div style="display:flex; align-items:center; gap:12px;">
                <div class="gridicon">{_icon("M12 2v20M5 7h14M7 21h10")}</div>
                <div>
                  <div style="font-weight:750;">Actual cost</div>
                  <div class="subtitle" style="margin:6px 0 0;">Pull actual cost from Azure.</div>
                </div>
              </div>
            </a>
            <a class="card clickcard" href="{url_for("amortized_cost")}">
              <div style="display:flex; align-items:center; gap:12px;">
                <div class="gridicon">{_icon("M4 19V5M4 19h16M8 15l3-3 3 2 4-6")}</div>
                <div>
                  <div style="font-weight:750;">Amortized cost</div>
                  <div class="subtitle" style="margin:6px 0 0;">Pull amortized cost from Azure.</div>
                </div>
              </div>
            </a>
          </div>
        </div>
        """,
    )


@dataclass(frozen=True)
class AzureToken:
    access_token: str
    expires_at: int


_TOKEN_CACHE: Optional[AzureToken] = None


def _azure_ready() -> tuple[bool, list[str]]:
    missing: list[str] = []
    if not AZURE_TENANT_ID:
        missing.append("AZURE_TENANT_ID")
    if not AZURE_CLIENT_ID:
        missing.append("AZURE_CLIENT_ID")
    if not AZURE_CLIENT_SECRET:
        missing.append("AZURE_CLIENT_SECRET")
    if not AZURE_SUBSCRIPTION_ID and not AZURE_SCOPE:
        missing.append("AZURE_SUBSCRIPTION_ID (or set AZURE_SCOPE)")
    return (len(missing) == 0), missing


def _get_azure_token() -> AzureToken:
    global _TOKEN_CACHE

    ok, missing = _azure_ready()
    if not ok:
        raise RuntimeError(f"Azure env vars missing: {', '.join(missing)}")

    now = int(time.time())
    if _TOKEN_CACHE and _TOKEN_CACHE.expires_at - 60 > now:
        return _TOKEN_CACHE

    token_url = f"https://login.microsoftonline.com/{AZURE_TENANT_ID}/oauth2/v2.0/token"
    data = {
        "client_id": AZURE_CLIENT_ID,
        "client_secret": AZURE_CLIENT_SECRET,
        "grant_type": "client_credentials",
        "scope": "https://management.azure.com/.default",
    }
    resp = requests.post(token_url, data=data, timeout=20)
    if resp.status_code != 200:
        raise RuntimeError(f"Token request failed: {resp.status_code} {resp.text}")
    payload = resp.json()
    access_token = payload["access_token"]
    expires_in = int(payload.get("expires_in", 3600))
    _TOKEN_CACHE = AzureToken(access_token=access_token, expires_at=now + expires_in)
    return _TOKEN_CACHE


def _cost_scope() -> str:
    if AZURE_SCOPE.strip():
        return AZURE_SCOPE.strip()
    return f"/subscriptions/{AZURE_SUBSCRIPTION_ID}"


def _date_range(days: int) -> tuple[str, str]:
    end = dt.date.today()
    start = end - dt.timedelta(days=days)
    return start.isoformat(), end.isoformat()


def _cost_query(cost_type: str, days: int) -> dict[str, Any]:
    start, end = _date_range(days)
    return {
        "type": "Usage",
        "timeframe": "Custom",
        "timePeriod": {"from": start, "to": end},
        "dataset": {
            "granularity": "None",
            "aggregation": {"totalCost": {"name": "Cost", "function": "Sum"}},
        },
        # The key switch:
        # - ActualCost: real billed usage cost (may be delayed)
        # - AmortizedCost: spreads upfront reservations/Savings Plans over time
        "costType": cost_type,
    }


def _query_cost(cost_type: str, days: int = DEFAULT_DAYS) -> dict[str, Any]:
    token = _get_azure_token()
    scope = _cost_scope()

    url = (
        f"https://management.azure.com{scope}"
        "/providers/Microsoft.CostManagement/query"
        "?api-version=2023-03-01"
    )
    headers = {
        "Authorization": f"Bearer {token.access_token}",
        "Content-Type": "application/json",
    }
    body = _cost_query(cost_type=cost_type, days=days)

    resp = requests.post(url, headers=headers, json=body, timeout=30)
    if resp.status_code >= 400:
        raise RuntimeError(f"Cost query failed: {resp.status_code} {resp.text}")
    return resp.json()


def _extract_total_cost(cost_query_response: dict[str, Any]) -> tuple[Optional[float], Optional[str]]:
    """
    Cost Management 'query' responses are shaped like:
      { properties: { columns: [...], rows: [[...]] } }
    We request one aggregation named 'totalCost', which usually appears in the first row.
    """
    try:
        props = cost_query_response["properties"]
        columns = props.get("columns", [])
        rows = props.get("rows", [])
        if not rows:
            return None, None

        # Find the 'totalCost' column index and currency, if present
        idx = None
        currency = None
        for i, col in enumerate(columns):
            if col.get("name") == "totalCost":
                idx = i
            if col.get("name") == "Currency":
                currency = None  # currency may be in rows; keep as best-effort
        if idx is None:
            # Often aggregation comes back as first numeric column
            idx = 0

        total = rows[0][idx]
        total_f = float(total) if total is not None else None
        return total_f, currency
    except Exception:
        return None, None


def _azure_status_badge() -> tuple[str, str]:
    ok, missing = _azure_ready()
    if not ok:
        return "NOT CONFIGURED", "bad"
    return "CONFIGURED", "ok"


@app.get("/azure")
def azure_status() -> str:
    login_required()
    status, klass = _azure_status_badge()

    token_preview = "—"
    token_error = None
    if klass == "ok":
        try:
            token = _get_azure_token()
            token_preview = token.access_token[:20] + "…" + token.access_token[-10:]
        except Exception as e:
            token_error = str(e)

    missing_text = ""
    ok, missing = _azure_ready()
    if not ok:
        missing_text = "<br/>Missing: " + ", ".join(f"<span class='mono'>{m}</span>" for m in missing)

    err_html = ""
    if token_error:
        err_html = f"<div class='pill bad' style='margin-top:10px;'>Token error: {token_error}</div>"

    return _html_page(
        "Azure",
        f"""
        <div class="row cols2">
          <div class="card">
            <div class="title">Azure connection</div>
            <p class="subtitle">
              This page validates your env vars and (if configured) fetches an access token.
            </p>
            <div class="pill {klass}">{status}{missing_text}</div>
            {err_html}
            <div class="hint" style="margin-top: 12px;">
              Scope used for cost queries: <span class="mono">{_cost_scope()}</span>
            </div>
          </div>
          <div class="card">
            <div class="title">Token preview</div>
            <p class="subtitle">If configured, we request a Management API token using client credentials.</p>
            <pre class="mono">{token_preview}</pre>
            <div class="hint">
              Required Azure role: at least <span class="mono">Cost Management Reader</span> on the subscription/scope.
            </div>
          </div>
        </div>
        """,
    )


def _cost_page(title: str, cost_type: str) -> str:
    login_required()
    status, klass = _azure_status_badge()
    days = DEFAULT_DAYS

    total = None
    err = None
    raw = None
    if klass == "ok":
        try:
            raw = _query_cost(cost_type=cost_type, days=days)
            total, _currency = _extract_total_cost(raw)
        except Exception as e:
            err = str(e)

    if klass != "ok":
        err = "Azure not configured. Visit Azure page and set env vars."

    if err:
        header = f"<div class='pill bad'>Error: {err}</div>"
    else:
        header = "<div class='pill ok'>Query succeeded</div>"

    total_str = "—" if total is None else f"{total:,.2f}"
    raw_str = "—" if raw is None else json.dumps(raw, indent=2)[:12000]

    return _html_page(
        title,
        f"""
        <div class="row cols2">
          <div class="card">
            <div class="title">{title}</div>
            <p class="subtitle">
              Pulls {cost_type} from Azure Cost Management for the last {days} days.
            </p>
            {header}
            <div class="kpi" style="margin-top: 12px;">
              <div>
                <div class="label">Total (sum of Cost)</div>
                <div class="value">{total_str}</div>
              </div>
              <div>
                <div class="label">Scope</div>
                <div class="value mono" style="font-size: 13px; font-weight: 650;">{_cost_scope()}</div>
              </div>
            </div>
            <div class="hint">
              Note: currency and exact totals depend on billing setup and availability in Cost Management.
            </div>
          </div>
          <div class="card">
            <div class="title">Raw response (truncated)</div>
            <p class="subtitle">Useful for debugging columns/rows.</p>
            <pre class="mono">{raw_str}</pre>
          </div>
        </div>
        """,
    )


@app.get("/cost/actual")
def actual_cost() -> str:
    return _cost_page("Actual cost", "ActualCost")


@app.get("/cost/amortized")
def amortized_cost() -> str:
    return _cost_page("Amortized cost", "AmortizedCost")


@app.errorhandler(401)
def unauthorized(_e: Exception) -> Response:
    return redirect(url_for("login"))


@app.errorhandler(404)
def not_found(_e: Exception) -> tuple[str, int]:
    return _html_page("Not found", "<div class='card'><div class='title'>404</div><p class='subtitle'>Page not found.</p></div>"), 404


def _print_startup_help() -> None:
    ok, missing = _azure_ready()
    print(f"{APP_NAME} starting on http://127.0.0.1:5000")
    print(f"Login: username={APP_USERNAME!r} password={'*' * len(APP_PASSWORD)}")
    if not ok:
        print("Azure is not configured yet. Missing:")
        for m in missing:
            print(f"  - {m}")
    else:
        print("Azure env vars look configured. Visit /azure to validate token.")


if __name__ == "__main__":
    _print_startup_help()
    app.run(host="127.0.0.1", port=5000, debug=True)
