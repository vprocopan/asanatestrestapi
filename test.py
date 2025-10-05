import os
import time
import datetime as dt
from typing import Dict, List, Optional

import asana  # new SDK with Configuration, ApiClient, and *Api classes

ASANA_ACCESS_TOKEN = os.getenv("ASANA_ACCESS_TOKEN")          # PAT or OAuth bearer
ASANA_AUDIT_SVC_TOKEN = os.getenv("ASANA_AUDIT_SVC_TOKEN")    # Service Account PAT (Enterprise) for Audit Log API, optional
DAYS_INACTIVE = int(os.getenv("ASANA_DAYS_INACTIVE", "365"))  # override if needed

RATE_LIMIT_SLEEP_BASE = 2.0  # seconds
MAX_RETRIES = 5

def make_api_client(token: str) -> asana.ApiClient:
    cfg = asana.Configuration()
    cfg.access_token = token
    # Optional: tweak retries via urllib3 Retry in advanced setups; default SDK retries exist
    api_client = asana.ApiClient(cfg)
    return api_client

def backoff_retry(callable_fn, *args, **kwargs):
    delay = RATE_LIMIT_SLEEP_BASE
    for attempt in range(MAX_RETRIES):
        try:
            return callable_fn(*args, **kwargs)
        except asana.rest.ApiException as e:
            # Handle rate limit 429 with Retry-After if present
            status = getattr(e, "status", None)
            headers = getattr(e, "headers", {}) or {}
            if status == 429:
                retry_after = headers.get("Retry-After")
                sleep_for = float(retry_after) if retry_after else delay
                time.sleep(sleep_for)
                delay *= 2
                continue
            raise
    raise RuntimeError("Exceeded retries due to rate limits")

def list_all_workspaces(api_client: asana.ApiClient) -> List[Dict]:
    workspaces_api = asana.WorkspacesApi(api_client)
    # GET /workspaces; returns a generator-like iterable; materialize to list of dicts
    # The SDK v5 methods accept an opts dict for query params like opt_fields
    resp = backoff_retry(workspaces_api.get_workspaces, {})
    return list(resp)
    # v5 Python usage for per-resource APIs and opts dict is documented in the SDK and developer quick start [web:74][web:71]

def list_workspace_users(api_client: asana.ApiClient, workspace_gid: str) -> List[Dict]:
    users_api = asana.UsersApi(api_client)
    opts = {
        "opt_fields": "gid,name,email,is_active,is_guest"
    }
    resp = backoff_retry(users_api.get_users_for_workspace, workspace_gid, opts)
    return list(resp)
    # UsersApi.get_users_for_workspace with opt_fields surfaces is_guest/is_active for guest detection [web:70][web:74]

def list_workspace_projects(api_client: asana.ApiClient, workspace_gid: str) -> List[Dict]:
    projects_api = asana.ProjectsApi(api_client)
    opts = {
        "archived": False,
        "opt_fields": "gid,name,archived,modified_at,owner"
    }
    resp = backoff_retry(projects_api.get_projects_for_workspace, workspace_gid, opts)
    return list(resp)
    # ProjectsApi.get_projects_for_workspace with archived filter and modified_at for inactivity checks [web:75][web:74]

def parse_iso8601(ts: str) -> dt.datetime:
    return dt.datetime.fromisoformat(ts.replace("Z", "+00:00"))

def find_inactive_projects(projects: List[Dict], days: int) -> List[Dict]:
    cutoff = dt.datetime.now(dt.timezone.utc) - dt.timedelta(days=days)
    inactive = []
    for p in projects:
        mod = p.get("modified_at")
        if not mod:
            inactive.append({**p, "reason": "missing_modified_at"})
            continue
        try:
            mod_dt = parse_iso8601(mod)
        except Exception:
            inactive.append({**p, "reason": "invalid_modified_at"})
            continue
        if mod_dt < cutoff:
            inactive.append({**p, "reason": f"older_than_{days}d"})
    return inactive
    # Known nuances around modified_at timing; apply a clear cutoff [web:74]

def detect_active_guests(users: List[Dict]) -> List[Dict]:
    guests = []
    for u in users:
        if u.get("is_active") and u.get("is_guest"):
            guests.append(u)
    return guests
    # External users are those with is_guest true and currently active [web:70][web:74]

def list_org_admins_via_auditlog(audit_api_client: asana.ApiClient, domain_gid: str) -> Optional[List[str]]:
    """
    Uses Audit Log API to derive current admins by scanning admin-role grant/revoke.
    Enterprise-only; authenticate with a Service Account token.
    """
    # The v5 SDK may not yet expose a dedicated AuditLogApi class; use low-level call_api
    # Endpoint: GET /domains/{domain_gid}/audit_log_events
    now = dt.datetime.now(dt.timezone.utc)
    start_time = (now - dt.timedelta(days=365)).isoformat()

    admins = set()
    next_page = None

    while True:
        query_params = [
            ("start_at", start_time),
            ("event_types", "user_admin_role_granted,user_admin_role_revoked"),
        ]
        if next_page:
            query_params.append(("offset", next_page))

        # call_api(method, path, path_params, query_params, header_params, body, post_params, files, response_type, auth_settings, async_req, _return_http_data_only, _preload_content, _request_timeout, collection_formats)
        try:
            resp = backoff_retry(
                audit_api_client.call_api,
                "/domains/{domain_gid}/audit_log_events",
                "GET",
                path_params={"domain_gid": domain_gid},
                query_params=query_params,
                header_params={},
                body=None,
                post_params=[],
                files={},
                response_type="object",
                auth_settings=["oauth2"],
                async_req=False,
                _return_http_data_only=True,
                _preload_content=True,
                _request_timeout=60,
                collection_formats={},
            )
        except asana.rest.ApiException as e:
            # If unauthorized or feature not available, return None to trigger fallback
            return None

        data = (resp or {}).get("data", [])
        for ev in data:
            et = ev.get("event_type")
            actor = ev.get("actor", {})
            subject = ev.get("resource", {})
            user_gid = subject.get("gid") or actor.get("gid")
            if not user_gid:
                continue
            if et == "user_admin_role_granted":
                admins.add(user_gid)
            elif et == "user_admin_role_revoked":
                admins.discard(user_gid)

        next_page = ((resp or {}).get("next_page") or {}).get("offset")
        if not next_page:
            break

    return list(admins)
    # Audit Log API reference and events list; Enterprise + Service Account required [web:43][web:41]

def run_security_checks():
    primary_client = make_api_client(ASANA_ACCESS_TOKEN)
    audit_client = make_api_client(ASANA_AUDIT_SVC_TOKEN) if ASANA_AUDIT_SVC_TOKEN else None

    results = []

    workspaces = list_all_workspaces(primary_client)

    for ws in workspaces:
        ws_gid = ws["gid"]
        ws_name = ws.get("name", "")

        users = list_workspace_users(primary_client, ws_gid)
        projects = list_workspace_projects(primary_client, ws_gid)

        active_guests = detect_active_guests(users)
        inactive_projects = find_inactive_projects(projects, DAYS_INACTIVE)

        admin_user_gids = None
        if audit_client:
            # For audit API, the domain id is the org workspace gid for enterprise organizations
            admin_user_gids = list_org_admins_via_auditlog(audit_client, ws_gid)

        if not admin_user_gids:
            # Fallback heuristic if Audit Log is unavailable: active non-guests as proxy for admins
            admin_user_gids = [u["gid"] for u in users if u.get("is_active") and not u.get("is_guest")]

        too_many_admins = len(admin_user_gids) > 4

        results.append({
            "workspace_gid": ws_gid,
            "workspace_name": ws_name,
            "admins_count": len(admin_user_gids),
            "admins_exceeded": too_many_admins,
            "admin_user_gids": admin_user_gids,
            "inactive_projects_count": len(inactive_projects),
            "inactive_projects": [
                {"gid": p["gid"], "name": p.get("name"), "modified_at": p.get("modified_at"), "reason": p.get("reason")}
                for p in inactive_projects
            ],
            "active_external_users_count": len(active_guests),
            "active_external_users": [
                {"gid": u["gid"], "name": u.get("name"), "email": u.get("email")}
                for u in active_guests
            ],
        })

    return results

if __name__ == "__main__":
    if not ASANA_ACCESS_TOKEN:
        raise SystemExit("Set ASANA_ACCESS_TOKEN environment variable")
    report = run_security_checks()
    import json
    print(json.dumps(report, indent=2))
