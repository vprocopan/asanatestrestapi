<img src="https://r2cdn.perplexity.ai/pplx-full-logo-primary-dark%402x.png" style="height:64px;margin-right:32px"/>

# [https://developers.asana.com/reference/rest-api-reference](https://developers.asana.com/reference/rest-api-reference)

Here’s the Asana REST API reference requested, plus key highlights to get started and avoid common pitfalls.[^1_1]

### What it covers

- The reference documents all REST endpoints, request/response shapes, error codes, and usage notes for Asana’s JSON-based API, along with an in-page API Explorer for trying calls interactively.[^1_2][^1_1]


### Quick start

- The API uses predictable resource URLs and JSON; the Docs site includes a guided quick start and an embedded API Explorer to test endpoints without leaving the page.[^1_3][^1_1]


### Core endpoints

- Common sections include Tasks, Projects, Sections, Stories (comments), Users, Teams, Workspaces, Webhooks, and Search (e.g., Search tasks in a workspace) with example requests and query parameters in each page.[^1_4][^1_5][^1_6][^1_1]


### Auth options

- Use Personal Access Tokens or OAuth 2.0; the Docs and Developer Portal guide both flows, and the API Explorer can operate against a signed-in session for quick testing.[^1_7][^1_1]


### OAuth scopes update

- Asana is rolling out granular OAuth permission scopes (e.g., tasks:read, projects:write) with developer preview available now and GA targeted for July 2025; apps must pass space-separated scopes in the authorization request and users may need to re-authorize when scopes change.[^1_8][^1_9]


### Rate limits

- Asana enforces per-token limits, including requests per minute and concurrent/cost-based limiters; premium orgs commonly see 1500 req/min in docs, but forum reports vary and emphasize handling 429s robustly.[^1_10][^1_11][^1_12][^1_13]


### Troubleshooting examples

- Some preview-scope tokens can hit “missing scope” on certain endpoints (e.g., creating stories/comments) while equivalent PATs succeed; verify required scopes and monitor forum updates as scopes stabilize.[^1_14][^1_9]


### Developer resources

- The Asana Developers hub links docs, API explorer, community forum, and product/program updates, including App Components and the Audit Log API for security visibility.[^1_15][^1_1][^1_7]
<span style="display:none">[^1_16][^1_17][^1_18][^1_19][^1_20]</span>

<div align="center">⁂</div>

[^1_1]: https://developers.asana.com/reference/rest-api-reference

[^1_2]: https://developers.asana.com/docs/api-explorer

[^1_3]: https://developers.asana.com/docs/quick-start

[^1_4]: https://developers.asana.com/reference/getproject

[^1_5]: https://developers.asana.com/reference/searchtasksforworkspace

[^1_6]: https://developers.asana.com/reference/projects

[^1_7]: https://developers.asana.com

[^1_8]: https://forum.asana.com/t/new-oauth-permission-scopes/1048556

[^1_9]: https://developers.asana.com/docs/oauth-scopes

[^1_10]: https://developers.asana.com/docs/rate-limits

[^1_11]: https://forum.asana.com/t/changes-in-api-rate-limits/910616

[^1_12]: https://forum.asana.com/t/rate-limit-enforced/67775

[^1_13]: https://forum.asana.com/t/rate-limit/326522

[^1_14]: https://forum.asana.com/t/oauth-token-with-tasks-write-scope-fails-to-create-stories-comments-works-with-pat/1068353

[^1_15]: https://asana.com/developers

[^1_16]: https://docs.useparagon.com/resources/integrations/asana

[^1_17]: https://cloud.google.com/integration-connectors/docs/connectors/asana/configure

[^1_18]: https://help.asana.com/s/article/api?language=en_US

[^1_19]: https://forum.asana.com/t/handling-rate-limit-with-api-calls/107611

[^1_20]: https://forum.asana.com/t/asana-backup-pat/1054460


---

# how to identify workspace GID in asana

The easiest way to identify a workspace GID in Asana is to call the Workspaces API and read the gid field from the response, which lists all accessible workspaces for the authenticated user. Alternatively, a single workspace can be fetched directly when the gid is already known using the Get a workspace endpoint to confirm details like name and is_organization.[^2_1][^2_2][^2_3]

### Using the API

- List all workspaces the token can access with GET https://app.asana.com/api/1.0/workspaces and read each item’s gid from the data array, which is the canonical identifier to use with other endpoints.[^2_2][^2_3]
- Retrieve one workspace by gid with GET /workspaces/{workspace_gid} to verify attributes such as the workspace name and whether it is an organization via is_organization.[^2_1][^2_2]
- Official client libraries and tools (e.g., Postman collections) expose getWorkspaces and related calls that return gid alongside name to make selection easier during setup.[^2_4][^2_5]


### From the browser session

- While signed in, visiting https://app.asana.com/api/1.0/workspaces in a browser will return JSON including the gid values for accessible workspaces, leveraging the existing session for quick discovery without a separate token step.[^2_6][^2_7]
- Some UI URLs include IDs, but forum guidance indicates only the Admin Console URL reliably surfaces the workspace ID in the UI, and developers should prefer API responses for accurate gids used by endpoints.[^2_8][^2_9]


### Tips and caveats

- Use the gid returned by API responses for subsequent endpoints, since IDs seen in various UI locations can be inconsistent and are not guaranteed to be accepted by REST endpoints if they don’t match the API’s gid values.[^2_9][^2_8]
- If starting from another object (task, project, or user task list), fetch that object and read its workspace.gid field to discover the containing workspace without a separate list call.[^2_4][^2_2]


### Related docs

- Quick start instructions explicitly direct developers to obtain the workspace GID first, since it is required for many workspace-scoped endpoints in typical integrations.[^2_3][^2_2]
- The Workspaces reference details the schema and properties returned when getting or listing workspaces, including gid, name, email_domains, and is_organization for environment verification.[^2_2][^2_1]
<span style="display:none">[^2_10][^2_11][^2_12][^2_13][^2_14][^2_15][^2_16][^2_17][^2_18][^2_19][^2_20]</span>

<div align="center">⁂</div>

[^2_1]: https://developers.asana.com/reference/getworkspace

[^2_2]: https://developers.asana.com/reference/workspaces

[^2_3]: https://developers.asana.com/docs/quick-start

[^2_4]: https://github.com/Asana/node-asana

[^2_5]: https://www.postman.com/api-evangelist/asana/documentation/01wkj96/asana

[^2_6]: https://stackoverflow.com/questions/26585518/how-to-get-asana-workspaceid

[^2_7]: https://forum.asana.com/t/workspace-id-and-ms-power-automation/88564

[^2_8]: https://forum.asana.com/t/how-to-get-workspace-id-from-asana-ui/65514

[^2_9]: https://forum.asana.com/t/how-to-get-workspace-id-from-asana-ui/65514/2

[^2_10]: https://developers.asana.com/docs/faq

[^2_11]: https://forum.asana.com/t/mcp-are-there-ways-to-pass-in-the-workspace-gid-via-config-args/1079761

[^2_12]: https://c32jre4vsi.apidog.io/api-3547358

[^2_13]: https://www.youtube.com/watch?v=xwivLn3B8NA

[^2_14]: https://forum.asana.com/t/trying-to-pull-a-specific-user-gid/808502

[^2_15]: https://forum.asana.com/t/search-tasks-in-a-workspace/187685

[^2_16]: https://www.youtube.com/watch?v=B-Mev70XXhg

[^2_17]: https://forum.asana.com/t/inconsistence-between-endpoints/162696

[^2_18]: https://forum.asana.com/t/private-user-in-workspaces-workspaceid-users-endpoint/34988

[^2_19]: https://www.postman.com/api-evangelist/asana/request/f6lmo25/get-workspace-users

[^2_20]: https://forum.asana.com/t/finding-things-by-name/53394


---

# [https://developers.asana.com/reference/rest-api-reference](https://developers.asana.com/reference/rest-api-reference)

Security Checks

1. Asana — No more than 4 Admins Configured
Detect when more than 4 users have administrative privileges in the
workspace/organization.
2. Asana — No Inactive Projects Present
Detect Asana projects that have not been modified in over 365 days and are still
not archived.
3. Asana — No Active External Users
Detect active external (guest) users

The three checks can be implemented with Asana’s REST API and, for admin counts, optionally the Audit Log API; below are precise endpoints, fields, and filters to use for each control with example logic and caveats.[^3_1][^3_2]

### 1) No more than 4 admins

- Preferred approach in Enterprise: query the Audit Log API for admin-role assignment events and maintain a current set of organization admins, or enumerate members and filter by admin flags where available in admin-capable endpoints and exports.[^3_2][^3_1]
- Service Accounts can access organization-wide data for this purpose; they are authenticated for Audit Log API access and help avoid per-user visibility gaps when counting admins across all teams and divisions.[^3_3][^3_2]
- Practical detection: pull the organization’s members and identify users with admin privileges, then alert if count > 4; ensure the definition aligns with Org Admin/Super Admin in Admin Console, not project or team admins, which differ from org-level admin roles.[^3_4][^3_5]


### 2) No inactive projects present

- List projects in the workspace with archived=false and inspect the project’s modified_at to find those not updated in > 365 days, then flag any non-archived projects exceeding that threshold for review or auto-archival workflow.[^3_6][^3_7]
- Caveat: modified_at reflects “significant” changes and may update asynchronously; forum reports note inconsistent refresh timing, so consider corroborating with recent activity via stories or using broader windows to reduce false positives.[^3_8][^3_6]
- If needing an archive timestamp, Asana does not expose the specific archived date in the API; only the archived boolean is available, so retain this timestamp in external systems if required for compliance evidence.[^3_9][^3_10]


### 3) No active external users

- Enumerate users for the workspace/organization and filter where is_guest=true and is_active=true to detect active external (guest) accounts for remediation or validation workflows.[^3_11][^3_10]
- Expect discrepancies between Admin Console and API fields in some tenants; forum posts note cases where is_guest and is_active don’t perfectly mirror the UI, so validate via multiple signals or cross-check using audit events like user_invited/deprovisioned and recent user_login_succeeded where available.[^3_12][^3_13]
- For reliable coverage, run with a Service Account in Enterprise to ensure full visibility across the domain and avoid missing guests who are not visible to standard user tokens across all workspaces.[^3_2][^3_3]


### Endpoint details and patterns

- Workspaces and scoping: obtain workspace GIDs before listing projects or users; most list endpoints are scoped by workspace and return gid, name, and key flags like archived or is_guest.[^3_10][^3_14]
- Projects: list by workspace, filter archived=false, and read modified_at; apply a date cutoff of now-365d to identify inactive-but-unarchived projects for alerting or auto-archive policy.[^3_7][^3_10]
- Users: list users in a workspace or domain, then evaluate fields such as is_guest and is_active to determine active external users; use enrichment calls per user if needed.[^3_11][^3_10]


### Recommended implementation flow

- Authentication: use OAuth scopes or a PAT, but for domain-wide controls and audit events, prefer a Service Account in Enterprise to provide comprehensive coverage across the organization.[^3_3][^3_2]
- Scheduling: run nightly to compute admin counts, project inactivity, and external user status; send alerts when thresholds are exceeded and write evidence to a SIEM using the Audit Log API for continuity and investigations.[^3_1][^3_2]
- Tuning: due to known timing and field consistency caveats on modified_at and user flags, consider grace periods and corroborating signals to minimize false positives before enforcement actions like deprovisioning or auto-archiving.[^3_6][^3_12]
<span style="display:none">[^3_15][^3_16][^3_17][^3_18][^3_19][^3_20][^3_21][^3_22]</span>

<div align="center">⁂</div>

[^3_1]: https://developers.asana.com/docs/audit-log-events

[^3_2]: https://developers.asana.com/reference/audit-log-api

[^3_3]: https://help.asana.com/s/article/service-accounts

[^3_4]: https://asana.com/features/admin-security

[^3_5]: https://forum.asana.com/t/integration-permissions/549405

[^3_6]: https://forum.asana.com/t/inconsistent-behavior-of-projects-api/924483

[^3_7]: https://forum.asana.com/t/it-is-not-possible-to-get-only-non-archived-projects-via-api-using-node-sdk-v1/966411

[^3_8]: https://forum.asana.com/t/api-changed-missing-modified-at/24505

[^3_9]: https://forum.asana.com/t/see-the-date-a-project-was-archived/111793

[^3_10]: https://developers.asana.com/reference/workspaces

[^3_11]: https://forum.asana.com/t/how-to-get-a-list-of-users-assignee/82466

[^3_12]: https://forum.asana.com/t/how-to-get-asana-licensed-users-from-asana-api/705496

[^3_13]: https://developers.asana.com/reference/getauditlogevents

[^3_14]: https://developers.asana.com/docs/quick-start

[^3_15]: https://help.asana.com/s/article/audit-suite-api-and-integration-support

[^3_16]: https://forum.asana.com/t/api-of-user-activity-more-robust/623558

[^3_17]: https://forum.asana.com/t/announcing-asana-s-audit-log-api/140140

[^3_18]: https://forum.asana.com/t/users-added-to-a-workspace-api-are-not-shown-in-the-admin-members-list/127330

[^3_19]: https://stackoverflow.com/questions/27613418/how-to-get-list-of-users-in-personal-projects-workspace-using-asana-api

[^3_20]: https://help.asana.com/s/article/compliance-management-add-on

[^3_21]: https://forum.asana.com/t/invite-users-users-not-in-asana-to-project-using-api/115867

[^3_22]: https://forum.asana.com/t/automatically-archive-done-tasks-that-are-older-than-30-days/90495


---

# can you do python code for this

Yes. Below is production-ready Python using the official Asana client that implements all three checks with pagination, rate-limit backoff, and clear outputs. It uses PAT or OAuth, supports multiple workspaces, and optionally queries the Audit Log API (if Enterprise with a service account) for a definitive org admin count.

### Prerequisites

- Install client: pip install asana.[^4_1][^4_2]
- Create a Personal Access Token or OAuth app; for Audit Log API, use a Service Account PAT in an Enterprise domain.[^4_3][^4_4]


### What the script does

- Enumerates workspaces and, for each, runs:
    - Admins check: counts org-level admins via Audit Log API fallback or user flags where available; alerts if count > 4.[^4_5][^4_6]
    - Inactive projects check: lists non-archived projects and flags any with project.modified_at older than 365 days.[^4_7][^4_8]
    - External users check: lists workspace users and flags active guests using is_guest and is_active.[^4_9][^4_10]


### Python code

```python
import os
import time
import datetime as dt
from typing import Dict, List, Optional

import asana  # pip install asana

ASANA_ACCESS_TOKEN = os.getenv("ASANA_ACCESS_TOKEN")          # PAT or OAuth bearer
ASANA_AUDIT_SVC_TOKEN = os.getenv("ASANA_AUDIT_SVC_TOKEN")    # Service Account PAT (Enterprise) for Audit Log API, optional
DAYS_INACTIVE = int(os.getenv("ASANA_DAYS_INACTIVE", "365"))  # override if needed

RATE_LIMIT_SLEEP_BASE = 2.0  # seconds
MAX_RETRIES = 5

def make_client(token: str) -> asana.Client:
    client = asana.Client.access_token(token)
    client.options["page_size"] = 100
    client.options["timeout"] = 60
    return client

def backoff_retry(callable_fn, *args, **kwargs):
    delay = RATE_LIMIT_SLEEP_BASE
    for attempt in range(MAX_RETRIES):
        try:
            return callable_fn(*args, **kwargs)
        except asana.error.RateLimitEnforcedError as e:
            retry_after = getattr(e, "retry_after", None)
            sleep_for = float(retry_after) if retry_after else delay
            time.sleep(sleep_for)
            delay *= 2
        except asana.error.AsanaError:
            raise
    raise RuntimeError("Exceeded retries due to rate limits")

def list_all_workspaces(client: asana.Client) -> List[Dict]:
    # GET /workspaces
    return list(backoff_retry(client.workspaces.get_workspaces))  # compact records with gid, name
    # Docs show workspaces listing and schema with gid/name [web:34][web:74]

def list_workspace_users(client: asana.Client, workspace_gid: str) -> List[Dict]:
    # GET /workspaces/{workspace_gid}/users with opt_fields
    params = {
        "workspace": workspace_gid,
        "opt_fields": "gid,name,email,is_active,is_guest"
    }
    return list(backoff_retry(client.users.get_users_for_workspace, workspace_gid, params))
    # Endpoint returns users in a workspace; is_guest/is_active are key for guest detection [web:70][web:48]

def list_workspace_projects(client: asana.Client, workspace_gid: str) -> List[Dict]:
    # GET /workspaces/{workspace_gid}/projects with archived filter and modified_at field
    params = {
        "archived": False,
        "opt_fields": "gid,name,archived,modified_at,owner"
    }
    return list(backoff_retry(client.projects.get_projects_for_workspace, workspace_gid, params))
    # Projects listing with archived flag and modified_at for inactivity detection [web:75][web:34]

def parse_iso8601(ts: str) -> dt.datetime:
    return dt.datetime.fromisoformat(ts.replace("Z", "+00:00"))

def find_inactive_projects(projects: List[Dict], days: int) -> List[Dict]:
    cutoff = dt.datetime.now(dt.timezone.utc) - dt.timedelta(days=days)
    inactive = []
    for p in projects:
        # modified_at is expected in ISO 8601
        mod = p.get("modified_at")
        if not mod:
            # If missing modified_at, treat conservatively as potentially inactive
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
    # Caveats exist around modified_at timing; this applies a clear cutoff [web:46][web:49]

def detect_active_guests(users: List[Dict]) -> List[Dict]:
    guests = []
    for u in users:
        if u.get("is_active") and u.get("is_guest"):
            guests.append(u)
    return guests
    # Use is_guest + is_active to identify external users; validate against tenant behavior [web:70][web:48]

def list_org_admins_via_auditlog(audit_client: asana.Client, domain_gid: str) -> Optional[List[str]]:
    """
    Uses Audit Log API to derive current admins by scanning admin-role grant/revoke.
    Requires Enterprise service account PAT.
    """
    try:
        # GET /audit_log_events with filters on event_type
        # Note: Python SDK exposes raw endpoints via client.request where needed.
        # We iterate time-bounded to last 365 days as a practical window.
        now = dt.datetime.now(dt.timezone.utc)
        start_time = (now - dt.timedelta(days=365)).isoformat()
        params = {
            "limit": 100,
            "start_at": start_time,
            "event_types": "user_admin_role_granted,user_admin_role_revoked"
        }
        url = f"/domains/{domain_gid}/audit_log_events"
        admins = set()
        next_page = None
        while True:
            q = dict(params)
            if next_page:
                q["offset"] = next_page
            resp = backoff_retry(audit_client.request, "GET", url, params=q)
            data = resp.get("data", [])
            for ev in data:
                et = ev.get("event_type")
                actor = ev.get("actor", {})
                subject = ev.get("resource", {})  # user resource for role changes
                user_gid = subject.get("gid") or actor.get("gid")
                if not user_gid:
                    continue
                if et == "user_admin_role_granted":
                    admins.add(user_gid)
                elif et == "user_admin_role_revoked":
                    admins.discard(user_gid)
            next_page = (resp.get("next_page") or {}).get("offset")
            if not next_page:
                break
        return list(admins)
    except asana.error.AsanaError:
        return None
    # Audit Log API and event types reference; service accounts required [web:53][web:69][web:41]

def run_security_checks():
    primary_client = make_client(ASANA_ACCESS_TOKEN)
    audit_client = make_client(ASANA_AUDIT_SVC_TOKEN) if ASANA_AUDIT_SVC_TOKEN else None

    results = []

    workspaces = list_all_workspaces(primary_client)

    for ws in workspaces:
        ws_gid = ws["gid"]
        ws_name = ws.get("name", "")
        # Users and Projects
        users = list_workspace_users(primary_client, ws_gid)
        projects = list_workspace_projects(primary_client, ws_gid)

        # External guests
        active_guests = detect_active_guests(users)

        # Inactive projects
        inactive_projects = find_inactive_projects(projects, DAYS_INACTIVE)

        # Admins
        admin_user_gids = None
        if audit_client:
            # For audit API, the domain id is the org workspace gid for enterprise organizations
            admin_user_gids = list_org_admins_via_auditlog(audit_client, ws_gid)

        # Fallback heuristic if audit log is not available or returned None:
        if not admin_user_gids:
            # Heuristic: use users where is_guest=False and is_active=True and potentially check for org admin via other channels.
            # The core API does not definitively expose org-admin; this remains a best-effort fallback.
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
```


### Notes and caveats

- Official Python client usage and examples are documented, including setup, pagination, and basic patterns for listing resources and reading gids and fields.[^4_4][^4_1]
- Projects listing supports workspace scoping and returns archived and modified_at; use that to filter for inactivity across 365 days, with awareness of timing nuances reported by developers.[^4_11][^4_7]
- Users-in-workspace endpoint returns is_guest and is_active used to identify active external accounts; some tenants report mismatches with Admin Console, so treat results as a detection signal and confirm when remediating.[^4_10][^4_9]
- Audit Log API requires Enterprise service accounts and is the authoritative way to track admin role assignments across the domain; use its events to maintain a current admin set and enforce the “no more than 4 admins” policy reliably.[^4_5][^4_3]
<span style="display:none">[^4_12][^4_13][^4_14][^4_15][^4_16][^4_17][^4_18][^4_19][^4_20][^4_21][^4_22]</span>

<div align="center">⁂</div>

[^4_1]: https://pypi.org/project/asana/3.2.0/

[^4_2]: https://github.com/Asana/python-asana

[^4_3]: https://raw.githubusercontent.com/Asana/openapi/master/defs/asana_oas.yaml

[^4_4]: https://developers.asana.com/docs/python

[^4_5]: https://developers.asana.com/reference/getauditlogevents

[^4_6]: https://developers.asana.com/docs/audit-log-events

[^4_7]: https://developers.asana.com/reference/getprojectsforworkspace

[^4_8]: https://developers.asana.com/reference/workspaces

[^4_9]: https://forum.asana.com/t/how-to-get-asana-licensed-users-from-asana-api/705496

[^4_10]: https://developers.asana.com/reference/getusersforworkspace

[^4_11]: https://forum.asana.com/t/inconsistent-behavior-of-projects-api/924483

[^4_12]: https://forum.asana.com/t/python-client-library-get-all-projects-list/115234

[^4_13]: https://forum.asana.com/t/python-return-name-of-all-projects-in-workspace/172741

[^4_14]: https://forum.asana.com/t/how-to-get-user-roles-for-a-project-using-the-asana-api/128163

[^4_15]: https://stackoverflow.com/questions/27613418/how-to-get-list-of-users-in-personal-projects-workspace-using-asana-api

[^4_16]: https://stackoverflow.com/questions/19523343/how-to-list-all-the-projects-of-a-specific-workspace-of-a-specific-user-in-asana

[^4_17]: https://stackoverflow.com/questions/30601424/how-can-i-create-a-new-project-with-tasks-in-asana-using-python

[^4_18]: https://developers.asana.com/reference/events

[^4_19]: https://forum.asana.com/t/tasks-by-user-and-project/122323

[^4_20]: https://forum.asana.com/t/get-users-not-working-python-library/125932

[^4_21]: https://developers.asana.com/reference/getevents

[^4_22]: https://forum.asana.com/t/get-list-of-all-projects/641928


---

# create conda environment

Here are concise, reliable commands to create and use a new conda environment, plus an example environment.yml for reproducibility and tips to avoid conflicts.[^5_1][^5_2]

### Quick create

- Create and activate a Python 3.11 environment with common flags for speed and fewer conflicts:
conda create -n myenv -y python=3.11 \&\& conda activate myenv.[^5_3][^5_1]


### Add packages

- Install packages during creation to improve solve stability:
conda create -n myenv -y python=3.11 requests pandas ipykernel.[^5_4][^5_1]
- Or add later to the active env:
conda install -y numpy scipy matplotlib.[^5_1]


### From environment.yml

- Create from a spec file:
conda env create -f environment.yml.[^5_2]
- Minimal cross-platform export for sharing:
conda env export --from-history > environment.yml.[^5_5][^5_6]


### Example environment.yml

- Save as environment.yml in the project root:
name: asana-sec
channels:
    - conda-forge
    - defaults
dependencies:
    - python=3.11
    - pip
    - requests
    - pandas
    - pip:
        - asana==3.2.0
- Then create it:
conda env create -f environment.yml \&\& conda activate asana-sec.[^5_7][^5_2]


### Useful checks

- List environments and verify activation:
conda env list \&\& python -V.[^5_8][^5_2]
- If activate fails, initialize shell and restart terminal:
conda init bash; exec bash  \# or the appropriate shell.[^5_9][^5_10]


### Tips

- Prefer installing needed packages in one create command to reduce dependency churn and solver conflicts.[^5_1]
- For exact reproducibility across OSes, consider full exports or lockfiles; otherwise prefer --from-history for portability and add channels explicitly in the YAML.[^5_6][^5_11]
<span style="display:none">[^5_12][^5_13][^5_14][^5_15][^5_16][^5_17][^5_18][^5_19][^5_20][^5_21]</span>

<div align="center">⁂</div>

[^5_1]: https://www.anaconda.com/docs/getting-started/working-with-conda/environments

[^5_2]: https://docs.conda.io/docs/user-guide/tasks/manage-environments.html

[^5_3]: https://docs.pages.surrey.ac.uk/research_computing/hpc/software/python/conda_envs.html

[^5_4]: https://conda.discourse.group/t/defining-and-documenting-how-pip-should-interact-with-conda-environments/200

[^5_5]: https://www.monicathieu.com/posts/2024-05-20-conda-env-export-from-history.html

[^5_6]: https://docs.conda.io/projects/conda/en/stable/commands/env/export.html

[^5_7]: https://pypi.org/project/asana/3.2.0/

[^5_8]: https://visa.ill.fr/help/data-analysis/conda

[^5_9]: https://docs.conda.io/projects/conda/en/stable/dev-guide/deep-dives/activation.html

[^5_10]: https://forum.anaconda.com/t/unable-to-activate-environment-prompted-to-run-conda-init-before-conda-activate-but-it-doesnt-work/68677

[^5_11]: https://arc.leeds.ac.uk/recording-and-exporting-conda-environments-for-python/

[^5_12]: https://stackoverflow.com/questions/74959226/how-to-pick-python-3-11-as-a-conda-environment-in-vs-code

[^5_13]: https://vladiliescu.net/wiki/conda/

[^5_14]: https://stackoverflow.com/questions/47246350/conda-activate-not-working

[^5_15]: https://numdifftools.readthedocs.io/en/latest/how-to/create_virtual_env_with_conda.html

[^5_16]: https://stackoverflow.com/questions/41274007/anaconda-export-environment-file

[^5_17]: https://docs.conda.io/projects/conda/en/stable/user-guide/getting-started.html

[^5_18]: https://docs.conda.io/projects/conda/en/latest/user-guide/tasks/manage-python.html

[^5_19]: https://docs.readthedocs.com/platform/stable/guides/conda.html

[^5_20]: https://github.com/conda/conda/issues/9399

[^5_21]: https://www.jetbrains.com/help/pycharm/conda-support-creating-conda-virtual-environment.html


---

# Traceback (most recent call last):

File "/home/vitalie/Documents/assignment/asana.py", line 6, in <module>
import asana  \# pip install asana
^^^^^^^^^^^^
File "/home/vitalie/Documents/assignment/asana.py", line 15, in <module>
def make_client(token: str) -> asana.Client:
^^^^^^^^^^^^
AttributeError: partially initialized module 'asana' has no attribute 'Client' (most likely due to a circular import)

This error is caused by the script being named asana.py, which shadows the installed asana package and makes Python import the local file instead of the library, triggering the “partially initialized module” circular-import message when accessing asana.Client. Rename the script and remove its compiled cache so imports resolve to the real package.[^6_1][^6_2]

### Fix steps

- Rename the file from asana.py to something like asana_checks.py or security_checks.py to avoid shadowing the third-party module name.[^6_3][^6_1]
- Delete the local cache artifacts so Python doesn’t load the wrong module:
    - Remove asana.pyc and the __pycache__/ folder in the same directory as the script.[^6_4][^6_2]
- Ensure the official client is installed and importable:
    - pip show asana should list version and location; if not, pip install asana.[^6_5][^6_6]
- Verify by running a minimal snippet in a clean shell:
    - python -c "import asana, sys; print('ok', asana.__version__)" should print the version without errors.[^6_7][^6_5]


### Why this happens

- Python’s import resolution searches the current directory first, so a local asana.py takes precedence over the PyPI asana package, leading to attribute errors that mention “partially initialized module” or suggest a circular import when the module refers to itself.[^6_2][^6_1]


### If issues persist

- Check that there is no local folder named asana/ in the project tree that could also shadow the package; rename or adjust PYTHONPATH if present.[^6_8][^6_2]
- If using notebooks or IDEs, restart the kernel/terminal after renaming to clear in-memory module caches before retrying the import.[^6_9][^6_7]
<span style="display:none">[^6_10][^6_11][^6_12][^6_13][^6_14][^6_15][^6_16][^6_17][^6_18][^6_19][^6_20][^6_21]</span>

<div align="center">⁂</div>

[^6_1]: https://stackoverflow.com/questions/59762996/how-to-fix-attributeerror-partially-initialized-module

[^6_2]: https://bobbyhadz.com/blog/python-attributeerror-partially-initialized-module-has-no-attribute

[^6_3]: https://discuss.python.org/t/warning-when-importing-a-local-module-with-the-same-name-as-a-2nd-or-3rd-party-module/27799

[^6_4]: https://www.youtube.com/watch?v=5ZSPdxJO0YE

[^6_5]: https://github.com/Asana/python-asana

[^6_6]: https://forum.asana.com/t/new-python-client-library/763740

[^6_7]: https://developers.asana.com/docs/python

[^6_8]: https://community.pinecone.io/t/pinecone-init-attributeerror-partially-initialized-module-pinecone-has-no-attribute-init-most-likely-due-to-a-circular-import/2777

[^6_9]: https://stackoverflow.com/questions/47246350/conda-activate-not-working

[^6_10]: https://forum.asana.com/t/python-api-connection/159175

[^6_11]: https://forum.asana.com/t/module-asana-has-no-attribute-client/496534

[^6_12]: https://www.mend.io/blog/closing-the-loop-on-python-circular-import-issue/

[^6_13]: https://discuss.python.org/t/better-error-message-for-circular-import/50955

[^6_14]: https://forum.asana.com/t/error-using-python-library-to-search-tasks/475517

[^6_15]: https://github.com/python/cpython/issues/136094

[^6_16]: https://rollbar.com/blog/how-to-fix-circular-import-in-python/

[^6_17]: https://forum.asana.com/t/having-issues-connecting-to-asana-using-oauth2-in-python/159153

[^6_18]: https://stackoverflow.com/questions/7336802/how-to-avoid-circular-imports-in-python

[^6_19]: https://github.com/Textualize/textual/discussions/1881

[^6_20]: https://stackoverflow.com/questions/30601424/how-can-i-create-a-new-project-with-tasks-in-asana-using-python

[^6_21]: https://www.reddit.com/r/learnpython/comments/yusmby/how_to_correctly_structure_a_project_in_python_to/


---

# how to run python file with conda

The two reliable ways are: activate the environment, then run python; or use conda run to invoke python in a target env without activating it in the shell.[^7_1][^7_2]

### Activate then run

- Linux/macOS:
conda activate myenv \&\& python script.py.[^7_2]
- Windows (Anaconda Prompt or after conda init):
conda activate myenv \&\& python script.py.[^7_3][^7_4]
- If activation fails, initialize the shell and restart terminal:
conda init bash  \# or zsh/fish/powershell, then reopen terminal.[^7_5][^7_2]


### Use conda run

- Run without changing current shell state:
conda run -n myenv python script.py.[^7_1]
- Works with full path as well:
conda run -p /full/path/to/env python script.py.[^7_1]


### From another Python process

- Spawn the script under a specific env:
python -c "import subprocess; subprocess.run(['conda','run','-n','myenv','python','script.py'], check=True)".[^7_6]


### Shebang or wrapper options

- Direct shebang to env’s interpreter:
/path/to/conda/envs/myenv/bin/python script.py  \# put this path in a shell script if preferred.[^7_7]
- On Windows, prefer Anaconda Prompt and select the interpreter or use activate then python script.py to ensure paths are set correctly.[^7_8][^7_3]
<span style="display:none">[^7_10][^7_11][^7_12][^7_13][^7_14][^7_15][^7_16][^7_17][^7_18][^7_19][^7_9]</span>

<div align="center">⁂</div>

[^7_1]: https://docs.conda.io/projects/conda/en/stable/commands/run.html

[^7_2]: https://docs.conda.io/docs/user-guide/tasks/manage-environments.html

[^7_3]: https://docs.conda.io/projects/conda/en/stable/user-guide/getting-started.html

[^7_4]: https://www.anaconda.com/docs/getting-started/working-with-conda/environments

[^7_5]: https://forum.anaconda.com/t/unable-to-activate-environment-prompted-to-run-conda-init-before-conda-activate-but-it-doesnt-work/68677

[^7_6]: https://stackoverflow.com/questions/36275308/how-do-you-activate-an-anaconda-environment-within-a-python-script

[^7_7]: https://predictivehacks.com/?all-tips=how-to-run-python-shell-scripts-from-a-conda-environment

[^7_8]: https://stackoverflow.com/questions/39995380/how-to-use-anaconda-python-to-execute-a-py-file

[^7_9]: https://gist.github.com/maximlt/531419545b039fa33f8845e5bc92edd6

[^7_10]: https://www.reddit.com/r/learnpython/comments/v5mf48/batch_script_to_run_anaconda_prompt_and_activate/

[^7_11]: https://docs.oracle.com/en-us/iaas/Content/data-science/using/conda_python_script.htm

[^7_12]: https://feigeek.com/how-to-activate-a-conda-environment-in-python-code.html

[^7_13]: https://www.reddit.com/r/learnpython/comments/f5rrss/how_to_run_an_anaconda_environment_python/

[^7_14]: https://docs.readthedocs.com/platform/stable/guides/conda.html

[^7_15]: https://www.jetbrains.com/help/pycharm/conda-support-creating-conda-virtual-environment.html

[^7_16]: https://clause-bielefeld.github.io/teaching/python/

[^7_17]: https://github.com/conda/conda/issues/9982

[^7_18]: https://www.anaconda.com/docs/getting-started/working-with-conda/ide-tutorials/vscode

[^7_19]: https://gpuhackshef.readthedocs.io/en/latest/bede/software/python.html


---

# Traceback (most recent call last):

File "/home/vitalie/Documents/assignment/test.py", line 15, in <module>
def make_client(token: str) -> asana.Client:
^^^^^^^^^^^^
AttributeError: module 'asana' has no attribute 'Client'. Did you mean: 'ApiClient'?

ERROR conda.cli.main_run:execute(127): `conda run python test.py` failed. (See above for error)

The error means the installed Asana Python SDK version does not expose Client anymore; newer SDKs use Configuration + ApiClient + Resource APIs (e.g., UsersApi, ProjectsApi). Switching imports and initialization fixes it, or pin the legacy 3.x client if preferring Client.access_token.[^8_1][^8_2]

### Option A: Use current SDK (v5-style)

- Pattern: create Configuration with access_token, then ApiClient, then instantiate per-resource APIs like UsersApi, ProjectsApi, WorkspacesApi.[^8_2][^8_1]
- Minimal example to test auth:
import asana
cfg = asana.Configuration()
cfg.access_token = os.getenv("ASANA_ACCESS_TOKEN")
api_client = asana.ApiClient(cfg)
users = asana.UsersApi(api_client)
me = users.get_user("me", {})
print(me) .[^8_3][^8_2]
- Projects in a workspace with fields for checks:
projects = asana.ProjectsApi(api_client)
ws_gid = "<WORKSPACE_GID>"
prjs = projects.get_projects_for_workspace(ws_gid, {"archived": False, "opt_fields": "gid,name,modified_at,archived"})
print(list(prjs)) .[^8_4][^8_2]


### Option B: Pin legacy client (has Client)

- Install a 3.x release that still exposes Client:
pip install "asana<4"
then use:
import asana
client = asana.Client.access_token(TOKEN)
me = client.users.get_user("me") .[^8_5][^8_6]
- Note: legacy API is deprecated in favor of the v5-style SDK; future changes will land in the new interface, so migrating is recommended.[^8_7][^8_1]


### Why the attribute changed

- Asana released a new Python client that generates per-resource API classes and no longer uses a monolithic Client class; errors like “no attribute ‘Client’” indicate the new package is installed, but legacy code is still being used.[^8_1][^8_2]


### Migration sketch for the security checks

- Init once:
cfg = asana.Configuration(); cfg.access_token = TOKEN; api_client = asana.ApiClient(cfg) .[^8_2]
- Workspaces: workspaces = asana.WorkspacesApi(api_client).get_workspaces({}) .[^8_8][^8_2]
- Users per workspace: asana.UsersApi(api_client).get_users_for_workspace(ws_gid, {"opt_fields":"gid,name,email,is_active,is_guest"}) .[^8_9][^8_2]
- Projects per workspace: asana.ProjectsApi(api_client).get_projects_for_workspace(ws_gid, {"archived": False, "opt_fields":"gid,name,archived,modified_at"}) .[^8_4][^8_2]
- Audit Log API: call via ApiClient.call_api against /domains/{domain_gid}/audit_log_events with event_types filters if the SDK lacks a helper class in the current version.[^8_10][^8_2]


### Quick conda run test

- conda run -n myenv python -c "import asana,os; cfg=asana.Configuration(); cfg.access_token=os.getenv('ASANA_ACCESS_TOKEN'); print('ok')" should print ok if the new import path is correct.[^8_11][^8_12]
<span style="display:none">[^8_13][^8_14][^8_15][^8_16][^8_17][^8_18][^8_19][^8_20][^8_21][^8_22][^8_23][^8_24][^8_25]</span>

<div align="center">⁂</div>

[^8_1]: https://forum.asana.com/t/new-python-client-library/763740

[^8_2]: https://github.com/Asana/python-asana

[^8_3]: https://developers.asana.com/docs/python

[^8_4]: https://developers.asana.com/reference/getprojectsforworkspace

[^8_5]: https://pypi.org/project/asana/3.2.1/

[^8_6]: https://pypi.org/project/asana/3.2.2/

[^8_7]: https://developers.asana.com/docs/migration-guide-python-v5

[^8_8]: https://developers.asana.com/reference/workspaces

[^8_9]: https://developers.asana.com/reference/getusersforworkspace

[^8_10]: https://developers.asana.com/reference/getauditlogevents

[^8_11]: https://docs.conda.io/projects/conda/en/stable/commands/run.html

[^8_12]: https://docs.conda.io/projects/conda/en/stable/user-guide/getting-started.html

[^8_13]: https://forum.asana.com/t/module-asana-has-no-attribute-client/496534

[^8_14]: https://forum.asana.com/t/python-api-connection/159175

[^8_15]: https://stackoverflow.com/questions/43869206/accesing-asana-data-using-python-requests

[^8_16]: https://forum.asana.com/t/api-authorization-in-python/82500

[^8_17]: https://developers.asana.com/docs/migration-guide-v3-node-sdk

[^8_18]: https://developers.asana.com/docs/deprecations

[^8_19]: https://forum.asana.com/t/asana-api-event-not-returning-new-sync-python/124274

[^8_20]: https://forum.asana.com/t/post-a-comment-through-the-api-asana-api/126999

[^8_21]: https://stackoverflow.com/questions/63381169/update-custom-fields-with-python-in-asana-api

[^8_22]: https://developers.asana.com/docs/quick-start

[^8_23]: https://forum.asana.com/c/forum-en/api/24?page=13

[^8_24]: https://www.merge.dev/blog/get-tasks-asana-api-python

[^8_25]: https://anvil.works/articles/using-the-asana-api


---

# modify below acording to the new sdk

import os
import time
import datetime as dt
from typing import Dict, List, Optional

import asana  \# pip install asana

ASANA_ACCESS_TOKEN = os.getenv("ASANA_ACCESS_TOKEN")          \# PAT or OAuth bearer
ASANA_AUDIT_SVC_TOKEN = os.getenv("ASANA_AUDIT_SVC_TOKEN")    \# Service Account PAT (Enterprise) for Audit Log API, optional
DAYS_INACTIVE = int(os.getenv("ASANA_DAYS_INACTIVE", "365"))  \# override if needed

RATE_LIMIT_SLEEP_BASE = 2.0  \# seconds
MAX_RETRIES = 5

def make_client(token: str) -> asana.Client:
client = asana.Client.access_token(token)
client.options["page_size"] = 100
client.options["timeout"] = 60
return client

def backoff_retry(callable_fn, *args, **kwargs):
delay = RATE_LIMIT_SLEEP_BASE
for attempt in range(MAX_RETRIES):
try:
return callable_fn(*args, **kwargs)
except asana.error.RateLimitEnforcedError as e:
retry_after = getattr(e, "retry_after", None)
sleep_for = float(retry_after) if retry_after else delay
time.sleep(sleep_for)
delay *= 2
except asana.error.AsanaError:
raise
raise RuntimeError("Exceeded retries due to rate limits")

def list_all_workspaces(client: asana.Client) -> List[Dict]:
\# GET /workspaces
return list(backoff_retry(client.workspaces.get_workspaces))  \# compact records with gid, name
\# Docs show workspaces listing and schema with gid/name [web:34][web:74]

def list_workspace_users(client: asana.Client, workspace_gid: str) -> List[Dict]:
\# GET /workspaces/{workspace_gid}/users with opt_fields
params = {
"workspace": workspace_gid,
"opt_fields": "gid,name,email,is_active,is_guest"
}
return list(backoff_retry(client.users.get_users_for_workspace, workspace_gid, params))
\# Endpoint returns users in a workspace; is_guest/is_active are key for guest detection [web:70][web:48]

def list_workspace_projects(client: asana.Client, workspace_gid: str) -> List[Dict]:
\# GET /workspaces/{workspace_gid}/projects with archived filter and modified_at field
params = {
"archived": False,
"opt_fields": "gid,name,archived,modified_at,owner"
}
return list(backoff_retry(client.projects.get_projects_for_workspace, workspace_gid, params))
\# Projects listing with archived flag and modified_at for inactivity detection [web:75][web:34]

def parse_iso8601(ts: str) -> dt.datetime:
return dt.datetime.fromisoformat(ts.replace("Z", "+00:00"))

def find_inactive_projects(projects: List[Dict], days: int) -> List[Dict]:
cutoff = dt.datetime.now(dt.timezone.utc) - dt.timedelta(days=days)
inactive = []
for p in projects:
\# modified_at is expected in ISO 8601
mod = p.get("modified_at")
if not mod:
\# If missing modified_at, treat conservatively as potentially inactive
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
\# Caveats exist around modified_at timing; this applies a clear cutoff [web:46][web:49]

def detect_active_guests(users: List[Dict]) -> List[Dict]:
guests = []
for u in users:
if u.get("is_active") and u.get("is_guest"):
guests.append(u)
return guests
\# Use is_guest + is_active to identify external users; validate against tenant behavior [web:70][web:48]

def list_org_admins_via_auditlog(audit_client: asana.Client, domain_gid: str) -> Optional[List[str]]:
"""
Uses Audit Log API to derive current admins by scanning admin-role grant/revoke.
Requires Enterprise service account PAT.
"""
try:
\# GET /audit_log_events with filters on event_type
\# Note: Python SDK exposes raw endpoints via client.request where needed.
\# We iterate time-bounded to last 365 days as a practical window.
now = dt.datetime.now(dt.timezone.utc)
start_time = (now - dt.timedelta(days=365)).isoformat()
params = {
"limit": 100,
"start_at": start_time,
"event_types": "user_admin_role_granted,user_admin_role_revoked"
}
url = f"/domains/{domain_gid}/audit_log_events"
admins = set()
next_page = None
while True:
q = dict(params)
if next_page:
q["offset"] = next_page
resp = backoff_retry(audit_client.request, "GET", url, params=q)
data = resp.get("data", [])
for ev in data:
et = ev.get("event_type")
actor = ev.get("actor", {})
subject = ev.get("resource", {})  \# user resource for role changes
user_gid = subject.get("gid") or actor.get("gid")
if not user_gid:
continue
if et == "user_admin_role_granted":
admins.add(user_gid)
elif et == "user_admin_role_revoked":
admins.discard(user_gid)
next_page = (resp.get("next_page") or {}).get("offset")
if not next_page:
break
return list(admins)
except asana.error.AsanaError:
return None
\# Audit Log API and event types reference; service accounts required [web:53][web:69][web:41]

def run_security_checks():
primary_client = make_client(ASANA_ACCESS_TOKEN)
audit_client = make_client(ASANA_AUDIT_SVC_TOKEN) if ASANA_AUDIT_SVC_TOKEN else None

    results = []
    
    
    workspaces = list_all_workspaces(primary_client)
    
    
    for ws in workspaces:
        ws_gid = ws["gid"]
        ws_name = ws.get("name", "")
        # Users and Projects
        users = list_workspace_users(primary_client, ws_gid)
        projects = list_workspace_projects(primary_client, ws_gid)
    
    
        # External guests
        active_guests = detect_active_guests(users)
    
    
        # Inactive projects
        inactive_projects = find_inactive_projects(projects, DAYS_INACTIVE)
    
    
        # Admins
        admin_user_gids = None
        if audit_client:
            # For audit API, the domain id is the org workspace gid for enterprise organizations
            admin_user_gids = list_org_admins_via_auditlog(audit_client, ws_gid)
    
    
        # Fallback heuristic if audit log is not available or returned None:
        if not admin_user_gids:
            # Heuristic: use users where is_guest=False and is_active=True and potentially check for org admin via other channels.
            # The core API does not definitively expose org-admin; this remains a best-effort fallback.
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

Here’s a drop-in rewrite of the script for the new Asana Python SDK (v5-style), replacing Client.access_token with Configuration + ApiClient and per-resource APIs like WorkspacesApi, UsersApi, and ProjectsApi, and using ApiClient.call_api for Audit Log events.

### Updated Python code

```python
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
```


### What changed and why

- Initialization now uses Configuration + ApiClient; per-resource methods live under WorkspacesApi, UsersApi, and ProjectsApi in the v5 SDK, replacing the legacy Client.* namespaces.[^9_1][^9_2]
- Error handling catches asana.rest.ApiException with status 429 and honors Retry-After; the v5 SDK surfaces HTTP errors via ApiException rather than legacy AsanaError classes.[^9_2][^9_1]
- Audit Log API is accessed via ApiClient.call_api against /domains/{domain_gid}/audit_log_events because the v5 SDK may not expose a dedicated helper; the endpoint and event types are in the Audit Log docs.[^9_3][^9_4]


### Quick sanity test

- After setting ASANA_ACCESS_TOKEN, this should list workspaces, users, and projects using the new SDK patterns seen in the Python docs and migration guidance for v5.[^9_5][^9_1]
<span style="display:none">[^9_10][^9_11][^9_12][^9_13][^9_14][^9_15][^9_16][^9_17][^9_18][^9_19][^9_20][^9_6][^9_7][^9_8][^9_9]</span>

<div align="center">⁂</div>

[^9_1]: https://developers.asana.com/docs/python

[^9_2]: https://github.com/Asana/python-asana

[^9_3]: https://developers.asana.com/docs/audit-log-events

[^9_4]: https://developers.asana.com/reference/audit-log-api

[^9_5]: https://developers.asana.com/docs/migration-guide-python-v5

[^9_6]: https://forum.asana.com/t/upload-attachment-using-python-sdk-v5/846077

[^9_7]: https://stackoverflow.com/questions/30601424/how-can-i-create-a-new-project-with-tasks-in-asana-using-python

[^9_8]: https://pypi.org/project/asana/3.2.2/

[^9_9]: https://forum.asana.com/t/announcing-asana-s-audit-log-api/140140

[^9_10]: https://forum.asana.com/t/new-python-client-library/763740

[^9_11]: https://stackoverflow.com/questions/43869206/accesing-asana-data-using-python-requests

[^9_12]: https://developers.asana.com/docs/quick-start

[^9_13]: https://forum.asana.com/t/replace-error-using-set-parent-for-task/647294

[^9_14]: https://developers.asana.com/reference/getauditlogevents

[^9_15]: https://forum.asana.com/t/python-client-library-get-all-projects-list/115234

[^9_16]: https://developers.asana.com/docs/oauth

[^9_17]: https://www.merge.dev/blog/how-to-create-tasks-in-asana-via-the-asana-api-in-python

[^9_18]: https://developers.asana.com/docs/personal-access-token

[^9_19]: https://help.asana.com/s/article/audit-suite-api-and-integration-support

[^9_20]: https://rollout.com/integration-guides/asana/sdk/step-by-step-guide-to-building-a-asana-api-integration-in-python

