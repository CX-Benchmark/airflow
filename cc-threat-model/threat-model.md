# Threat model: Apache Airflow monorepo (github.com/cx-benchmark/airflow, main @ a462d683)

Reviewed whole at this commit (the model on file gave no commit and lacked the required sections). Paths are relative to the repository root; `core/` = `airflow-core/src/airflow/`, `api/` = `core/api_fastapi/`, `sdk/` = `task-sdk/src/airflow/sdk/`.

## system

**Purpose.** Apache Airflow 3: schedules and runs user-defined workflows ("Dags") written with the Task SDK (README.md, AGENTS.md "Architecture Boundaries"). Versions: `core/__init__.py` `__version__ = "3.4.0"` (main), `sdk/__init__.py` `1.4.0`, `airflowctl` `0.1.5`; Dockerfile `ARG AIRFLOW_VERSION="3.3.2"`; `chart/Chart.yaml` `version: 2.0.0`, `appVersion: 3.3.2`.

**Components (read unless marked out of view).**
- **API server** — FastAPI, `api/app.py:create_app(apps)`; `airflow api-server --apps core|execution|all` (default all, `core/cli/cli_config.py:ARG_API_SERVER_APPS`), so by default the Execution API shares the public port. Mounts:
  - `/api/v2` public REST and `/ui` UI-only API (`api/core_api/routes/public/__init__.py`, `.../routes/ui/__init__.py`), registered by `api/core_api/app.py:init_views`.
  - `/execution` Task Execution API, Cadwyn-versioned (`api/execution_api/app.py:create_task_execution_api_app`).
  - `/auth` the configured auth manager's sub-app (`api/app.py:init_auth_manager` → `get_fastapi_app()`).
  - Plugin FastAPI apps at plugin-chosen prefixes; prefixes starting with `/api/v2, /ui, /execution, /auth, /pluginsv2` are refused (`api/app.py:init_plugins`, `RESERVED_URL_PREFIXES`). Airflow-2 Flask plugins at `/pluginsv2` through the FAB provider (`api/core_api/app.py:init_flask_plugins`).
  - `/static` (built React UI), plugin translation routes under `/static/i18n/`, catch-all `/{rest_of_path}` rendering `index.html` (`init_views`).
- **React UI** — `core/ui/` (TypeScript, Vite); simple-auth-manager login SPA in `api/auth/managers/simple/ui/`.
- **Scheduler** (`core/jobs/scheduler_job_runner.py`), **Dag File Processor** (`core/dag_processing/`), **Triggerer** (`core/jobs/triggerer_job_runner.py`), executors (`core/executors/`): metadata-DB access; bodies out of view except where cited.
- **Task SDK / worker runtime** — `sdk/execution_time/supervisor.py` forks the task process and relays its requests to the Execution API via `sdk/api/client.py`; supervisor↔task comms are length-prefixed msgpack frames over sockets (`sdk/execution_time/comms.py`). Non-Python runtimes are launched by coordinators (`sdk/coordinators/`: java, node, executable).
- **Language SDKs for Dag authors** — `go-sdk/` (module `github.com/apache/airflow/go-sdk`), `java-sdk/` (Gradle/Kotlin, Maven Central per README), `ts-sdk/` (npm `apache-airflow-ts-sdk` 1.0.0-beta1). A bundle executable dials the supervisor's `--comm host:port` (`go-sdk/pkg/execution/server.go`).
- **Log server** — `core/utils/serve_logs/`: uvicorn on all interfaces (`core.py:serve_logs`, `host=""`), `[logging] worker_log_server_port` 8793 / `trigger_log_server_port` 8794.
- **Scheduler health server** — `core/utils/scheduler_health.py` (`http.server`), only with `[scheduler] enable_health_check` (default False), bind `0.0.0.0:8974`.
- **CLIs** — `airflow` (`core/cli/`, local, uses config/DB directly; out of view beyond `api_server_command.py`/`cli_config.py`) and `airflowctl` (`airflow-ctl/`, remote REST client).
- **Providers** — `providers/` (109 `pyproject.toml` outside tests, each its own distribution): auth managers (`fab`, `keycloak`, `amazon` AWS), executors (`celery`, `cncf/kubernetes`, `edge3`), Dag bundles (`git`), hooks/operators for external systems. Read only where cited.
- **Shared libraries** `shared/*`, symlinked into core and task-sdk (AGENTS.md "Shared libraries").
- **Deployment artefacts** — `Dockerfile` (prod image), `chart/` (Helm), `clients/python` (generated REST client), `scripts/systemd` unit files.

**Principals it trusts** (`airflow-core/docs/security/security_model.rst` "user types"): Deployment Managers (all credentials and configuration); Dag authors (arbitrary code on workers, Dag File Processor, Triggerer — "neither verified, checked nor sand-boxed"); authenticated UI users limited by auth-manager roles (SimpleAuthManager VIEWER < USER < OP < ADMIN, `api/auth/managers/simple/simple_auth_manager.py:SimpleAuthManagerRole`); installed plugins and providers (code "can only be provided by installed packages" or the plugins folder). The doc's diagram marks UI, CLI, external REST clients and Worker/Task as untrusted and API server, Scheduler, DFP, Triggerer as the trusted control plane.

**Built, shipped, deployed (own files).**
- PyPI: `apache-airflow` (root `pyproject.toml`), `apache-airflow-core`, `apache-airflow-task-sdk`, `apache-airflow-ctl`, `apache-airflow-providers-*`; released by release managers per `dev/README_RELEASE_*.md` (no CI job publishing Python packages seen).
- Docker image: `Dockerfile` final stage `USER` AIRFLOW_UID (default 50000), `EXPOSE 8080`, `ENTRYPOINT ["/usr/bin/dumb-init", "--", "/entrypoint"]` (body copied from `scripts/docker/entrypoint_prod.sh`); pushed by `.github/workflows/release_dockerhub_image.yml` (workflow_dispatch, `DOCKERHUB_TOKEN`).
- npm TS SDK `.github/workflows/ts-sdk-release.yml`; docs to S3 `publish-docs-to-s3.yml` and registry site `registry-build.yml` (both workflow_dispatch, `DOCS_AWS_*` secrets).
- Runtime: `airflow api-server` binds `[api] host` default `0.0.0.0`, port 8080, `[api] server_type` uvicorn; TLS only with `[api] ssl_cert/ssl_key`; `--proxy-headers` opt-in (`cli_config.py:ARG_API_SERVER_ALLOW_PROXY_FORWARDING`). Helm defaults (`chart/values.yaml`): `executor: CeleryExecutor`, `config.core.auth_manager` FabAuthManager, `load_examples: 'False'`, ClusterIP services, `networkPolicies.enabled: false`, `rbac.create: true`, `allowPodLaunching: true`.

## adversaries

Positions made concrete by code; for each, what it reaches. Entry points carry the authentication the code requires and the check. Omissions are counted at the end.

### A1 — unauthenticated network client of the API server (and the other listeners)
Anonymous (handler, router and app-level middleware read; no auth dependency):
- `GET /api/v2/monitor/health` — `routes/public/monitor.py:get_health` → `core/api/common/airflow_health.py:get_airflow_health`: metadatabase status, scheduler/triggerer/DFP status and heartbeats, and per live instance its `hostname`, triggerer `team_names`, DFP `bundle_names`. `GET /api/v2/version` — version and git version. Both on `public_router` outside `authenticated_router` and skipped by `JWTRefreshMiddleware` (`UNAUTHENTICATED_PATHS`).
- `GET /api/v2/auth/login?next=` — 400 unless `api/core_api/security.py:is_safe_url` (http/https, same netloc as the request base URL or `[api] base_url`, path under the base, leading `//` and backslashes normalised); redirects to the auth manager login URL. `GET /api/v2/auth/logout` — revokes every presented token (`collect_request_tokens` → `revoke_token`), deletes the `_token` cookie, redirects to `get_url_logout()` or login.
- `/docs`, `/redoc` when `[api] enable_swagger_ui` (default True); FastAPI's default `openapi_url` is not overridden in `create_app` (library default, not verified).
- `/static/*`, `/static/i18n/languages.json` and plugin locale routes (`core_api/app.py:init_ui_translation_views`, segments checked by `_I18N_SEGMENT` `^[A-Za-z0-9_-]+$`), catch-all `index.html` (context `backend_server_base_url = request.base_url.path`), 404 stubs `/health`, `/api/v1/*`, `/api/*`.
- `GET /execution/health`, `GET /execution/health/ping` (`execution_api/routes/health.py`; ping returns service names and `repr(e)` of failures) — on `execution_api_router` outside the `require_auth` router.
- Auth-manager sub-app `/auth/*` (login surface, anonymous by design):
  - SimpleAuthManager (default `[core] auth_manager`): `POST /auth/token` and `POST /auth/token/cli` (`simple/routes/login.py` → `simple/services/login.py:create_token`; password compared with `hmac.compare_digest` against the JSON password file); `GET /auth/token` and `GET /auth/token/login` issue an ADMIN JWT for user "Anonymous" only when `[core] simple_auth_manager_all_admins` is True, else 403 (`token/login` redirects to `next` only if `is_safe_url`); `/auth/static`, `/auth/{path}` SPA. No rate limiting or lockout in these handlers.
  - With `simple_auth_manager_all_admins=True`, `simple/middleware.py:SimpleAllAdminMiddleware` (registered by `SimpleAuthManager.get_fastapi_middlewares`) appends `Authorization: Bearer <admin token>` to every request: every route below becomes anonymous-admin.
  - FAB: `POST /auth/token`, `/auth/token/cli`, `GET /auth/logout` (`providers/fab/.../auth_manager/api_fastapi/routes/login.py`) and the whole FAB Flask app mounted at `/auth/` through `WSGIMiddleware` (`fab_auth_manager.py:get_fastapi_app`). Flask views out of view; `providers/fab/src/airflow/providers/fab/www/app.py` initialises `CSRFProtect` and session-cookie flags from `[fab]`.
  - Keycloak: `/auth/login` (sets an OAuth `state` cookie), `/auth/login_callback` (state compared with `secrets.compare_digest`; `redirect_uri` from `[api] base_url` when set), `/auth/logout`, `/auth/logout_callback` (`providers/keycloak/.../routes/login.py`); `POST /auth/token`, `/auth/token/cli` (`routes/token.py`, body not read).
  - AWS: `/auth/login`, `/auth/login/token`, `POST /auth/login_callback` (SAML; `InResponseTo` enforced unless IdP-initiated login is opted in; `providers/amazon/.../auth_manager/routes/login.py:login_callback`).
- Plugin FastAPI apps: Airflow applies no authentication (comment and code in `api/app.py:init_plugins`; only team-scoped plugins under `[core] multi_team` get `TeamAuthorizationMiddleware`). Plugin root middlewares wrap every request. In-repo: edge3 `GET /edge_worker/v1/health`; common.ai `hitl_review_app` `/health`.
- Log server `GET /log/<path>` on 8793/8794: JWT in the raw `Authorization` header, `utils/serve_logs/log_server.py:JWTAuthStaticFiles.validate_jwt_token` (HS512, key `[api] secret_key`, audience `task-instance-logs`, claim `filename` must equal the requested path); Starlette `StaticFiles` rooted at `[logging] base_log_folder` (or the logging config's task-handler folder). A missing header → 403, and the request headers are logged.
- Scheduler `GET /health` (when enabled): anonymous.
- Celery Flower (`airflow celery flower`; provider defaults `flower_host 0.0.0.0`, `flower_basic_auth ""` in `providers/celery/.../get_provider_info.py`): server code out of view.

Everything else under `/api/v2` and `/ui` needs a valid user (A2); `/execution` needs an Execution token (A4).

### A2 — authenticated UI/API user (any role), or anyone holding a user JWT
- **Authentication** — `api/core_api/security.py:get_user`: a `Bearer` header wins; else `request.state.user` only if `request.state.user_authenticated_via is USER_INJECTED_BY_TRUSTED_MIDDLEWARE` (set by `api/auth/middlewares/refresh_token.py:JWTRefreshMiddleware`); else the `_token` cookie. `resolve_user_from_token` → `BaseAuthManager.get_user_from_token` (`base_auth_manager.py`): `JWTValidator.avalidated_claims`, `RevokedToken.is_revoked(jti)`, `deserialize_user`. Expired → 401, invalid → 403.
- **Default coverage** — `authenticated_router = AirflowRouter(dependencies=[Depends(get_user)])` includes the 29 public routers; `ui_router` (prefix `/ui`, `dependencies=[Depends(get_user)]`) includes all 17 UI routers. Opt-outs: `monitor_router`, `version_router`, `auth_router` only (`routes/public/__init__.py`).
- **Authorization** — every route in `routes/public/*.py` and `routes/ui/*.py` declares a dependency from `core_api/security.py` that calls the auth manager, except those named below:
  - `requires_access_dag(method, access_entity)`: Dag id from the path, else query `dag_id`; `~` or absent → `DagDetails(id=None)` (a whole-entity check). List endpoints add `Readable*FilterDep` (`permitted_dag_filter_factory` → `auth_manager.get_authorized_dag_ids`) to restrict rows; Dag-bundle and event-log lists use their own factories (`IMPORT_ERRORS_ALL` / `AUDIT_LOGS_ALL` for rows with no Dag).
  - Dag named elsewhere: `requires_access_backfill` (path `backfill_id` → the row's Dag, parsed with the handler's `NonNegativeInt` adapter; else body `dag_id`, non-string → 400); `requires_access_event_log`; `requires_access_dag_bulk`, `_dag_run_bulk`, `_dag_run_clear_bulk`, `requires_access_connection_bulk`, `_pool_bulk`, `_variable_bulk` build one request per entity (CREATE with overwrite also checks PUT; multi-team adds destination-team checks).
  - `PUT /api/v2/parseDagFile/{file_token}` — `requires_access_dag_from_file_token`: token decoded with itsdangerous `URLSafeSerializer([api] secret_key)` (bad signature → 404); authorizes PUT on every Dag in that file, or `AccessView.REPARSE_ALL` when the file has none.
  - Connections, variables, pools: `requires_access_connection|variable|pool` + `_collect_teams_to_check` (multi-team only: the existing row's team and body `team_name`; unreadable JSON or non-string team → 400).
  - Views: `requires_access_view` (`IMPORT_ERRORS`, `JOBS`, `PLUGINS`, `PROVIDERS`); import-error and Dag-source handlers also redact stack traces/source when the caller cannot read every Dag in the file (`import_error.py:REDACTED_STACKTRACE`, `dag_sources.py:REDACTED_SOURCE`).
  - `/api/v2/config*`: `requires_access_configuration` and `services/public/config.py:_check_expose_config` (403 unless `[api] expose_config`, default False; sensitive options masked).
  - HITL updates also consult `is_authorized_hitl_task(assigned_users)` (SimpleAuthManager: everyone when all-admins).
  - Authentication only: `GET /ui/config` and `GET /ui/teams` (`requires_authenticated()`; teams filtered by `ReadableTeamsFilterDep`); `GET /ui/auth/menus`, `GET /ui/auth/me`, `POST /ui/auth/token` (`GetUserDep`; mints a JWT for the caller valid `[api_auth] jwt_expiration_time` 86400 s or `jwt_cli_expiration_time` 3600 s).
  - Checked in the handler instead of the decorator: `POST /api/v2/connections/enqueue-test` (POST, or PUT when it may commit over an existing row, on that connection) and `GET /api/v2/connections/enqueue-test` (GET on the test's connection, else 404; token in header `Airflow-Connection-Test-Token`). `POST /api/v2/connections/test` re-checks GET before merging stored secrets and refuses stored-credential reuse on a different host/port (`connections.py:test_connection`). All three 403 unless `[core] test_connection` = Enabled (default Disabled).
- **Default role map** (`simple_auth_manager.py` `is_authorized_*`): Dags GET ≥ VIEWER, writes ≥ USER; assets, aliases, pools GET ≥ VIEWER, writes ≥ OP; configuration GET ≥ VIEWER (still gated by `expose_config`), writes ≥ OP; connections and variables ≥ OP for every method; views ≥ VIEWER except `IMPORT_ERRORS_ALL`, `AUDIT_LOGS_ALL`, `REPARSE_ALL` (ADMIN). Non-admins are refused when the resource's team is not in `user.teams`; ADMIN bypasses all.
- **Inputs they place that other components consume**: Dag-run `conf` (`[core] dag_run_conf_overrides_params` True) and notes (markdown), XCom entries (`POST/PATCH` xcom routes), task/asset state-store values, HITL responses, asset events, variables/connections (OP+), connection tests executed on a worker (`ConnectionTestRequest` → `/execution/connection-tests`).
- **Provider APIs in this position**: FAB `/auth/fab/v1/users|roles|permissions` (`requires_fab_custom_view` per method; `providers/fab/.../routes/users.py`, `roles.py`); edge3 `/edge_worker/ui/*` (all `requires_access_view(AccessView.JOBS)`, including worker maintenance, shutdown, queue and concurrency changes; `providers/edge3/.../worker_api/routes/ui.py`); common.ai HITL review (`requires_access_dag(..., HITL_DETAIL)`).

### A3 — another team (experimental `[core] multi_team`, default False)
- REST: the target's team from `DagModel.get_team_name`, `Connection/Variable/Pool.get_team_name`, body `team_name`; the auth manager decides (`SimpleAuthManager._is_authorized` compares with `user.teams`).
- Execution API: `execution_api/security.py:get_team_name_dep` (TI → Dag → bundle → team) scopes variable/connection lookups; `routes/xcoms.py:has_xcom_access` allows same-team access, or reads of team-less Dags, only when multi_team is on; `has_connection_access` and `has_variable_access` return True unconditionally.
- Plugins: team-scoped plugin apps wrapped in `api/auth/middlewares/team_authorization.py:TeamAuthorizationMiddleware` (`is_authorized_team`); team-scoped root middlewares are skipped.

### A4 — task code or a compromised worker holding an Execution API token
- **Tokens**: workload token (scope `workload`, lifetime `[scheduler] task_queued_timeout`, `core/executors/workloads/base.py:generate_token`) travels in the executor payload (argv for K8s/ECS/Batch/Lambda, Celery message body, per the `BundleInfo` docstring); `PATCH /execution/task-instances/{id}/run` swaps it for an `execution` token (`security.py:issue_execution_token`). Execution tokens: audience `[execution_api] jwt_audience` `urn:airflow.apache.org:task`, lifetime 600 s, reissued with the same claims by `app.py:JWTReissueMiddleware` when ≤ max(20 %, 30 s) remains. Also callback (`cb:self`), connection-test (`ct:self`, `token:workload`) and Dag-processor session/Job/parse tokens (`execution_api/dag_processor_tokens.py`; `POST /execution/jobs` needs `dag_processor_session`, `/jobs/{id}/heartbeat|complete|parse-token` need `dag_processor`).
- **Checks** (`execution_api/security.py`): `JWTBearer` validates once per request (required `aud, exp, iat`, plus `iss` when `[api_auth] jwt_issuer`) and builds a typed principal (`TIToken`, `DagProcessor*Token`, `DagParseToken`); `require_auth` enforces token type against the route's `allowed_token_types` (precomputed by `ExecutionAPIRoute`, default execution-only), `ti:self`/`ct:self`/`cb:self` subject = path id, a live-attempt check on mutations (`_require_live_attempt`, when `IdentifyArchivedTaskStateUpdates.is_applied`), an open-Job check for processor tokens, and bundle binding (`SelectedDagBundle`, `DagInGrantedBundle`). Applied to every router in `routes/__init__.py` via `authenticated_router = VersionedAPIRouter(dependencies=[Security(require_auth)])`; health is the only router outside.
- **Subject-bound (`ti:self`)**: `/task-instances/{id}/run|state|skip-downstream|dag-run-note|heartbeat|rtif|rendered-map-index|previous-successful-dagrun|validate-inlets-and-outlets`, `/hitlDetails/{id}`, `/task-reschedules/{id}/start_date`, `/store/ti/{id}/...`.
- **Not subject-bound (any valid execution token, any Dag)**: `GET /connections/{id}` (returns `password` and `extra` unredacted, `execution_api/datamodels/connection.py:ConnectionResponse`); `GET/PUT/DELETE /variables/{key}`, `/variables/keys`; `GET/HEAD/POST/DELETE /xcoms/{dag}/{run}/{task}/{key}` and `/slice`, `/item`; `/dag-runs/{dag}/{run}` GET, POST (trigger), `/clear`, `/state`, `/dag-runs/count|previous`; `/dags/{dag_id}`; `/task-instances/count|previous|states|breadcrumbs`; `/assets/*`, `/asset-events/*`, `/store/asset/*`.
- **Values the worker sets that the server later trusts**: `hostname` in the run payload is stored on the TI (`routes/task_instances.py`); the API server fetches logs from `http://{ti.hostname}:{port}/log/...` with a log JWT (`core/utils/log/file_task_handler.py:_get_log_retrieval_url`, `_fetch_logs_from_service`). Rendered template fields (`PUT .../rtif`), XComs and HITL details are shown in the UI.

### A5 — Dag author (trusted for code execution; the boundary is the control plane)
- Code runs in workers, DFP children and the triggerer. The DFP manager and triggerer reach the Execution API through `execution_api/in_process.py:InProcessExecutionAPI` (`dag_processing/manager.py`, `jobs/triggerer_job_runner.py`), whose `_configure_in_process_auth` overrides `_jwt_bearer`, `has_connection_access`, `has_variable_access`, `has_xcom_access` to allow.
- What must hold per AGENTS.md: the scheduler "never runs user code"; per security_model.rst no Dag-author code runs in the scheduler or API server. Serialized Dags written by the DFP are decoded there by `core/serialization/serialized_objects.py:BaseSerialization.deserialize` and `core/serialization/decoders.py`: timetables, partition mappers and windows are imported only from core prefixes (`helpers.py:is_core_timetable_import_path` = `airflow.timetables.`) or classes registered by plugins; wait policies core-only; builtin exceptions only from `_DESERIALIZABLE_BUILTIN_EXCEPTIONS`; priority-weight strategies from plugins; unknown type → `TypeError`. API XCom reads return the stored JSON or `core/serialization/stringify.py` output (`routes/public/xcom.py:get_xcom_entry`); dependency evaluation uses `XComModel.deserialize_value_primitives`.
- Dag-author and user text rendered in the UI: React markdown with `skipHtml` (`ui/src/components/ReactMarkdown.tsx`); KaTeX and mermaid output injected with `dangerouslySetInnerHTML` (`ReactMarkdownBlocks.tsx`; mermaid `securityLevel: "strict"` in `ui/src/utils/renderMermaid.ts`).

### A6 — edge worker or other client of the Edge Worker API (`providers/edge3`, mounted at `/edge_worker` only when `[edge] api_enabled`)
- `/edge_worker/v1/worker/*`, `/jobs/*`, `/logs/*` → `worker_api/auth.py:jwt_token_authorization_rest`. Shared-secret mode: `JWTValidator(secret_key=[api_auth] jwt_secret, audience="api")` plus a signed `method` claim equal to the request path. OIDC mode (`[edge] trusted_jwks_url`): JWKS + issuer/audience, then `[edge] jwt_verifier` (default authorizes any valid token; a config error if neither issuer nor verifier is set).

### A7 — local unprivileged user on an Airflow host
- Coordinator socket for Java/Node/executable tasks: `sdk/coordinators/_subprocess.py:_start_server` binds `127.0.0.1:0`; `_is_connection_from_process` accepts only connections owned by the child's process tree (psutil).
- The supervisor sets `PR_SET_DUMPABLE=0` before forking the task and again in the exec bootstrap (`sdk/execution_time/supervisor.py`, Linux only).
- The generated `airflow.cfg` (fernet key, JWT secret) is made group/other-inaccessible (`core/configuration.py:write_default_airflow_configuration_if_needed` → `make_group_other_inaccessible`); `[core] daemon_umask` `0o077`. SimpleAuthManager passwords: plaintext JSON `AIRFLOW_HOME/simple_auth_manager_passwords.json.generated`, printed to stdout/logs on first init (`SimpleAuthManager.init`).
- `airflowctl` stores its token in the OS keyring, or in a debug JSON file with `--skip-keyring` (`airflow-ctl/src/airflowctl/api/client.py:Credentials.save`).

### A8 — malicious external system, data or identity provider
- Provider hooks parse responses and files from external systems (out of view; ~457 k lines of provider source). Keycloak and SAML responses (A1). Remote JWKS fetched with httpx when `[api_auth] trusted_jwks_url` is set (`api/auth/tokens.py:JWKS._fetch_remote_jwks`). Git Dag bundles (`providers/git`, out of view).

### A9 — plugin and provider authors
- Trusted by the docs. Their FastAPI apps, root middlewares, macros, timetables, listeners and extra links run in the API server/scheduler (`core/plugins_manager.py`; plugins from entry points and `[core] plugins_folder`).

### SDK callers
`task-sdk`, `go-sdk`, `java-sdk`, `ts-sdk` public APIs are called by Dag-author code; their runtime inputs come from the supervisor/coordinator channel and the Execution API. An application embedding them is outside the system.

**Entry points summarised rather than listed one by one**: 134 routes in `api/core_api/routes/public/*.py`, 34 in `routes/ui/*.py`, 62 in `api/execution_api/routes/*.py`, 14 in `providers/fab/.../api_fastapi/routes/*.py`, 18 in `providers/edge3/.../worker_api/routes/*.py` — their access rule is stated per router above. FAB Flask views under `/auth/` and the Flower UI are out of view.

## assets

**Credentials and keys** (where loaded):
- JWT signing key — `[api_auth] jwt_secret` (HS512 by default), or `[api_auth] jwt_private_key_path` (RS256/EdDSA, JWKS built from it), or `[api_auth] trusted_jwks_url` (validation only) (`api/auth/tokens.py:get_signing_args`, `get_sig_validation_args`). Signs user, Execution, workload, callback and Dag-processor tokens and, for edge3, worker tokens. Generated into `airflow.cfg` when the config file is first written (`configuration.py`); the Execution API refuses an empty one (`make_secret_key_if_needed=False`); the core API generates a per-process one with a warning (`get_signing_key`).
- `[api] secret_key` — signs log-server JWTs (`file_task_handler.py:_fetch_logs_from_service`, `log_server.py`) and `file_token`s (`app.state.secret_key`, `core_api/app.py:init_config`); default expands `configuration.py:SECRET_KEY` (random per process; whether the generated `airflow.cfg` persists it not verified).
- Fernet key `[core] fernet_key` (encrypts connection/variable values at rest), metadata DB URI `[database] sql_alchemy_conn`, secrets-backend kwargs `[secrets] backend_kwargs` / `[workers] secrets_backend_kwargs`, Keycloak client secret, Celery broker/result URIs, Flower basic auth — all marked `sensitive` in `core/config_templates/config.yml` or provider config.
- Connection passwords/extras and Variables (DB, Fernet-encrypted, or a secrets backend). REST responses redact password and extras (`core_api/datamodels/connections.py:ConnectionResponse.redact_*`); variable values are masked only when the key name looks sensitive (`datamodels/variables.py:VariableResponse.redact_val` → `redact(val, key)`). The Execution API returns them in clear (A4).
- User JWTs in the `_token` cookie / bearer header; revocation table `RevokedToken`; SimpleAuthManager password file; Keycloak access/refresh/id tokens in cookies (`providers/keycloak/.../routes/login.py`).

**Capabilities**: code execution on workers (Dag authors; connection-configuring users for some providers per security_model.rst); triggering, clearing, marking Dags/TIs; creating asset events (which trigger asset-scheduled Dags); reparsing files; connection tests on workers.

**Integrity**: serialized Dags and Dag code in the DB (written by the DFP); scheduler decisions; task state (`ti:self`); audit log (`action_logging()` dependencies, `api/logging/decorators.py`); shipped artefacts (PyPI, Docker Hub image, Helm chart, npm/Maven SDKs).

**Trust boundaries and where enforced**:
1. Browser/REST client → API server: `get_user` + `requires_access_*` (`api/core_api/security.py`). CORS middleware only when origins/methods/headers are configured; a `*` origin aborts start-up (`core_api/app.py:init_config`).
2. Worker → API server: `/execution` `JWTBearer` + `require_auth` (`api/execution_api/security.py`). DFP and triggerer do not cross it; they use the in-process transport.
3. Task process → supervisor: msgpack frames decoded by `msgspec` into typed frames and validated by pydantic `TypeAdapter(ToTask)` (`sdk/execution_time/comms.py`); coordinator TCP loopback + process-tree check (A7).
4. API server → worker log server: HTTP to the TI's recorded hostname with a `filename`-bound JWT (A1/A4).
5. DFP → DB → scheduler/API server: serialized-Dag decoding restrictions (A5).
6. Worker-side deserialization: `sdk/serde/__init__.py:deserialize` imports a class only if it matches `[core] allowed_deserialization_classes` (glob via `fnmatch`, default `airflow.*`) or `allowed_deserialization_classes_regexp` (`fullmatch`), or has a registered deserializer.
7. Edge worker → API server: `edge3/worker_api/auth.py` (A6).
8. Plugins/providers ↔ core: none (in-process, trusted).

## out-of-scope
What follows reports the repositories' own statements and exempts nothing from the audit.


From the repositories' own documents (quoted or closely paraphrased):
- `.github/SECURITY.md`: "Airflow is not designed to be used by untrusted users, and some trusted users are trusted enough to do a variety of operations that could be considered as vulnerabilities in other products/circumstances"; read the security model first; dependency-scan results for the reference Docker image are ignored; "the issues found and fixed in providers do not apply to the Airflow core package"; third-party providers are handled by their publishers.
- `airflow-core/docs/security/security_model.rst` "What is NOT considered a security vulnerability": Dag authors executing arbitrary code (workers, DFP, triggerer, including DB access); Dag-author code passing unsanitized input to operators/hooks — SQL/command injection counts only if "triggered by a **non-Dag-author** user role ... **without** the Dag author deliberately writing code that passes that input unsafely" (exception: official docs recommending an injectable pattern); DFP and triggerer DB access and JWT bypass via the in-process transport are "intentional architectural choices". (The rest of that section was not read in full.)
- Same document, conceded limitations: the Execution JWT "does **not** carry per-Dag authorization" — a task can trigger/clear Dag runs and read/write variables, connections and XComs of any Dag; `ti:self` "is not a per-Dag access control"; no cross-workload isolation in the Execution API; multi-team "does not yet guarantee task-level isolation"; DFP/Triggerer software guards do not stop intentional access (same Unix user: `/proc/<pid>/environ`, config files, `_CMD` options, secrets managers); in symmetric mode anyone holding `jwt_secret` can forge tokens; Dag authors can leak configuration through logs; edge3 workers must hold `[api_auth] jwt_secret`, so edge hosts are "part of the control-plane trust boundary"; the audit-log permission shows logs of all Dags; the Trigger-Dag permission does not cover asset-triggered runs ("anyone who has capability to create those assets"); historical `GET /api/v2/dagSources/{dag_id}?version_number=` is scoped by current file membership — keep one Dag per file or restrict `DagAccessEntity.CODE`; `DagAccessEntity.VERSION` alone reveals which parts of a stored Dag differ, values only with CODE.
- Same document, user capabilities: Admin and Op users can execute code on workers via connections and can cause API-server DoS; "Connection configuration users" have write-only access to credentials and may set options leading to RCE for some providers — "highly trusted"; Viewers read task logs; only admins see audit logs by default.
- Same document, required of the Deployment Manager: TLS/VPC, rate limiting, authentication and authorization in front of the web application, unusual-activity detection, session backend and timeouts; protect and review Dag bundle submission ("Airflow does not provide any tooling or mechanisms around it"); keep Dag authors away from the plugins folder; restrict secrets per component (its table: workers get neither DB URI nor JWT key); prefer asymmetric JWT keys; network isolation. "Airflow doesn't support unauthenticated users by default. If allowed, potential vulnerabilities must be assessed and addressed by the Deployment Manager", with `/api/v2/monitor/health` and `/login` as the intended exceptions.
- `simple_auth_manager.py` class docstring: "This auth manager should not be used in production ... only intended for development and testing purposes" (it logs a warning when the deployment looks production-like, `_looks_like_production`).
- `chart/values.yaml`: `jwtSecret` "not advised to use in production as during helm upgrade it will be changed"; "Do not set config containing secrets via plain text values".
- AGENTS.md "Security Model": separates actual vulnerabilities from documented "Known limitations" and "Deployment hardening opportunities" (cited as evidence only).
- `execution_api/routes/connections.py:has_connection_access` and `variables.py:has_variable_access` comments: always True until "true multi-tenancy".

## production

One line per top-level area (from packaging, CI, image and chart):
- `airflow-core/src/` — production (`apache-airflow-core`: API server, scheduler, DFP, triggerer, UI build, migrations). `airflow-core/src/airflow/example_dags/` ships and loads when `[core] load_examples` (default True; chart sets False). `airflow-core/tests/`, `docs/`, `newsfragments/`, `adr/`, `3rd-party-licenses/` — tests/docs.
- `task-sdk/src/` — production (`apache-airflow-task-sdk`, on every worker); `task-sdk/tests` — tests.
- `providers/*/src/` — production, each published separately (`providers/*/pyproject.toml`); `providers/*/tests/` (incl. system tests) and `docs/` — tests/docs. Only cited providers read; the rest listed only.
- `shared/*/src/` — production, symlinked into core and task-sdk; `shared/*/tests` — tests.
- `airflow-ctl/src/` — production CLI (`apache-airflow-ctl`); `airflow-ctl/tests`, `airflow-ctl-tests/` — tests.
- `chart/` — production Helm chart (`templates/`, `values.yaml`, `files/`, `charts/`); `chart/tests`, `chart/docs` — tests/docs; `chart/dockerfiles`, `chart/kustomize-overlays` — listed only, unclassified.
- `Dockerfile` — production image; `scripts/docker/` — production (embedded into the image: `entrypoint_prod.sh`, `clean-logs.sh`, install scripts); `Dockerfile.ci` — CI image.
- `go-sdk/`, `java-sdk/`, `ts-sdk/` — production libraries for Dag authors (listed; entry files read only); their `example/`, `dags/`, `scala_spark_example/` and tests — examples/tests.
- `clients/python/` — production (`apache-airflow-client`, generated from the OpenAPI spec at release; only build config is in-tree).
- `scripts/systemd/` — shipped sample unit files (deployment example).
- `registry/` — published static website (Eleventy; `registry-build.yml` to S3), not part of the runtime.
- `scripts/ci`, `scripts/in_container`, `scripts/tools`, `scripts/cov`, `scripts/tests` — CI/dev tooling.
- `dev/` — release and dev tooling (breeze, release scripts); `devel-common/` — shared test fixtures.
- `airflow-e2e-tests/`, `docker-tests/`, `kubernetes-tests/`, `task-sdk-integration-tests/`, `performance/` — tests/benchmarks.
- `docs/`, `docker-stack-docs/`, `providers-summary-docs/`, `contributing-docs/`, root `*.md`/`*.rst` — documentation.
- `.github/` — CI (secrets used: `GITHUB_TOKEN`, `DOCKERHUB_TOKEN`, `DOCS_AWS_*`, `SLACK_BOT_TOKEN`, `CODECOV_TOKEN`, `CONSTRAINTS_GITHUB_REPOSITORY`; `pull_request_target` only in `java-sdk-dependabot-verification-metadata.yml`).
- `.agents/`, `.claude/`, `.apache-magpie-overrides/`, `.devcontainer/` — agent/dev tooling.
- `constraints/`, `generated/`, `manifests/`, `empty/`, `docker-context-files/` — build metadata/placeholders.

## facts

**Security policy** — `.github/SECURITY.md` (report to security@airflow.apache.org); security model `airflow-core/docs/security/security_model.rst` and `jwt_token_authentication.rst` (latter not read); per-provider `providers/*/docs/security.rst`.

**Template engines and escaping**
- Task templates: `sdk/definitions/_internal/templater.py:create_template_env` — `SandboxedEnvironment` by default; `NativeEnvironment` (not sandboxed) when `render_template_as_native_obj`; `is_safe_attribute` relaxed to allow `_x` names (blocks only Jinja-internal attributes); no autoescape set. Rendered on workers.
- Log filename template: `core/utils/log/task_log_address.py` `jinja2.Environment(autoescape=False)` (renders a path).
- API server `index.html`: Starlette `Jinja2Templates` (`core_api/app.py`, `simple_auth_manager.py:get_fastapi_app`); its autoescape default is library behaviour, not verified (Starlette 1.8.0 in `uv.lock`).
- UI: React 19 JSX escaping; raw HTML only from KaTeX/mermaid output (`ReactMarkdownBlocks.tsx`); markdown `skipHtml`.

**Serialization formats and loaders**
- JSON for REST, Execution API, serialized Dags (`BaseSerialization`, decoding rules in A5) and XCom (`models/xcom.py` `XComEncoder`/`XComDecoder`).
- Worker `serde` allow-list (boundary 6); the default `airflow.*` admits any importable class under `airflow.` that has a deserializer, is a dataclass/attrs class or has a `deserialize` method.
- `TaskInstance.executor_config`: `ExecutorConfigType(pickler=dill)`, a SQLAlchemy `PickleType` (`core/models/taskinstance.py`, `core/utils/sqlalchemy.py`), unpickled whenever the column is loaded; writers other than the scheduler not verified.
- Supervisor comms: msgpack (`msgspec`) + pydantic (`comms.py`); Go SDK msgpack (`go-sdk/pkg/execution/frames.go`).
- YAML Dag importer: `yaml.load_all(stream, _UniqueKeySafeLoader)` (`sdk/importers/yaml_importer/parser.py`); `sdk/importers/python_importer.py` `marshal.loads` on cached bytecode.
- Celery: `accept_content ["json"]` (`providers/celery/.../executors/default_celery.py`). Migrations `0046`/`0055` use `dill`/`pickle` for one-time data conversion.
- itsdangerous `URLSafeSerializer` for `file_token`.

**Authentication and sessions**
- User JWT: `JWTGenerator`/`JWTValidator` (`api/auth/tokens.py`); claims `jti`, `iss` (if set), `aud`, `nbf`, `exp`, `iat`; validator requires `exp, iat, nbf`, audience `[api_auth] jwt_audience` else `apache-airflow` (`BaseAuthManager._get_jwt_audience`), leeway `[api_auth] jwt_leeway` 10 s; algorithm `GUESS` → HS512 (secret) / RS256 or EdDSA (private key) / the JWK's own algorithm (JWKS; `kid` required). Revocation by `jti` at logout.
- Cookie `_token`: httponly, `samesite="lax"`, `secure` when the request scheme is https or `[api] ssl_cert` is set, path from `[api] base_url` (`refresh_token.py:build_cookie_headers`, `simple/routes/login.py`; Keycloak sets httponly+secure without an explicit samesite). A bearer header takes precedence (`get_user`).
- Execution API tokens (A4); log-server tokens HS512 with `[api] secret_key`, audience `task-instance-logs`; edge3 tokens (A6); FAB Flask session + `CSRFProtect`; Keycloak OAuth code flow with state cookie; AWS SAML.

**Defaults that change exposure** (`core/config_templates/config.yml` unless noted)
- `[core] auth_manager` = SimpleAuthManager; `simple_auth_manager_users` `admin:admin` (user admin, role ADMIN; password generated); `simple_auth_manager_all_admins` False.
- `[api] host` `0.0.0.0`, `port` 8080, `enable_swagger_ui` True, `expose_config` False, `expose_stacktrace` False, `access_control_allow_origins` empty (no CORS), `ssl_cert` empty.
- `[api_auth] jwt_expiration_time` 86400, `jwt_cli_expiration_time` 3600; `[execution_api] jwt_expiration_time` 600.
- `[core] load_examples` True, `test_connection` Disabled, `multi_team` False, `dag_run_conf_overrides_params` True, `allowed_deserialization_classes` `airflow.*`, `hide_sensitive_var_conn_fields` True.
- `[logging] worker_log_server_port` 8793, `trigger_log_server_port` 8794 (all interfaces); `[scheduler] enable_health_check` False (`0.0.0.0:8974`).
- Helm (`chart/values.yaml`): `createUserJob.defaultUser` admin/admin, role Admin; bundled PostgreSQL `postgresPassword: postgres` and `data.metadataConnection` postgres/postgres with `sslmode: disable`; `fernetKey`, `apiSecretKey`, `jwtSecret` default to `randAlphaNum` (`templates/secrets/*.yaml`); Redis password random; `flower.enabled: false`; `networkPolicies.enabled: false`. `standard_airflow_environment` (DB URI, `AIRFLOW_CONN_AIRFLOW_DB`, Fernet key, `[api] secret_key`) goes into worker, DFP, triggerer, scheduler, API-server, Flower and job pods; `jwt_secret_environment` only into API server and scheduler (`templates/_helpers.yaml` and deployment templates). The chart therefore gives Celery workers the DB URI, unlike the hardening table in security_model.rst.
- Image entrypoint: optional admin creation from `_AIRFLOW_WWW_USER_*` env (`scripts/docker/entrypoint_prod.sh`).

**Build and hardening**
- Image runs as uid 50000 under `dumb-init` (`Dockerfile`). Config-file permissions and `daemon_umask` (A7). `PR_SET_DUMPABLE` in the supervisor. CORS wildcard refused. No security-header middleware (CSP, HSTS, X-Frame-Options) found under `api/`; `core_api/app.py:init_middlewares` adds only auth-manager middlewares and GZip.
- CI: CodeQL for python, javascript, actions, go, java (`.github/workflows/codeql-analysis.yml`); zizmor config `.github/zizmor.yml`; `dependency-review.yml`; `java-sdk-dependency-security.yml`; prek/pre-commit hooks (`.pre-commit-config.yaml`).

**Where routes, schemas and permissions are defined**
- REST/UI routes `api/core_api/routes/{public,ui}/*.py`, schemas `api/core_api/datamodels/`, OpenAPI `api/core_api/openapi/`; Execution API routes `api/execution_api/routes/`, schemas `datamodels/`, versions `versions/`; auth dependencies `api/core_api/security.py`, `api/execution_api/security.py`; resource/permission model `api/auth/managers/models/resource_details.py` (`DagAccessEntity`, `AccessView`) and `base_auth_manager.py`; FAB permissions `providers/fab/.../security_manager/` (out of view); permission reference `airflow-core/docs/security/api_permissions_ref.rst` (not read).
- Configuration schema `core/config_templates/config.yml`; provider config in `providers/*/provider.yaml` / `get_provider_info.py`.

**Languages** (tracked lines via `git ls-files`, generated/lock files excluded): Python ~1.89 M (core src ~159 k, task-sdk src ~46 k, providers src ~457 k, tests ~900 k, dev+scripts ~162 k); TypeScript/TSX ~205 k (UI ~119 k, ts-sdk, registry); YAML ~121 k; Go ~38 k; Kotlin ~22 k and Java ~1.4 k (java-sdk); JavaScript ~16 k; shell ~7 k.


<!-- written at these commits:
a462d683469bb9f55646b0515ef84c41e16650fb https://github.com/cx-benchmark/airflow
-->
