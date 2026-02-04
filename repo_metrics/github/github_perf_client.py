# ----------------------------
# GitHub client (REST + GraphQL) using TokenPool
# ----------------------------
import threading
import requests
from configuration import Configuration as Config
import time
from typing import List, Optional, Dict

from models.repo import ContributorInfo
from repo_metrics.github.token_pool import TokenPool
from loggers.github_client_logger import github_client_logger as logger


class GitHubPerfClient:
    def __init__(self) -> None:
        self.base = Config.github_api_base_url
        self.pool = TokenPool()

        # Cache /users/{login} lookups (thread-safe)
        self._user_profile_cache: Dict[str, dict] = {}
        self._user_profile_lock = threading.Lock()

        # Cache contributors per repository so repeated queries reuse data
        # Key includes repo identity + knobs that change the output shape.
        self._contributors_cache: Dict[tuple, List[ContributorInfo]] = {}
        self._contributors_cache_lock = threading.Lock()

        # "single-flight" tracking so concurrent requests don't refetch same repo
        self._contributors_inflight: Dict[tuple, threading.Event] = {}

    def rest_get_json(self, path: str, *, params: Optional[dict] = None) -> dict:
        tok, sess = self.pool.pick_for_rest()
        url = path if path.startswith("http") else f"{self.base}{path}"
        resp = sess.get(url, params=params, timeout=30)

        # rate limited?
        is_rl = resp.status_code in (403, 429) and (
            resp.headers.get("X-RateLimit-Remaining") == "0" or "rate limit" in resp.text.lower()
        )
        if is_rl:
            self.pool.mark_rest_rate_limited(tok, resp)

            # retry once with another token
            tok2, sess2 = self.pool.pick_for_rest()
            if tok2 != tok:
                resp2 = sess2.get(url, params=params, timeout=30)
                is_rl2 = resp2.status_code in (403, 429) and (
                    resp2.headers.get("X-RateLimit-Remaining") == "0" or "rate limit" in resp2.text.lower()
                )
                if is_rl2:
                    self.pool.mark_rest_rate_limited(tok2, resp2)
                resp = resp2

        if resp.status_code >= 400:
            logger.error(f"GitHub REST error {resp.status_code} for {path}: {resp.text[:300]}")
            raise RuntimeError(f"GitHub REST error {resp.status_code} for {path}: {resp.text[:300]}")
        return resp.json()

    def graphql(self, query: str, variables: Optional[dict] = None) -> dict:
        tok, sess = self.pool.pick_for_graphql()
        url = f"{self.base}/graphql"
        body = {"query": query, "variables": variables or {}}

        resp = sess.post(url, json=body, timeout=30)

        # HTTP rate limiting
        is_rl = resp.status_code in (403, 429) and (
            resp.headers.get("X-RateLimit-Remaining") == "0" or "rate limit" in resp.text.lower()
        )
        if is_rl:
            # treat like REST for cooldown
            self.pool.mark_rest_rate_limited(tok, resp)

            # retry once with another token (token-aware)
            tok2, sess2 = self.pool.pick_for_graphql()
            if tok2 != tok:
                resp2 = sess2.post(url, json=body, timeout=30)
                is_rl2 = resp2.status_code in (403, 429) and (
                    resp2.headers.get("X-RateLimit-Remaining") == "0" or "rate limit" in resp2.text.lower()
                )
                if is_rl2:
                    self.pool.mark_rest_rate_limited(tok2, resp2)
                tok, resp = tok2, resp2

        if resp.status_code >= 400:
            logger.error(f"GitHub GraphQL HTTP {resp.status_code}: {resp.text[:300]}")
            raise RuntimeError(f"GitHub GraphQL HTTP {resp.status_code}: {resp.text[:300]}")

        payload = resp.json()

        # GraphQL 200 + errors
        if payload.get("errors"):
            logger.error(print("[GQL ERROR]", payload["errors"]))
            msg = str(payload["errors"][0].get("message", "")).lower()
            if "rate limit" in msg or "abuse" in msg:
                # cooldown this token a bit and retry once
                with self.pool._lock:
                    st = self.pool._states[tok]
                    st.cooldown_until = max(st.cooldown_until, time.time() + 30.0)

                tok2, sess2 = self.pool.pick_for_graphql()
                resp2 = sess2.post(url, json=body, timeout=30)
                if resp2.status_code >= 400:
                    logger.error(f"GitHub GraphQL HTTP {resp2.status_code}: {resp2.text[:300]}")
                    raise RuntimeError(f"GitHub GraphQL HTTP {resp2.status_code}: {resp2.text[:300]}")
                payload2 = resp2.json()
                if payload2.get("errors"):
                    logger.error(f"GitHub GraphQL errors: {payload2['errors']}")
                    raise RuntimeError(f"GitHub GraphQL errors: {payload2['errors']}")
                payload = payload2
                tok = tok2
            else:
                logger.error(f"GitHub GraphQL errors: {payload['errors']}")
                raise RuntimeError(f"GitHub GraphQL errors: {payload['errors']}")

        data = payload.get("data", {}) or {}
        rl = data.get("rateLimit")
        if isinstance(rl, dict):
            self.pool.update_gql_budget(tok, rl)

        return data

    def get_user_profile_cached(self, login: str) -> dict:
        """
        Fetch /users/{login} with a simple in-memory cache to reduce API calls.
        Thread-safe for concurrent workers.
        """
        with self._user_profile_lock:
            cached = self._user_profile_cache.get(login.lower())
            if cached is not None:
                return cached

        profile = self.rest_get_json(f"/users/{login}")

        with self._user_profile_lock:
            # store even if empty dict to avoid retry storms
            self._user_profile_cache[login.lower()] = profile if isinstance(profile, dict) else {}
            return self._user_profile_cache[login.lower()]

    # def _fetch_user_profiles_gql(self, logins: List[str]) -> Dict[str, dict]:
    #     """
    #     Fetch user profile fields for many logins in a single GraphQL request.
    #
    #     Returns: {login_lower: {"name": ..., "company": ..., "email": ..., "site_admin": ..., "location": ...}}
    #     """
    #     # Build aliases so we can query many users in one request
    #     # GitHub GraphQL: user(login:"...") { ... }
    #     parts = []
    #     for i, login in enumerate(logins):
    #         safe_login = login.replace('"', "")  # defensive
    #         parts.append(
    #             f'u{i}: user(login: "{safe_login}") {{ '
    #             f'login name company email site_admin location '
    #             f'}}'
    #         )
    #
    #     query = (
    #         "query BatchedUsers {\n"
    #         "  rateLimit { cost remaining resetAt }\n"
    #         f"  {' '.join(parts)}\n"
    #         "}"
    #     )
    #
    #     data = self.graphql(query, variables=None)  # your token-aware graphql()
    #     out: Dict[str, dict] = {}
    #
    #     # Each alias u0/u1/... becomes a key
    #     for i, login in enumerate(logins):
    #         node = data.get(f"u{i}")
    #         if isinstance(node, dict) and node.get("login"):
    #             out[str(node["login"]).lower()] = node
    #
    #     return out

    def _fetch_user_profiles_gql(self, logins: List[str]) -> Dict[str, dict]:
        """
        Fetch profiles for a list of GitHub logins via GraphQL.

        Returns: { login_lower: {login,name,company,email,siteAdmin,location} }

        Robustness improvements:
          - uses GraphQL variables (no string interpolation issues)
          - dedupes + strips logins
          - on failure, automatically splits the batch into smaller calls
        """
        # Normalize + dedupe while preserving order
        cleaned: List[str] = []
        seen = set()
        for l in logins:
            if not l:
                continue
            s = str(l).strip()
            if not s:
                continue
            key = s.lower()
            if key in seen:
                continue
            seen.add(key)
            cleaned.append(s)

        if not cleaned:
            return {}

        def run_batch(batch: List[str]) -> Dict[str, dict]:
            # Build per-login variables: $l0, $l1, ...
            var_defs: List[str] = []
            fields: List[str] = []
            variables: Dict[str, str] = {}

            for i, login in enumerate(batch):
                v = f"l{i}"
                var_defs.append(f"${v}: String!")
                fields.append(
                    f"""
                    u{i}: user(login: ${v}) {{
                      login
                      name
                      company
                      email
                      location
                    }}
                    """
                )
                variables[v] = login

            query = f"""
            query BatchedUsers({", ".join(var_defs)}) {{
              rateLimit {{ cost remaining resetAt }}
              {"".join(fields)}
            }}
            """

            data = self.graphql(query, variables)  # returns payload["data"]

            out: Dict[str, dict] = {}
            for i, login in enumerate(batch):
                node = data.get(f"u{i}")
                # If user not found or not accessible, GraphQL returns null here (not an error)
                if isinstance(node, dict) and node.get("login"):
                    out[str(node["login"]).lower()] = node
                else:
                    out[login.lower()] = {}  # cache negative to avoid repeat work
            return out

        # Try full batch; if it fails, split recursively (keeps you moving forward)
        def run_split(batch: List[str]) -> Dict[str, dict]:
            try:
                return run_batch(batch)
            except (requests.exceptions.RequestException, RuntimeError, ValueError):
                if len(batch) <= 1:
                    return {batch[0].lower(): {}} if batch else {}
                mid = len(batch) // 2
                out = run_split(batch[:mid])
                out.update(run_split(batch[mid:]))
                return out

        return run_split(cleaned)

    def list_contributors(self, owner: str, repo: str, *, fetch_profiles: bool = True,) -> List[ContributorInfo]:
        """
        Cached + fast contributor enrichment:

          - Repo-level cache: if the same repo is requested again (e.g., many packages map to the
            same https://github.com/apache/kafka), reuse the already-fetched contributor list.
          - "Single-flight": if multiple threads request the same repo at the same time, only
            one thread performs the fetch; others wait for the cached result.

        Enrichment behavior:
          - REST: /contributors (paginated) to get contributor list
          - GraphQL: batch user(login) lookups to enrich name/company/email/siteAdmin/location
            for the top max_profile_lookups contributors (reuses self._user_profile_cache too).

        Requires these fields on the client (initialize once in __init__):
          self._contributors_cache: Dict[tuple, List[ContributorSummary]] = {}
          self._contributors_cache_lock = threading.Lock()
          self._contributors_inflight: Dict[tuple, threading.Event] = {}
          self._user_profile_cache / self._user_profile_lock (already used here)
        """
        owner_norm = owner.strip().lower()
        repo_norm = repo.strip().lower()

        # Cache key must include knobs that change output content.
        cache_key = (
            owner_norm,
            repo_norm,
            int(Config.max_contributors),
            bool(fetch_profiles),
            int(Config.max_profile_lookups),
            int(Config.gql_batch_size),
        )

        # 1) Fast path: return cached contributors if present
        with self._contributors_cache_lock:
            cached = self._contributors_cache.get(cache_key)
            if cached is not None:
                print(f"Returning cached contributors for Owner: {owner_norm}, Repo: {repo_norm}")
                return cached

            # 2) Single-flight: if in-flight, wait; else mark as in-flight and fetch
            inflight_event = self._contributors_inflight.get(cache_key)
            if inflight_event is None:
                inflight_event = threading.Event()
                self._contributors_inflight[cache_key] = inflight_event
                is_fetcher = True
            else:
                is_fetcher = False

        if not is_fetcher:
            # Wait for the fetcher to finish and populate cache
            inflight_event.wait(timeout=120)
            with self._contributors_cache_lock:
                return self._contributors_cache.get(cache_key, [])

        # We are the fetcher; compute and then cache + notify waiters.
        results: List[ContributorInfo] = []
        page = 1
        per_page = 100

        def _norm_str(v: object) -> Optional[str]:
            if isinstance(v, str):
                v = v.strip()
                return v if v else None
            return None

        try:
            # 1) Collect contributors via REST
            raw: List[dict] = []
            while len(raw) < Config.max_contributors:
                data = self.rest_get_json(
                    f"/repos/{owner}/{repo}/contributors",
                    params={"per_page": per_page, "page": page, "anon": "false"},
                )
                if not isinstance(data, list) or not data:
                    break
                raw.extend(data)
                if len(data) < per_page:
                    break
                page += 1

            raw = raw[:Config.max_contributors]

            # 2) Determine which logins to enrich
            logins_to_enrich: List[str] = []
            if fetch_profiles and Config.max_profile_lookups > 0:
                for c in raw:
                    login = c.get("login")
                    if login:
                        logins_to_enrich.append(str(login))
                    if len(logins_to_enrich) >= Config.max_profile_lookups:
                        break

            # 3) Batch-fetch profiles via GraphQL (and cache them)
            profiles_by_login: Dict[str, dict] = {}
            if logins_to_enrich:
                # Pull from cache first
                missing: List[str] = []
                with self._user_profile_lock:
                    for login in logins_to_enrich:
                        key = login.lower()
                        cached_prof = self._user_profile_cache.get(key)
                        if cached_prof is not None:
                            profiles_by_login[key] = cached_prof
                        else:
                            missing.append(login)

                # Fetch missing in GraphQL batches
                if missing:
                    # chunk missing
                    for i in range(0, len(missing), Config.gql_batch_size):
                        batch = missing[i: i + Config.gql_batch_size]

                        # Try GraphQL first (robust version now splits internally)
                        try:
                            batch_profiles = self._fetch_user_profiles_gql(batch)
                        except (requests.exceptions.RequestException, RuntimeError, ValueError) as e:
                            logger.info(f"[WARN] _fetch_user_profiles_gql failed for batch size={len(batch)}: {e}")
                            batch_profiles = {}

                        # If GraphQL returned nothing (still possible), fallback to REST /users/{login}
                        if not batch_profiles:
                            batch_profiles = {}
                            for login in batch:
                                try:
                                    # If you already have get_user_profile_cached(login) using REST, reuse it here
                                    prof = self.get_user_profile_cached(login)
                                except (requests.exceptions.RequestException, RuntimeError, ValueError) as e:
                                    logger.info(f"[WARN] get_user_profile_cached failed for batch size={len(batch)}: {e}")
                                    prof = {}
                                batch_profiles[login.lower()] = prof

                        # store in local dict + cache (store empty dicts too to prevent retry storms)
                        with self._user_profile_lock:
                            for login in batch:
                                key = login.lower()
                                prof = batch_profiles.get(key, {})
                                profiles_by_login[key] = prof
                                self._user_profile_cache[key] = prof

            # 4) Build ContributorSummary list
            for c in raw:
                login = c.get("login")
                if not login:
                    continue

                login_str = str(login)
                prof = profiles_by_login.get(login_str.lower(), {}) if fetch_profiles else {}

                results.append(
                    ContributorInfo(
                        login=login_str,
                        github_id=int(c.get("id", 0)),
                        contributions=int(c.get("contributions", 0)),
                        html_url=str(c.get("html_url", f"https://github.com/{login_str}")),
                        name=_norm_str(prof.get("name")),
                        company=_norm_str(prof.get("company")),
                        email=_norm_str(prof.get("email")),
                        #site_admin=bool(prof.get("siteAdmin", False)) or bool(prof.get("site_admin", False)),
                        location=_norm_str(prof.get("location")),
                    )
                )

            return results

        finally:
            # Cache results and release waiters (even if results is empty due to errors)
            with self._contributors_cache_lock:
                self._contributors_cache[cache_key] = results
                ev = self._contributors_inflight.pop(cache_key, None)
                if ev is not None:
                    ev.set()

    # def list_contributors(self, owner: str, repo: str, *, fetch_profiles: bool = True,) -> List[ContributorInfo]:
    #     """
    #     Faster contributor enrichment:
    #       - REST: /contributors to get contributor list (paginated)
    #       - GraphQL: batch user(login) lookups to enrich name/company/email/siteAdmin/location
    #         for the top max_profile_lookups contributors.
    #
    #     gql_batch_size: 25 is a safe default.
    #     """
    #     results: List[ContributorInfo] = []
    #     page = 1
    #     per_page = 100
    #
    #     def _norm_str(v: object) -> Optional[str]:
    #         if isinstance(v, str):
    #             v = v.strip()
    #             return v if v else None
    #         return None
    #
    #     # 1) Collect contributors via REST
    #     raw: List[dict] = []
    #     while len(raw) < Config.max_contributors:
    #         data = self.rest_get_json(
    #             f"/repos/{owner}/{repo}/contributors",
    #             params={"per_page": per_page, "page": page, "anon": "false"},
    #         )
    #         if not isinstance(data, list) or not data:
    #             break
    #         raw.extend(data)
    #         if len(data) < per_page:
    #             break
    #         page += 1
    #
    #     raw = raw[:Config.max_contributors]
    #
    #     # 2) Determine which logins to enrich
    #     logins_to_enrich: List[str] = []
    #     if fetch_profiles and Config.max_profile_lookups > 0:
    #         for c in raw:
    #             login = c.get("login")
    #             if login:
    #                 logins_to_enrich.append(str(login))
    #             if len(logins_to_enrich) >= Config.max_profile_lookups:
    #                 break
    #
    #     # 3) Batch-fetch profiles via GraphQL (and cache them)
    #     profiles_by_login: Dict[str, dict] = {}
    #     if logins_to_enrich:
    #         # Pull from cache first
    #         missing: List[str] = []
    #         with self._user_profile_lock:
    #             for login in logins_to_enrich:
    #                 cached = self._user_profile_cache.get(login.lower())
    #                 if cached is not None:
    #                     profiles_by_login[login.lower()] = cached
    #                 else:
    #                     missing.append(login)
    #
    #         # Fetch missing in GraphQL batches
    #         if missing:
    #             # chunk missing
    #             for i in range(0, len(missing), Config.gql_batch_size):
    #                 batch = missing[i: i + Config.gql_batch_size]
    #                 try:
    #                     batch_profiles = self._fetch_user_profiles_gql(batch)
    #                 except (requests.exceptions.RequestException, RuntimeError, ValueError):
    #                     batch_profiles = {}
    #
    #                 # store in local dict + cache (store empty dicts too to prevent retry storms)
    #                 with self._user_profile_lock:
    #                     for login in batch:
    #                         prof = batch_profiles.get(login.lower(), {})
    #                         profiles_by_login[login.lower()] = prof
    #                         self._user_profile_cache[login.lower()] = prof
    #
    #     # 4) Build ContributorSummary list
    #     for c in raw:
    #         login = c.get("login")
    #         if not login:
    #             continue
    #
    #         login_str = str(login)
    #         prof = profiles_by_login.get(login_str.lower(), {}) if fetch_profiles else {}
    #
    #         results.append(
    #             ContributorInfo(
    #                 login=login_str,
    #                 github_id=int(c.get("id", 0)),
    #                 contributions=int(c.get("contributions", 0)),
    #                 html_url=str(c.get("html_url", f"https://github.com/{login_str}")),
    #                 name=_norm_str(prof.get("name")),
    #                 company=_norm_str(prof.get("company")),
    #                 email=_norm_str(prof.get("email")),
    #                 site_admin=bool(prof.get("siteAdmin", False)) or bool(prof.get("site_admin", False)),
    #                 location=_norm_str(prof.get("location")),
    #             )
    #         )
    #
    #     return results

    # def list_contributors(self, owner: str, repo: str, *, fetch_profiles: bool = True,) -> List[ContributorInfo]:
    #     """
    #     REST contributors listing (paginated), optionally enriched with /users/{login}
    #     fields: name, company, email, site_admin, location.
    #
    #     Performance controls:
    #       - fetch_profiles: if False, avoids /users/{login} calls entirely
    #       - max_profile_lookups: caps how many contributor profiles we enrich per repo
    #     """
    #     results: List[ContributorInfo] = []
    #     page = 1
    #     per_page = 100
    #
    #     profile_lookups = 0
    #
    #     def _norm_str(v: object) -> Optional[str]:
    #         if isinstance(v, str):
    #             v = v.strip()
    #             return v if v else None
    #         return None
    #
    #     while len(results) < Config.max_contributors:
    #         data = self.rest_get_json(
    #             f"/repos/{owner}/{repo}/contributors",
    #             params={"per_page": per_page, "page": page, "anon": "false"},
    #         )
    #         if not isinstance(data, list) or not data:
    #             break
    #
    #         for c in data:
    #             login = c.get("login")
    #             if not login:
    #                 continue
    #
    #             # Defaults if we don't fetch profile
    #             name = None
    #             company = None
    #             email = None
    #             site_admin = False
    #             location = None
    #
    #             if fetch_profiles and profile_lookups < Config.max_profile_lookups:
    #                 try:
    #                     profile = self.get_user_profile_cached(str(login))
    #                 except (requests.exceptions.RequestException, RuntimeError, ValueError) as e:
    #                     logger.exception(e)
    #                     profile = {}
    #
    #                 name = _norm_str(profile.get("name"))
    #                 company = _norm_str(profile.get("company"))
    #                 email = _norm_str(profile.get("email"))
    #                 site_admin = bool(profile.get("site_admin", False))
    #                 location = _norm_str(profile.get("location"))
    #
    #                 profile_lookups += 1
    #
    #             results.append(
    #                 ContributorInfo(
    #                     login=str(login),
    #                     github_id=int(c.get("id", 0)),
    #                     contributions=int(c.get("contributions", 0)),
    #                     html_url=str(c.get("html_url", f"https://github.com/{login}")),
    #                     name=name,
    #                     company=company,
    #                     email=email,
    #                     site_admin=site_admin,
    #                     location=location,
    #                 )
    #             )
    #
    #             if len(results) >= Config.max_contributors:
    #                 break
    #
    #         if len(data) < per_page:
    #             break
    #         page += 1
    #
    #     return results

    # def list_contributors(self, owner: str, repo: str,) -> List[ContributorInfo]:
    #     """
    #     REST contributors listing (paginated). This is the heaviest part at scale.
    #     """
    #     results: List[ContributorInfo] = []
    #     page = 1
    #     per_page = 100
    #
    #     while len(results) < Config.max_contributors:
    #         data = self.rest_get_json(
    #             f"/repos/{owner}/{repo}/contributors",
    #             params={"per_page": per_page, "page": page, "anon": "false"},
    #         )
    #         if not isinstance(data, list) or not data:
    #             break
    #
    #         for c in data:
    #             login = c.get("login")
    #             if not login:
    #                 continue
    #             results.append(
    #                 ContributorInfo(
    #                     login=str(login),
    #                     github_id=int(c.get("id", 0)),
    #                     contributions=int(c.get("contributions", 0)),
    #                     html_url=str(c.get("html_url", f"https://github.com/{login}")),
    #                 )
    #             )
    #             if len(results) >= Config.max_contributors:
    #                 break
    #
    #         if len(data) < per_page:
    #             break
    #         page += 1
    #
    #     return results
