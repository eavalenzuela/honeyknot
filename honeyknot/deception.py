"""Responses that look like a vulnerable host, so the attack proceeds.

A honeypot that answers every probe with `404` collects the first packet of
every attack and the last packet of none. The interesting bytes — the
dropper URL, the miner config, the container spec, the second-stage
webshell — only arrive if the attacker believes step one worked.

So this module is a catalogue of *convincing failures*: an `.env` that
returns database credentials, a `?cmd=id` that answers `uid=0(root)`, a
Docker socket that accepts a container create, an admin form that takes a
password. None of it is real. Nothing is executed; shell-looking output
comes from `honeyknot.shell`'s table-driven emulator, and every secret is a
canary token.

Canary tokens
-------------
Every credential this module hands out is derived from a per-deployment
seed (`[http] canary_seed`, defaulting to the configured hostname). They
are structurally valid — `AKIA` prefix, 40-character secret, plausible
password — because a token that obviously reads as fake gets discarded
instead of used. The point is the reverse of secrecy: if one of these
strings ever turns up in a paste dump, a credential-stuffing list, or an
authentication log on a real system, that's proof of where it came from
and roughly when it was taken. `canary_token` is deterministic, so the same
deployment always issues the same token and a hit is attributable.

They authenticate nothing, anywhere. There is no account behind them.

Design note: `respond()` returns None when no deception route matches, and
the caller falls through to the handler's configured TOML rules. Operator
config always wins over anything invented here.
"""

from __future__ import annotations

import base64
import hashlib
import html
import json
import re
import urllib.parse
from dataclasses import dataclass, field

MAX_BODY_ECHO = 4096


@dataclass
class WebResponse:
    """One deception reply plus whatever it's worth telling the operator."""
    status: str = "200 OK"
    body: bytes = b""
    content_type: str = "text/html; charset=UTF-8"
    extra_headers: list[str] = field(default_factory=list)
    events: list[tuple[str, dict]] = field(default_factory=list)
    close: bool = False


# --------------------------------------------------------------------------
# Canary tokens
# --------------------------------------------------------------------------

_B32 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"


def canary_token(kind: str, seed: str) -> str:
    """A deterministic, structurally-plausible fake secret.

    `kind` selects the shape (`aws_key`, `aws_secret`, `password`, `hex`,
    `api_key`); `seed` scopes it to this deployment.
    """
    digest = hashlib.sha256(f"honeyknot:{seed}:{kind}".encode()).digest()
    if kind == "aws_key":
        return "AKIA" + "".join(_B32[b % 32] for b in digest[:16])
    if kind == "aws_secret":
        return base64.b64encode(digest)[:40].decode()
    if kind == "password":
        words = ("Summer", "Winter", "Dragon", "Falcon", "Marble", "Copper",
                 "Velvet", "Quartz")
        word = words[digest[0] % len(words)]
        return f"{word}{digest[1] % 100:02d}{digest[2] % 100:02d}!"
    if kind == "api_key":
        return digest.hex()[:32]
    return digest.hex()[:40]


# --------------------------------------------------------------------------
# Static decoy content
# --------------------------------------------------------------------------

def _env_file(seed: str, host: str) -> bytes:
    return (
        "APP_NAME=Laravel\n"
        "APP_ENV=production\n"
        "APP_DEBUG=false\n"
        f"APP_KEY=base64:{canary_token('api_key', seed)}==\n"
        f"APP_URL=http://{host}\n\n"
        "DB_CONNECTION=mysql\n"
        "DB_HOST=127.0.0.1\n"
        "DB_PORT=3306\n"
        "DB_DATABASE=app_production\n"
        "DB_USERNAME=app_rw\n"
        f"DB_PASSWORD={canary_token('password', seed)}\n\n"
        "REDIS_HOST=127.0.0.1\n"
        "REDIS_PORT=6379\n\n"
        "MAIL_MAILER=smtp\n"
        "MAIL_HOST=smtp.mailtrap.io\n"
        "MAIL_USERNAME=noreply@example.com\n"
        f"MAIL_PASSWORD={canary_token('password', seed + ':mail')}\n\n"
        f"AWS_ACCESS_KEY_ID={canary_token('aws_key', seed)}\n"
        f"AWS_SECRET_ACCESS_KEY={canary_token('aws_secret', seed)}\n"
        "AWS_DEFAULT_REGION=us-east-1\n"
        "AWS_BUCKET=app-production-assets\n"
    ).encode()


def _git_config(host: str) -> bytes:
    return (
        "[core]\n"
        "\trepositoryformatversion = 0\n"
        "\tfilemode = true\n"
        "\tbare = false\n"
        "\tlogallrefupdates = true\n"
        "[remote \"origin\"]\n"
        f"\turl = https://git.{host}/platform/webapp.git\n"
        "\tfetch = +refs/heads/*:refs/remotes/origin/*\n"
        "[branch \"main\"]\n"
        "\tremote = origin\n"
        "\tmerge = refs/heads/main\n"
    ).encode()


def _wp_config(seed: str) -> bytes:
    return (
        "<?php\n"
        "define( 'DB_NAME', 'wordpress' );\n"
        "define( 'DB_USER', 'wp_admin' );\n"
        f"define( 'DB_PASSWORD', '{canary_token('password', seed + ':wp')}' );\n"
        "define( 'DB_HOST', 'localhost' );\n"
        "define( 'DB_CHARSET', 'utf8mb4' );\n"
        f"define( 'AUTH_KEY',  '{canary_token('hex', seed + ':auth')}' );\n"
        f"define( 'SECURE_AUTH_KEY',  '{canary_token('hex', seed + ':sauth')}' );\n"
        f"define( 'LOGGED_IN_KEY',  '{canary_token('hex', seed + ':login')}' );\n"
        "$table_prefix = 'wp_';\n"
        "define( 'WP_DEBUG', false );\n"
        "require_once ABSPATH . 'wp-settings.php';\n"
    ).encode()


def _aws_credentials(seed: str) -> bytes:
    return (
        "[default]\n"
        f"aws_access_key_id = {canary_token('aws_key', seed)}\n"
        f"aws_secret_access_key = {canary_token('aws_secret', seed)}\n"
        "region = us-east-1\n"
    ).encode()


def _server_status(host: str) -> bytes:
    return (
        "<html><head><title>Apache Status</title></head><body>"
        f"<h1>Apache Server Status for {html.escape(host)}</h1>\n"
        "<dl><dt>Server Version: Apache/2.4.41 (Ubuntu) OpenSSL/1.1.1f</dt>\n"
        "<dt>Server MPM: prefork</dt>\n"
        "<dt>Server Built: 2020-08-12T21:33:25</dt></dl><hr>\n"
        "<dl><dt>Current Time: Monday, 06-Jan-2020 12:04:31 UTC</dt>\n"
        "<dt>Parent Server Config. Generation: 1</dt>\n"
        "<dt>Total accesses: 184213 - Total Traffic: 2.1 GB</dt>\n"
        "<dt>1 requests currently being processed, 9 idle workers</dt></dl>\n"
        "<pre>_W_.____........................................................\n"
        "................................................................</pre>\n"
        "</body></html>"
    ).encode()


def _phpinfo(host: str) -> bytes:
    return (
        "<!DOCTYPE html><html><head><title>phpinfo()</title></head><body>"
        "<h1 class=\"p\">PHP Version 7.4.3</h1>\n"
        "<table><tr><td class=\"e\">System</td><td class=\"v\">"
        f"Linux {html.escape(host)} 5.4.0-42-generic #46-Ubuntu SMP x86_64</td></tr>\n"
        "<tr><td class=\"e\">Server API</td><td class=\"v\">FPM/FastCGI</td></tr>\n"
        "<tr><td class=\"e\">Loaded Configuration File</td>"
        "<td class=\"v\">/etc/php/7.4/fpm/php.ini</td></tr>\n"
        "<tr><td class=\"e\">disable_functions</td><td class=\"v\">"
        "<i>no value</i></td></tr>\n"
        "<tr><td class=\"e\">allow_url_fopen</td><td class=\"v\">On</td></tr>\n"
        "<tr><td class=\"e\">allow_url_include</td><td class=\"v\">Off</td></tr>\n"
        "<tr><td class=\"e\">DOCUMENT_ROOT</td><td class=\"v\">/var/www/html</td></tr>\n"
        "</table></body></html>"
    ).encode()


def _actuator_env(seed: str) -> bytes:
    return json.dumps({
        "activeProfiles": ["prod"],
        "propertySources": [
            {"name": "systemEnvironment", "properties": {
                "SPRING_DATASOURCE_URL": {
                    "value": "jdbc:mysql://db.internal:3306/app"},
                "SPRING_DATASOURCE_USERNAME": {"value": "app_rw"},
                "SPRING_DATASOURCE_PASSWORD": {
                    "value": canary_token("password", seed + ":spring")},
                "AWS_ACCESS_KEY_ID": {
                    "value": canary_token("aws_key", seed + ":spring")},
            }},
            {"name": "applicationConfig: [classpath:/application.yml]",
             "properties": {"server.port": {"value": "8080"}}},
        ],
    }, indent=2).encode()


def _login_form(title: str, action: str) -> bytes:
    safe_title = html.escape(title)
    safe_action = html.escape(action)
    return (
        f"<!DOCTYPE html><html><head><title>{safe_title}</title></head>"
        f"<body><div id=\"login\"><h1>{safe_title}</h1>"
        f"<form name=\"loginform\" id=\"loginform\" action=\"{safe_action}\" "
        "method=\"post\">"
        "<p><label>Username<br><input type=\"text\" name=\"log\" "
        "id=\"user_login\" size=\"20\"></label></p>"
        "<p><label>Password<br><input type=\"password\" name=\"pwd\" "
        "id=\"user_pass\" size=\"20\"></label></p>"
        "<p class=\"submit\"><input type=\"submit\" name=\"wp-submit\" "
        "id=\"wp-submit\" value=\"Log In\"></p>"
        "</form></div></body></html>"
    ).encode()


# --------------------------------------------------------------------------
# Command-execution surfaces
#
# Every parameter name below is one that a real webshell or a real RCE
# exploit uses. Pulling the command out and running it through the shell
# emulator is what converts "someone probed us" into "here is the loader
# they would have run, and the URL it fetches from".
# --------------------------------------------------------------------------

# Deliberately excludes `s`, `q`, and `query`: those are ordinary search
# parameters on real sites, and `s` in particular is ThinkPHP's *route*
# parameter, which would shadow the actual command in `vars[1][]`.
_CMD_PARAMS = ("cmd", "command", "exec", "execute", "shell", "run", "system",
               "cmdline", "c", "e", "x")

_PHP_EXEC_RE = re.compile(
    rb"(?:system|shell_exec|passthru|exec|popen|proc_open)\s*\(\s*"
    rb"['\"]([^'\"]{1,400})['\"]")
_PHP_ECHO_RE = re.compile(rb"echo\s+['\"]([^'\"]{1,200})['\"]")
_THINKPHP_CMD_RE = re.compile(r"vars\[1\]\[\]?=?([^&]{1,400})")


def extract_command(path: str, body: bytes) -> str | None:
    """Pull an attacker-supplied command out of a request, if there is one.

    Handles query parameters, form bodies, PHP source posted to an
    `eval`-style endpoint (PHPUnit's `eval-stdin.php`), and ThinkPHP's
    `invokefunction` argument vector.
    """
    query = urllib.parse.urlsplit(path).query
    for source in (query, body[:MAX_BODY_ECHO].decode("latin-1")):
        if not source:
            continue
        # ThinkPHP first: its argument vector is the command, while its `s`
        # route parameter would otherwise look like one.
        m = _THINKPHP_CMD_RE.search(urllib.parse.unquote_plus(source))
        if m:
            return m.group(1)
        try:
            params = urllib.parse.parse_qs(source, keep_blank_values=False)
        except ValueError:
            params = {}
        for key in _CMD_PARAMS:
            if key in params and params[key] and params[key][0].strip():
                return params[key][0]

    m = _PHP_EXEC_RE.search(body[:MAX_BODY_ECHO])
    if m:
        return m.group(1).decode("latin-1")
    m = _PHP_ECHO_RE.search(body[:MAX_BODY_ECHO])
    if m:
        return "echo " + m.group(1).decode("latin-1")
    return None


def extract_shellshock(headers: dict[str, str]) -> str | None:
    """Return the command smuggled in a Shellshock-style header value."""
    for name, value in headers.items():
        if name.startswith(":"):
            continue
        idx = value.find("() {")
        if idx == -1:
            continue
        rest = value[idx:]
        semi = rest.find("};")
        if semi != -1:
            return rest[semi + 2:].strip()
        semi = rest.find(";")
        if semi != -1:
            return rest[semi + 1:].strip()
    return None


# --------------------------------------------------------------------------
# The site
# --------------------------------------------------------------------------

class DeceptionSite:
    """Route table for vulnerable-looking HTTP responses.

    One instance per port, constructed from `[http]` options. It holds no
    per-connection state — the shell session it executes against is passed
    in by the caller and lives on the connection context.
    """

    def __init__(self, opts: dict | None = None):
        opts = opts or {}
        self.profile = opts.get("profile", "generic")
        self.hostname = opts.get("hostname", "srv-web-01")
        self.seed = opts.get("canary_seed", self.hostname)
        self.server = opts.get("server", _DEFAULT_SERVER.get(
            self.profile, "nginx/1.18.0 (Ubuntu)"))
        self.docker_version = opts.get("docker_version", "20.10.7")
        self.es_version = opts.get("elasticsearch_version", "6.8.6")

    # -- entry point -------------------------------------------------------

    def respond(self, method: str, path: str, headers: dict[str, str],
                body: bytes, shell) -> WebResponse | None:
        """Return a deception response, or None to fall through to config."""
        route = urllib.parse.urlsplit(path).path or "/"
        low = route.lower()

        # 1. Command execution beats everything: if the request carries a
        #    command anywhere, running it is more valuable than serving the
        #    decoy file the path would otherwise map to.
        shellshock = extract_shellshock(headers)
        if shellshock:
            return self._exec(shellshock, shell, vector="shellshock",
                              path=route)
        if _is_exec_surface(low, method, body):
            command = extract_command(path, body)
            if command:
                return self._exec(command, shell, vector="webshell", path=route)

        # 2. Secret-bearing decoy files.
        static = self._static_route(low)
        if static is not None:
            return static

        # 3. Authentication surfaces that harvest credentials.
        auth = self._auth_route(method, low, headers, body)
        if auth is not None:
            return auth

        # 4. Profile-specific API surfaces.
        api = self._api_route(method, route, body)
        if api is not None:
            return api

        return None

    # -- routes ------------------------------------------------------------

    def _static_route(self, low: str) -> WebResponse | None:
        if re.fullmatch(r"/\.env(\.[a-z]+)?", low):
            return WebResponse(
                body=_env_file(self.seed, self.hostname),
                content_type="text/plain; charset=UTF-8",
                events=[("secret_served", {"artifact": "dotenv", "path": low})])
        if low.startswith("/.git/"):
            if low.endswith("/head"):
                return WebResponse(body=b"ref: refs/heads/main\n",
                                   content_type="text/plain")
            return WebResponse(
                body=_git_config(self.hostname),
                content_type="text/plain; charset=UTF-8",
                events=[("secret_served", {"artifact": "git_config",
                                           "path": low})])
        if low.startswith("/.aws/") or low.endswith("/credentials"):
            return WebResponse(
                body=_aws_credentials(self.seed),
                content_type="text/plain; charset=UTF-8",
                events=[("secret_served", {"artifact": "aws_credentials",
                                           "path": low})])
        if re.match(r"^/wp-config\.php(\.(bak|old|save|orig|txt)|~)?$", low):
            return WebResponse(
                body=_wp_config(self.seed),
                content_type="text/plain; charset=UTF-8",
                events=[("secret_served", {"artifact": "wp_config",
                                           "path": low})])
        if low in ("/server-status", "/server-info"):
            return WebResponse(body=_server_status(self.hostname))
        if low in ("/phpinfo.php", "/info.php", "/php_info.php", "/i.php"):
            return WebResponse(body=_phpinfo(self.hostname))
        if low == "/robots.txt":
            return WebResponse(
                body=b"User-agent: *\nDisallow: /admin/\nDisallow: /backup/\n"
                     b"Disallow: /.git/\nDisallow: /api/internal/\n",
                content_type="text/plain")
        if low.startswith("/actuator"):
            return self._actuator(low)
        return None

    def _actuator(self, low: str) -> WebResponse:
        if low in ("/actuator", "/actuator/"):
            base = f"http://{self.hostname}:8080/actuator"
            return WebResponse(
                body=json.dumps({"_links": {
                    name: {"href": f"{base}/{name}", "templated": False}
                    for name in ("self", "health", "env", "beans", "mappings",
                                 "configprops", "heapdump", "threaddump")
                }}).encode(),
                content_type="application/vnd.spring-boot.actuator.v3+json")
        if low.startswith("/actuator/health"):
            return WebResponse(
                body=b'{"status":"UP","groups":["liveness","readiness"]}',
                content_type="application/vnd.spring-boot.actuator.v3+json")
        if low.startswith("/actuator/env"):
            return WebResponse(
                body=_actuator_env(self.seed),
                content_type="application/vnd.spring-boot.actuator.v3+json",
                events=[("secret_served", {"artifact": "actuator_env",
                                           "path": low})])
        return WebResponse(
            status="200 OK", body=b"{}",
            content_type="application/vnd.spring-boot.actuator.v3+json")

    def _auth_route(self, method: str, low: str, headers: dict[str, str],
                    body: bytes) -> WebResponse | None:
        basic = headers.get("authorization", "")
        needs_basic = low.startswith(("/manager/", "/host-manager/",
                                      "/cgi-bin/luci", "/admin/config"))
        if needs_basic:
            if basic.lower().startswith("basic "):
                events = []
                user, password = _decode_basic(basic)
                if user is not None:
                    events.append(("credentials", {
                        "service": "http", "username": user,
                        "password": password, "auth": "basic", "path": low}))
                # 403 rather than 401: a second challenge just makes the tool
                # retry the same pair, while "authenticated but forbidden"
                # pushes it to try a different account.
                return WebResponse(
                    status="403 Forbidden",
                    body=b"<html><head><title>403 Access Denied</title></head>"
                         b"<body><h1>403 Access Denied</h1><p>You are not "
                         b"authorized to view this page.</p></body></html>",
                    events=events)
            return WebResponse(
                status="401 Unauthorized",
                body=b"<html><head><title>401 Unauthorized</title></head>"
                     b"<body><h1>401 Unauthorized</h1></body></html>",
                extra_headers=['WWW-Authenticate: Basic realm="Tomcat Manager '
                               'Application"'])

        login_paths = ("/wp-login.php", "/wp-admin", "/wp-admin/",
                       "/administrator/index.php", "/admin", "/admin/",
                       "/admin/login", "/login", "/login.php", "/user/login",
                       "/boaform/admin/formlogin", "/cgi-bin/luci")
        if low in login_paths or low.startswith("/wp-admin/"):
            if method == "POST":
                creds = _form_credentials(body)
                events = []
                if creds:
                    events.append(("credentials", {
                        "service": "http", "username": creds[0],
                        "password": creds[1], "auth": "form", "path": low}))
                return WebResponse(
                    status="200 OK",
                    body=b"<html><body><div id=\"login_error\"><strong>Error"
                         b"</strong>: The password you entered is incorrect."
                         b"</div></body></html>",
                    events=events)
            title = "Log In" if "wp-" in low else "Administration Login"
            return WebResponse(body=_login_form(title, low))
        return None

    def _api_route(self, method: str, route: str,
                   body: bytes) -> WebResponse | None:
        low = route.lower()

        # `/version` and `/info` are Docker's endpoints but also perfectly
        # ordinary paths on a web app, so answering them with Docker JSON on
        # a generic site would be a tell. Off-profile, only the paths that
        # mean nothing else get the Docker treatment.
        if self.profile == "docker" or low.startswith("/v1.") \
                or _DOCKER_UNAMBIGUOUS_RE.match(low):
            resp = self._docker(method, low, body)
            if resp is not None:
                return resp

        if self.profile == "elasticsearch" or low.startswith(
                ("/_cluster", "/_cat", "/_nodes", "/_search")):
            resp = self._elasticsearch(method, low)
            if resp is not None:
                return resp

        if self.profile == "generic" and low == "/":
            return WebResponse(body=_INDEX_HTML.format(
                h=html.escape(self.hostname)).encode())
        return None

    def _docker(self, method: str, low: str, body: bytes) -> WebResponse | None:
        # Strip the optional /v1.41 API-version prefix.
        path = re.sub(r"^/v\d+\.\d+", "", low) or "/"
        if path == "/version":
            return WebResponse(body=json.dumps({
                "Version": self.docker_version, "ApiVersion": "1.41",
                "MinAPIVersion": "1.12", "GitCommit": "b0f5bc3",
                "GoVersion": "go1.13.15", "Os": "linux", "Arch": "amd64",
                "KernelVersion": "5.4.0-42-generic",
            }).encode(), content_type="application/json")
        if path == "/info":
            return WebResponse(body=json.dumps({
                "ID": "H4KL:2NQZ:6TYU:ABCD", "Containers": 3,
                "ContainersRunning": 2, "Images": 7, "Driver": "overlay2",
                "MemTotal": 8232517632, "NCPU": 4,
                "Name": self.hostname, "ServerVersion": self.docker_version,
                "OperatingSystem": "Ubuntu 20.04.1 LTS",
                "DockerRootDir": "/var/lib/docker",
            }).encode(), content_type="application/json")
        if path in ("/containers/json", "/images/json"):
            return WebResponse(body=json.dumps(
                _DOCKER_CONTAINERS if path.startswith("/containers")
                else _DOCKER_IMAGES).encode(),
                content_type="application/json")
        if path == "/containers/create":
            # The gold: the container spec names the miner image, the
            # command, and any host mounts they intended to escape through.
            spec = _safe_json(body)
            return WebResponse(
                status="201 Created",
                body=b'{"Id":"8dfafdbc3a40e6d0a1f9c0f9e1a2b3c4d5e6f7a8",'
                     b'"Warnings":[]}',
                content_type="application/json",
                events=[("container_create", {
                    "image": _dig(spec, "Image"),
                    "cmd": _dig(spec, "Cmd"),
                    "entrypoint": _dig(spec, "Entrypoint"),
                    "binds": _dig(spec, "HostConfig", "Binds"),
                    "privileged": _dig(spec, "HostConfig", "Privileged"),
                    "network_mode": _dig(spec, "HostConfig", "NetworkMode"),
                    "bytes": len(body),
                })])
        if _DOCKER_START_RE.match(path):
            return WebResponse(status="204 No Content", body=b"",
                               content_type="application/json",
                               events=[("container_start", {"path": path})])
        if _DOCKER_EXEC_RE.match(path):
            return WebResponse(
                status="201 Created",
                body=b'{"Id":"a1b2c3d4e5f60718293a4b5c6d7e8f90"}',
                content_type="application/json",
                events=[("container_exec", {
                    "cmd": _dig(_safe_json(body), "Cmd"), "path": path})])
        return None

    def _elasticsearch(self, method: str, low: str) -> WebResponse | None:
        if low == "/":
            return WebResponse(body=json.dumps({
                "name": self.hostname, "cluster_name": "elasticsearch",
                "cluster_uuid": "kR7bQ2vXSm-9wHhTt1LzOA",
                "version": {"number": self.es_version,
                            "build_flavor": "default", "build_type": "deb",
                            "lucene_version": "7.7.2"},
                "tagline": "You Know, for Search",
            }).encode(), content_type="application/json")
        if low.startswith("/_cluster/health"):
            return WebResponse(body=json.dumps({
                "cluster_name": "elasticsearch", "status": "green",
                "number_of_nodes": 1, "active_primary_shards": 12,
                "active_shards": 12, "unassigned_shards": 0,
            }).encode(), content_type="application/json")
        if low.startswith("/_cat/indices"):
            return WebResponse(
                body=b"green open customers  9pQ2 5 1 18422 0 12.1mb 6.0mb\n"
                     b"green open orders     Kx8s 5 1 90211 0 88.4mb 44.2mb\n"
                     b"green open .kibana_1  Zm3t 1 1     4 0  30.1kb 15kb\n",
                content_type="text/plain; charset=UTF-8")
        if low.startswith("/_nodes"):
            return WebResponse(body=json.dumps({
                "cluster_name": "elasticsearch",
                "nodes": {"kR7bQ2vXSm": {"name": self.hostname,
                                         "version": self.es_version,
                                         "roles": ["master", "data"]}},
            }).encode(), content_type="application/json")
        if "/_search" in low:
            return WebResponse(body=json.dumps({
                "took": 4, "timed_out": False,
                "hits": {"total": 0, "max_score": None, "hits": []},
            }).encode(), content_type="application/json")
        return None

    # -- command execution -------------------------------------------------

    def _exec(self, command: str, shell, *, vector: str,
              path: str) -> WebResponse:
        """Run an attacker command through the emulator and return its output.

        Nothing executes. `shell` is a `honeyknot.shell.ShellSession`; if the
        caller didn't supply one we still record the attempt, because the
        command string itself is the artifact worth keeping.
        """
        events: list[tuple[str, dict]] = [
            ("web_command", {"vector": vector, "path": path,
                             "command": command[:500]}),
        ]
        output = b""
        if shell is not None:
            result = shell.execute(command)
            output = result.output
            events.extend(result.events)
            for name, data in result.artifacts:
                events.append(("_artifact", {"name": name, "data": data}))
        return WebResponse(
            body=output,
            content_type="text/plain; charset=UTF-8",
            events=events)


# --------------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------------

_DEFAULT_SERVER = {
    "generic": "nginx/1.18.0 (Ubuntu)",
    "docker": "Docker/20.10.7 (linux)",
    "elasticsearch": "nginx/1.18.0 (Ubuntu)",
    "tomcat": "Apache-Coyote/1.1",
    "springboot": "Apache-Coyote/1.1",
    "router": "Boa/0.94.14rc21",
}

_DOCKER_UNAMBIGUOUS_RE = re.compile(
    r"^/(?:containers/|images/json|exec/|_ping)")
_DOCKER_START_RE = re.compile(r"^/containers/[^/]+/(?:start|restart|kill)$")
_DOCKER_EXEC_RE = re.compile(r"^/containers/[^/]+/exec$")

_DOCKER_CONTAINERS = [
    {"Id": "3f2c1b0a9e8d", "Names": ["/web"], "Image": "nginx:1.19",
     "State": "running", "Status": "Up 3 days",
     "Ports": [{"PrivatePort": 80, "PublicPort": 8080, "Type": "tcp"}]},
    {"Id": "7a6b5c4d3e2f", "Names": ["/redis"], "Image": "redis:6-alpine",
     "State": "running", "Status": "Up 3 days", "Ports": []},
]

_DOCKER_IMAGES = [
    {"Id": "sha256:2622e6cca7eb", "RepoTags": ["nginx:1.19"], "Size": 133000000},
    {"Id": "sha256:ef47f3b6dc11", "RepoTags": ["redis:6-alpine"], "Size": 32000000},
]

_INDEX_HTML = (
    "<!DOCTYPE html><html><head><title>{h}</title></head><body>"
    "<h1>It works!</h1>"
    "<p>This is the default web page for this server.</p>"
    "<p>The web server software is running but no content has been added, yet."
    "</p></body></html>"
)

# Paths that are webshells, RCE endpoints, or generic "run this" surfaces.
_EXEC_PATHS = re.compile(
    r"(?:^/shell$|/vendor/phpunit/.*eval-stdin\.php|/_ignition/execute-solution"
    r"|/gponform/diag_form|/ctrlt/deviceupgrade_1|/hnap1/?$|/setup\.cgi"
    r"|/goform/form(?:syscmd|wsc)|/boaform/(?:admin/)?form(?:syscmd|ping)"
    r"|/cgi-bin/|/ztp/cgi-bin/handler|/api/jsonws/invoke"
    r"|/(?:shell|cmd|c99|r57|wso|alfa|indoxploit|up|upload|1|x|xx|test)\.(?:php|jsp|asp|aspx)$"
    r"|/index\.php$|/ws/v1/cluster/apps)")


def _is_exec_surface(low: str, method: str, body: bytes) -> bool:
    if _EXEC_PATHS.search(low):
        return True
    # A `?cmd=` on any path at all is a webshell probe; the path is whatever
    # they think they already uploaded.
    return method in ("GET", "POST") and b"cmd=" in body[:512]


def _decode_basic(header: str) -> tuple[str | None, str | None]:
    try:
        raw = base64.b64decode(header.split(" ", 1)[1], validate=False)
    except (IndexError, ValueError):
        return None, None
    text = raw.decode("utf-8", errors="replace")
    user, sep, password = text.partition(":")
    return (user, password) if sep else (text, None)


def _form_credentials(body: bytes) -> tuple[str, str] | None:
    """Pull a username/password pair out of a urlencoded form body."""
    try:
        params = urllib.parse.parse_qs(
            body[:MAX_BODY_ECHO].decode("latin-1"), keep_blank_values=True)
    except ValueError:
        return None
    user_keys = ("log", "user", "username", "usr", "login", "uname", "email",
                 "j_username", "userid", "admin_username")
    pass_keys = ("pwd", "pass", "password", "passwd", "j_password", "pw",
                 "admin_password")
    user = next((params[k][0] for k in user_keys if params.get(k)), None)
    password = next((params[k][0] for k in pass_keys if params.get(k)), None)
    if user is None and password is None:
        return None
    return user or "", password or ""


def _safe_json(body: bytes) -> dict:
    try:
        parsed = json.loads(body[:256 * 1024].decode("utf-8", errors="replace"))
    except (ValueError, UnicodeDecodeError):
        return {}
    return parsed if isinstance(parsed, dict) else {}


def _dig(obj: dict, *keys):
    """Walk nested dict keys, returning None instead of raising."""
    cur = obj
    for key in keys:
        if not isinstance(cur, dict):
            return None
        cur = cur.get(key)
    return cur
