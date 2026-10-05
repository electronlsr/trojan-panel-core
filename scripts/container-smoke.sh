#!/usr/bin/env bash
# Disposable Linux/amd64 image smoke test for GitHub Actions only.
# Usage: bash scripts/container-smoke.sh core|backend|ui IMAGE
# Build/load IMAGE first. No host ports, existing volumes, or user services are used.
# Dependency versions match the official installer baseline, not production advice.
set -Eeuo pipefail
set +x
umask 077

fail() { printf 'ERROR: %s\n' "$*" >&2; exit 1; }
[[ $# == 2 ]] || fail 'usage: container-smoke.sh core|backend|ui IMAGE'
mode=$1
image=$2
expected_version=${EXPECTED_PANEL_VERSION:-v$(cat "$(dirname "${BASH_SOURCE[0]}")/../.release-version")}
[[ "$expected_version" =~ ^v[0-9]+\.[0-9]+\.[0-9]+([.-][a-z0-9]+)*$ ]] || fail 'invalid expected Panel version'
case "$mode" in core|backend|ui) ;; *) fail "unknown mode: $mode" ;; esac
[[ -n "$image" && "$image" != -* ]] || fail 'invalid image argument'
[[ ${GITHUB_ACTIONS:-} == true && ${RUNNER_OS:-} == Linux && ${RUNNER_ENVIRONMENT:-} == github-hosted ]] || fail 'run only in a disposable GitHub-hosted Linux Actions runner'
[[ $(uname -m) == x86_64 ]] || fail 'this smoke must run natively on amd64'
for tool in docker jq timeout python3; do command -v "$tool" >/dev/null || fail "missing command: $tool"; done
# Do not follow a remote Docker context/DOCKER_HOST to a user or production server.
[[ -z ${DOCKER_HOST:-} || ${DOCKER_HOST} == unix://* ]] || fail 'remote DOCKER_HOST is forbidden'
endpoint=$(docker context inspect --format '{{.Endpoints.docker.Host}}')
[[ "$endpoint" == unix://* ]] || fail 'a local Unix-socket Docker context is required'
[[ $(docker info --format '{{.OSType}}/{{.Architecture}}') == linux/x86_64 ]] || fail 'Docker daemon must be native Linux x86_64'
[[ $(docker image inspect --format '{{.Os}}/{{.Architecture}}' "$image") == linux/amd64 ]] || fail 'load the Linux/amd64 test image first'

work=$(mktemp -d "${RUNNER_TEMP:-/tmp}/tp-image-smoke.XXXXXXXX")
prefix="tp-smoke-${mode}-$(python3 -c 'import secrets; print(secrets.token_hex(6))')"
network="$prefix-net"
app="$prefix-app"
db="$prefix-db"
cache="$prefix-redis"
containers=()
volumes=()
network_created=false
cleanup() {
  local status=$?
  trap - EXIT
  set +e
  if (( status != 0 )); then
    for container in "${containers[@]}"; do
      printf '\n--- %s logs ---\n' "$container" >&2
      docker logs --tail 100 "$container" >&2
      if [[ "$container" == "$app" ]]; then
        docker exec "$app" sh -c 'for f in /tpdata/trojan-panel/logs/*.log /tpdata/trojan-panel-core/logs/*.log; do [ ! -f "$f" ] || tail -n 100 "$f"; done' >&2
      fi
    done
  fi
  # Only exact resource names created by this invocation are removed. Never prune.
  if ((${#containers[@]})); then docker rm -fv "${containers[@]}" >/dev/null 2>&1; fi
  if ((${#volumes[@]})); then docker volume rm "${volumes[@]}" >/dev/null 2>&1; fi
  if "$network_created"; then docker network rm "$network" >/dev/null 2>&1; fi
  rm -rf -- "$work"
  exit "$status"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

secret() { python3 -c 'import secrets; print(secrets.token_hex(24))'; }
db_password=$(secret)
redis_password=$(secret)
auth_password=$(secret)
for value in "$db_password" "$redis_password" "$auth_password"; do printf '::add-mask::%s\n' "$value"; done

docker network create --internal --label io.trojan-panel.smoke="$prefix" "$network" >/dev/null
network_created=true
mounts=()
mount_volume() {
  local suffix=$1 target=$2 name="$prefix-$1"
  docker volume create --label io.trojan-panel.smoke="$prefix" "$name" >/dev/null
  volumes+=("$name")
  mounts+=(--mount "type=volume,source=$name,target=$target")
}
running() { [[ $(docker inspect --format '{{.State.Running}}' "$1") == true ]]; }
wait_for() {
  local label=$1 container=$2 limit=$3
  shift 3
  local deadline=$((SECONDS + limit))
  until "$@" >"$work/last-check.log" 2>&1; do
    running "$container" || fail "$label container exited"
    if (( SECONDS >= deadline )); then cat "$work/last-check.log" >&2; fail "timed out waiting for $label"; fi
    sleep 2
  done
}
mysql_query() {
  timeout 10 docker exec -i -e MYSQL_PWD="$db_password" "$db" \
    mysql --protocol=tcp -h127.0.0.1 -uroot --batch --skip-column-names "$@"
}
redis_query() {
  timeout 10 docker exec -e REDISCLI_AUTH="$redis_password" "$cache" redis-cli --raw "$@"
}
http_get() {
  timeout 10 docker exec "$app" wget -q -T 5 -O - "http://127.0.0.1:$port$1"
}
http_post() {
  timeout 10 docker exec "$app" wget -q -T 5 -O - \
    --header='Content-Type: application/json' --post-data="$2" "http://127.0.0.1:$port$1"
}
json_response() {
  local expected=$1
  shift
  "$@" >"$work/response.json" && jq -e "$expected" "$work/response.json" >/dev/null
}
check_binary() {
  local expected=$1
  shift
  local output
  output=$(timeout 20 docker exec "$app" "$@" 2>&1) || fail "binary execution failed: $* ($output)"
  [[ "$output" == *"$expected"* ]] || fail "version/module mismatch: $* ($output)"
  printf '%s\n' "$output"
}
check_files() {
  timeout 20 docker exec "$app" sh -ec "$1"
}

if [[ "$mode" != ui ]]; then
  # These accounts, databases and passwords exist only in this throw-away stack.
  containers+=("$db")
  docker run -d --name "$db" --network "$network" --network-alias mariadb \
    --label io.trojan-panel.smoke="$prefix" \
    --env "MYSQL_ROOT_PASSWORD=$db_password" --env MYSQL_ROOT_HOST=% \
    --env MYSQL_DATABASE=trojan_panel_db mariadb:10.7.3 >/dev/null
  containers+=("$cache")
  docker run -d --name "$cache" --network "$network" --network-alias redis \
    --label io.trojan-panel.smoke="$prefix" redis:6.2.7 \
    redis-server --requirepass "$redis_password" --save '' --appendonly no >/dev/null
  # A TCP SQL query avoids mistaking MariaDB's temporary bootstrap server for readiness.
  wait_for MariaDB "$db" 120 mysql_query -e 'SELECT 1'
  wait_for Redis "$cache" 60 bash -c '[[ $("$@") == PONG ]]' _ \
    docker exec -e "REDISCLI_AUTH=$redis_password" "$cache" redis-cli --raw PING
fi

case "$mode" in
  backend)
    root=/tpdata/trojan-panel
    port=8081
    mount_volume config "$root/config"
    mount_volume logs "$root/logs"
    mount_volume webfile "$root/webfile"
    ;;
  core)
    root=/tpdata/trojan-panel-core
    port=8082
    mount_volume config "$root/config"
    mount_volume logs "$root/logs"
    for component in xray trojango hysteria naiveproxy hysteria2; do
      mount_volume "$component-config" "$root/bin/$component/config"
    done
    # Core deliberately does not initialize the panel schema. This is a minimal
    # CI-only account fixture for its existing SQL auth contract, not a migration.
    mysql_query trojan_panel_db <<SQL
CREATE TABLE account (
 id BIGINT UNSIGNED PRIMARY KEY AUTO_INCREMENT,
 username VARCHAR(64) NOT NULL,
 pass VARCHAR(64) NOT NULL,
 hash VARCHAR(64) NOT NULL,
 quota BIGINT NOT NULL,
 download BIGINT NOT NULL DEFAULT 0,
 upload BIGINT NOT NULL DEFAULT 0
);
INSERT INTO account (username, pass, hash, quota) VALUES ('ci-smoke', '$auth_password', SHA2('$auth_password', 224), -1);
SQL
    ;;
  ui)
    root=/tpdata/trojan-panel-ui
    port=8080
    # The official installer supplies this config. Without it, the stock image
    # can return the nginx welcome page instead of the packaged Vue application.
    cat >"$work/default.conf" <<'NGINX'
server {
    listen 8080;
    server_name localhost;
    root /tpdata/trojan-panel-ui;
    location / { index index.html index.htm; }
}
NGINX
    chmod 644 "$work/default.conf"
    mounts+=(--mount "type=bind,source=$work/default.conf,target=/etc/nginx/conf.d/default.conf,readonly")
    ;;
esac

containers+=("$app")
if [[ "$mode" == ui ]]; then
  docker create --name "$app" --network "$network" --label io.trojan-panel.smoke="$prefix" \
    "${mounts[@]}" "$image" >/dev/null
else
  docker create --name "$app" --network "$network" --label io.trojan-panel.smoke="$prefix" \
    "${mounts[@]}" \
    --env mariadb_ip=mariadb --env mariadb_port=3306 --env mariadb_user=root \
    --env "mariadb_pas=$db_password" --env database=trojan_panel_db --env account_table=account \
    --env redis_host=redis --env redis_port=6379 --env "redis_pass=$redis_password" \
    --env "server_port=$port" --env grpc_port=8100 --env GIN_MODE=release \
    "$image" >/dev/null
  if [[ "$mode" == backend ]]; then
    # Seed only the optional logo so app initialization needs no external HTTP.
    # Every actual config, template and database is still created by the app.
    mkdir -p "$work/seed/template"
    python3 - "$work/seed/template/logo.png" <<'PY'
import base64, pathlib, sys
pathlib.Path(sys.argv[1]).write_bytes(base64.b64decode('iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mP8/x8AAwMCAO+jRZkAAAAASUVORK5CYII='))
PY
    docker cp "$work/seed/." "$app:$root/config/"
  fi
fi
[[ $(docker inspect --format '{{.Config.WorkingDir}}' "$app") == "$root/" || \
   $(docker inspect --format '{{.Config.WorkingDir}}' "$app") == "$root" ]] || fail 'unexpected image working directory'
docker start "$app" >/dev/null

case "$mode" in
  backend)
    wait_for 'backend settings API (SQL + Redis)' "$app" 120 \
      json_response ".code == 20000 and .type == \"success\" and .data.systemName == \"Trojan Panel\" and .data.version == \"$expected_version\"" \
      http_get /api/auth/setting
    check_binary "$expected_version" "$root/trojan-panel" -version
    check_files 'test -s config/config.ini; test -s config/rbac_model.conf;
      test -s config/template/template-clash-rule.yaml; test -s config/template/template-xray.json;
      test -s config/export/AccountTemplate.json; test -s config/export/NodeServerTemplate.json;
      test -d logs; test -d webfile'
    [[ $(mysql_query trojan_panel_db -e "SELECT COUNT(*) FROM account WHERE username='sysadmin'") == 1 ]] || fail 'backend schema/default account not initialized'
    [[ $(redis_query EXISTS trojan-panel:system) == 1 ]] || fail 'backend did not populate Redis settings cache'
    ;;
  core)
    wait_for 'core validation API' "$app" 90 json_response '.ok == false and has("id")' \
      http_post /api/auth/hysteria2 '{}'
    # Compare actual executables to the version manifest packaged alongside them.
    docker cp "$app:$root/core-versions.env" "$work/core-versions.env"
    manifest_value() {
      local value
      value=$(sed -n "s/^$1=//p" "$work/core-versions.env")
      [[ -n "$value" && "$value" != *$'\n'* ]] || fail "missing/duplicate manifest key: $1"
      printf '%s' "$value"
    }
    panel_version=$(manifest_value PANEL_VERSION)
    [[ "v$panel_version" == "$expected_version" ]] || fail 'Core inventory does not match the release version'
    xray_version=$(manifest_value XRAY_VERSION)
    trojan_version=$(manifest_value TROJAN_GO_VERSION)
    hy1_version=$(manifest_value HYSTERIA1_VERSION)
    hy2_version=$(manifest_value HYSTERIA2_VERSION)
    caddy_version=$(manifest_value CADDY_VERSION)
    check_binary "v$panel_version" "$root/trojan-panel-core" -version
    check_binary "${xray_version#v}" "$root/bin/xray/xray" version
    check_binary "$trojan_version" "$root/bin/trojango/trojan-go" -version
    check_binary "$hy1_version" "$root/bin/hysteria/hysteria" --version
    check_binary "${hy2_version#app/}" "$root/bin/hysteria2/hysteria2" version
    check_binary "$caddy_version" "$root/bin/naiveproxy/naiveproxy" version
    check_binary http.handlers.forward_proxy "$root/bin/naiveproxy/naiveproxy" list-modules
    check_files 'test -s config/config.ini; test -s config/sqlite/trojan_panel_core.db; test -d logs;
      for c in xray trojango hysteria naiveproxy hysteria2; do test -d "bin/$c/config"; done'
    docker cp "$app:$root/config/sqlite/trojan_panel_core.db" "$work/core.db"
    python3 - "$work/core.db" <<'PY'
import sqlite3, sys
with sqlite3.connect(sys.argv[1]) as con:
    assert con.execute('PRAGMA integrity_check').fetchone() == ('ok',)
    assert con.execute("SELECT count(*) FROM sqlite_master WHERE type='table' AND name='node_config'").fetchone() == (1,)
PY
    # Readiness and binary checks allow >1 second to avoid the 5 requests/s limit.
    payload=$(printf '%s' "$auth_password" | base64 -w0)
    json_response '.ok == true and .msg == "success"' \
      http_post /api/auth/hysteria "{\"payload\":\"$payload\"}" || fail 'Hysteria 1 positive SQL auth failed'
    json_response '.ok == true' \
      http_post /api/auth/hysteria2 "{\"auth\":\"$auth_password\"}" || fail 'Hysteria 2 positive SQL auth failed'
    json_response '.ok == false and .id == ""' \
      http_post /api/auth/hysteria2 '{"auth":"deliberately-invalid-ci-password"}' || fail 'Hysteria 2 negative auth failed'
    # The application's Redis pool is lazy without active nodes. Verify container
    # DNS, TCP and authenticated Redis reachability separately; this does not
    # claim to exercise synchronization, distributed locks or quota updates.
    timeout 5 docker exec -e "SMOKE_REDIS_PASSWORD=$redis_password" "$app" bash -ec '
      exec 3<>/dev/tcp/redis/6379
      printf "AUTH %s\r\nPING\r\n" "$SMOKE_REDIS_PASSWORD" >&3
      IFS= read -r reply <&3; test "$reply" = "$(printf "+OK\r")"
      IFS= read -r reply <&3; test "$reply" = "$(printf "+PONG\r")"
    ' || fail 'Redis is not reachable/authenticated from core container'
    # Verify the gRPC listener without claiming a complete RPC/proxy lifecycle test.
    timeout 5 docker exec "$app" bash -c 'exec 3<>/dev/tcp/127.0.0.1/8100' || fail 'core gRPC listener unavailable'
    ;;
  ui)
    wait_for 'UI HTTP' "$app" 60 http_get /
    http_get / >"$work/index.html"
    check_files 'test -s index.html; test -s version; test -d static'
    [[ $(docker exec "$app" cat version) == "$expected_version" ]] || fail 'UI version file does not match the release version'
    timeout 10 docker exec "$app" nginx -t
    docker cp "$app:$root/index.html" "$work/image-index.html"
    cmp "$work/index.html" "$work/image-index.html" || fail 'Nginx is not serving the packaged index.html'
    python3 - "$work/index.html" "$work/assets.txt" <<'PY'
from html.parser import HTMLParser
from pathlib import Path
import sys
class Assets(HTMLParser):
    def __init__(self):
        super().__init__(); self.app = False; self.paths = set()
    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        self.app |= attrs.get('id') == 'app'
        path = attrs.get('src') if tag == 'script' else attrs.get('href') if tag == 'link' else None
        if path and not path.startswith(('http:', 'https:', '//', 'data:')) and path.split('?')[0].endswith(('.js', '.css')):
            self.paths.add('/' + path.removeprefix('./').lstrip('/'))
p = Assets(); p.feed(Path(sys.argv[1]).read_text())
assert p.app and p.paths, 'expected Vue #app and JavaScript/CSS assets'
Path(sys.argv[2]).write_text('\n'.join(sorted(p.paths)) + '\n')
PY
    while IFS= read -r asset; do
      http_get "$asset" >"$work/asset"
      [[ -s "$work/asset" ]] || fail "empty UI asset: $asset"
      [[ $(head -c 15 "$work/asset") != '<!DOCTYPE html>' ]] || fail "HTML fallback instead of asset: $asset"
    done <"$work/assets.txt"
    ;;
esac

if [[ "$mode" != ui ]]; then
  # Existing installer paths are persisted; restart must not replace configuration.
  before=$(docker exec "$app" sha256sum config/config.ini)
  docker restart --time 5 "$app" >/dev/null
  if [[ "$mode" == backend ]]; then
    wait_for 'backend after restart' "$app" 60 json_response '.code == 20000 and .type == "success"' http_get /api/auth/setting
  else
    wait_for 'core after restart' "$app" 60 json_response '.ok == false and has("id")' http_post /api/auth/hysteria2 '{}'
  fi
  [[ $(docker exec "$app" sha256sum config/config.ini) == "$before" ]] || fail 'existing config changed on restart'
fi
running "$app" || fail 'application exited after smoke checks'
printf 'PASS: %s Linux/amd64 image startup, runtime paths and API/static checks (%s)\n' "$mode" "$image"
