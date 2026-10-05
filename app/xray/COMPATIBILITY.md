# Xray stable compatibility

Verified against official stable [Xray v26.3.27](https://github.com/XTLS/Xray-core/releases/tag/v26.3.27), release commit `d2758a0`, using the official Linux amd64 release binary. The release API reports `prerelease: false`. The source module is also tagged `v1.260327.0` and requires Go 1.26; the panel's control SDK intentionally remains `v1.8.0`.

## Preserved interfaces

The panel uses the unchanged protobuf wire fields and service methods for `User`, `TypedMessage`, `AddUserOperation`, `RemoveUserOperation`, `AlterInbound`, `RemoveInbound`, `GetStats`, `QueryStats`, and `GetSysStats`. The VMess `alter_id` field was removed upstream, but the panel sends zero, which protobuf omits. Dynamic Trojan accounts send only the password. The previous bundled Xray v1.8.4 already lacked the Trojan `flow` protobuf field and ignored stale flow metadata sent by the panel's older SDK. The UI hides that field for Trojan and can retain a previous VLESS value. Rejecting this inert node metadata in r1 prevented users from being added; the hotfix restores the previous effective behavior without changing saved configuration, protocol, or TLS. VLESS server flow accepts empty or `xtls-rprx-vision`; the panel UI's exact lowercase `none` sentinel is normalized to empty at the RPC boundary.

Config generation preserves arbitrary top-level template fields, existing template inbounds, stream settings, and TLS settings. It adds only the panel's API/user inbounds and missing TLS certificate defaults. Unsupported values are retained for Xray's preflight validation; they are never automatically converted to another protocol.

## Existing configurations requiring explicit migration

Latest Xray rejects these legacy options. There is no automatic legacy-core fallback:

- HTTP/H2/H3 transport (`network: "http"`, `"h2"`, `"h3"`); upstream recommends XHTTP.
- Legacy QUIC transport (`network: "quic"`); upstream recommends XHTTP HTTP/3.
- Legacy `security: "xtls"`; current Vision uses TLS or REALITY.
- Explicit nonempty Trojan `flow` in Xray JSON clients, and VLESS server flows other than `xtls-rprx-vision`. This differs from the panel's inert stored Trojan node metadata described above.
- Global `transport` settings; move appropriate options explicitly into each inbound/outbound `streamSettings`.
- mKCP `header` and `seed`; current upstream uses the corresponding Finalmask settings.
- TLS `allowInsecure: true` after June 1, 2026, and `verifyPeerCertInNames`; upstream names `pinnedPeerCertSha256` / `verifyPeerCertByName` as replacements. These require an explicit certificate-verification decision, not silent substitution.

WebSocket, gRPC, HTTPUpgrade, VMess, Trojan, and classic Shadowsocks currently produce deprecation warnings but remain usable. gRPC as a proxy transport is distinct from the local gRPC control API.

Source: [transport parsing](https://github.com/XTLS/Xray-core/blob/v26.3.27/infra/conf/transport_internet.go), [VLESS parsing](https://github.com/XTLS/Xray-core/blob/v26.3.27/infra/conf/vless.go), [Trojan parsing](https://github.com/XTLS/Xray-core/blob/v26.3.27/infra/conf/trojan.go), [global config](https://github.com/XTLS/Xray-core/blob/v26.3.27/infra/conf/xray.go).

## Reproducible checks

Run isolated config/flow unit tests:

```sh
go test ./app/xray -count=1
```

Run the same tests plus real-core integration checks with a verified official binary:

```sh
XRAY_TEST_BINARY=/absolute/path/to/xray go test ./app/xray -count=1 -v
```

The binary tests use temporary files, dynamically allocated loopback ports, and a local HTTP target. They do not use the panel database or Redis, contact a remote proxy, or read deployed configuration. Coverage:

- Generated TCP, WebSocket, gRPC, XHTTP, HTTPUpgrade, and mKCP configs pass the latest binary's `run -test`.
- Removed HTTP/QUIC/XTLS, legacy mKCP header/seed, legacy VLESS flow, global transport, and old TLS peer-name settings produce explicit upstream validation errors.
- Legacy SDK dynamic user add works for VMess, VLESS, Trojan, and classic Shadowsocks.
- Real proxied HTTP traffic reaches only a local test server for each protocol.
- User traffic counters increase and reset through the existing panel stats methods.
- Existing panel `DeleteUser`, `RemoveInboundHandler`, `GetSysStats`, and `QueryStats` work against the latest binary.
- Actual panel `AddUser` with a reopened disposable SQLite database and a loopback Redis-protocol cache fixture forwards real Trojan and VLESS TCP+TLS HTTP traffic. Trojan saved flows include empty, `none`, `xtls-rprx-vision`, and `xtls-rprx-direct`; stored values remain unchanged. Explicit JSON Trojan flow and invalid VLESS flow continue to reject.

These are protocol/control compatibility checks, not a production MariaDB/Redis-sync, quota, client-matrix, or full deployment test. TLS checks use a verified disposable local certificate. Historical fixed-port tests are available only with the `integration` build tag and still require their original local services; they are separate from these disposable smoke tests.

Historical wire evidence: [Xray v1.8.4 Trojan Account](https://github.com/XTLS/Xray-core/blob/f7c20b85dcbd6c2e8acf2589dfaef8a448daf337/proxy/trojan/config.proto) already contains only the password; [its JSON parser](https://github.com/XTLS/Xray-core/blob/f7c20b85dcbd6c2e8acf2589dfaef8a448daf337/infra/conf/trojan.go) already rejects explicit flow. The distinction is not a new protocol fallback or removal of TLS protection.
