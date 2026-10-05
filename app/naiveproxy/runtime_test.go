package naiveproxy

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"testing"
	"time"
	"trojan-panel-core/core"
	"trojan-panel-core/internal/proxytest"
	"trojan-panel-core/model/constant"
	"trojan-panel-core/model/dto"
)

func TestNaiveOfficialRuntime(t *testing.T) {
	binary := proxytest.Binary(t, "NAIVE_TEST_BINARY")
	dir := proxytest.Workdir(t)
	cert, key := proxytest.Certificate(t, dir)
	oldConfig := core.Config
	core.Config = &core.AppConfig{CertConfig: core.CertConfig{CrtPath: cert, KeyPath: key}}
	t.Cleanup(func() { core.Config = oldConfig })
	apiPort, proxyPort := proxytest.TCPPort(t), proxytest.TCPPort(t)
	if err := os.MkdirAll(constant.NaiveProxyPath, 0755); err != nil {
		t.Fatal(err)
	}
	if err := initNaiveProxy(dto.NaiveProxyConfigDto{ApiPort: uint(apiPort), Port: uint(proxyPort), Domain: "localhost"}); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, constant.NaiveProxyPath, fmt.Sprintf("config-%d.json", apiPort))
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	// Reproduce an existing deployment's persisted deprecated account, then
	// exercise the exact startup migration before starting official Caddy.
	var config map[string]any
	if err := json.Unmarshal(data, &config); err != nil {
		t.Fatal(err)
	}
	delete(config, "logging")
	server := config["apps"].(map[string]any)["http"].(map[string]any)["servers"].(map[string]any)["srv0"].(map[string]any)
	server["listen"] = []string{fmt.Sprintf("127.0.0.1:%d", proxyPort)}
	routes := server["routes"].([]any)[0].(map[string]any)["handle"].([]any)[0].(map[string]any)["routes"].([]any)
	routes[0].(map[string]any)["handle"] = []any{map[string]any{"handler": "forward_proxy", "auth_user_deprecated": "legacy", "auth_pass_deprecated": "legacy-pass", "hide_ip": true, "hide_via": true, "probe_resistance": map[string]any{}, "acl": []any{map[string]any{"subjects": []string{"127.0.0.1"}, "allow": true}}}}
	data, _ = json.Marshal(config)
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	if err := migrateNaiveProxyConfig(path); err != nil {
		t.Fatal(err)
	}
	logPath := proxytest.Start(t, binary, "run", "--config", path)
	proxytest.WaitTCP(t, fmt.Sprintf("127.0.0.1:%d", apiPort), logPath)
	proxytest.WaitTCP(t, fmt.Sprintf("127.0.0.1:%d", proxyPort), logPath)
	api := NewNaiveProxyApi(uint(apiPort))
	user, _, err := api.GetUser("legacy-pass")
	if err != nil || user == nil || user.AuthUserDeprecated != "legacy" {
		t.Fatalf("migrated account missing: %v %v", user, err)
	}
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, "authenticated-loopback-target") }))
	defer origin.Close()
	fetch := func(username, password string) string {
		t.Helper()
		proxyURL, _ := url.Parse(fmt.Sprintf("https://127.0.0.1:%d", proxyPort))
		proxyURL.User = url.UserPassword(username, password)
		transport := &http.Transport{Proxy: http.ProxyURL(proxyURL), TLSClientConfig: &tls.Config{InsecureSkipVerify: true, ServerName: "localhost"}}
		defer transport.CloseIdleConnections()
		client := &http.Client{Transport: transport, Timeout: 3 * time.Second}
		response, err := client.Get(origin.URL)
		if err != nil {
			t.Logf("proxy request failed: %v", err)
			return ""
		}
		defer response.Body.Close()
		body, _ := io.ReadAll(response.Body)
		t.Logf("proxy request status=%d body=%q", response.StatusCode, body)
		return string(body)
	}
	if got := fetch("legacy", "legacy-pass"); got != "authenticated-loopback-target" {
		t.Fatalf("migrated account failed real proxy authentication: %q", got)
	}
	if got := fetch("legacy", "incorrect"); got == "authenticated-loopback-target" {
		t.Fatal("incorrect password authenticated")
	}
	if err := api.AddUser(dto.NaiveProxyAddUserDto{Username: "new-user", Pass: "new:password"}); err != nil {
		t.Fatal(err)
	}
	// Permit only this local test target for the newly added handler.
	_, addedIndex, err := api.GetUser("new:password")
	if err != nil || addedIndex == nil {
		t.Fatalf("new account missing: %v", err)
	}
	aclURL := fmt.Sprintf("http://127.0.0.1:%d/config/apps/http/servers/srv0/routes/0/handle/0/routes/0/handle/%d/acl", apiPort, *addedIndex)
	request, _ := http.NewRequest(http.MethodPost, aclURL, bytes.NewBufferString(`[{"subjects":["127.0.0.1"],"allow":true}]`))
	request.Header.Set("Content-Type", "application/json")
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(response.Body)
	response.Body.Close()
	if response.StatusCode != 200 {
		t.Fatalf("allow test target: %s", body)
	}
	if got := fetch("new-user", "new:password"); got != "authenticated-loopback-target" {
		t.Fatalf("new account failed real proxy authentication: %q", got)
	}
	if err := api.DeleteUser("new:password"); err != nil {
		t.Fatal(err)
	}
	if got := fetch("new-user", "new:password"); got == "authenticated-loopback-target" {
		t.Fatal("deleted account still authenticated")
	}
	if got := fetch("legacy", "legacy-pass"); got != "authenticated-loopback-target" {
		t.Fatalf("removing another account changed legacy authentication: %q", got)
	}
	if err := api.DeleteUser("legacy-pass"); err != nil {
		t.Fatal(err)
	}
	users, err := api.ListUsers()
	if err != nil || len(*users) != 0 {
		t.Fatalf("delete/list failed: %v %v", users, err)
	}
}
