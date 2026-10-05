package hysteria2

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
	"trojan-panel-core/core"
	"trojan-panel-core/internal/proxytest"
	"trojan-panel-core/model/constant"
	"trojan-panel-core/model/dto"
)

func TestHysteria2OfficialRuntime(t *testing.T) {
	binary := proxytest.Binary(t, "HYSTERIA2_TEST_BINARY")
	dir := proxytest.Workdir(t)
	cert, key := proxytest.Certificate(t, dir)
	rejected := make(chan struct{}, 1)
	auth := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/auth/hysteria2" {
			t.Errorf("unexpected auth path %s", r.URL.Path)
		}
		var request dto.Hysteria2AuthDto
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil || request.Auth == nil {
			t.Error("invalid official auth request")
			w.WriteHeader(400)
			return
		}
		allowed := *request.Auth == "test-account-password"
		json.NewEncoder(w).Encode(map[string]any{"ok": allowed, "id": *request.Auth})
		if !allowed {
			select {
			case rejected <- struct{}{}:
			default:
			}
		}
	}))
	defer auth.Close()
	oldConfig := core.Config
	core.Config = &core.AppConfig{CertConfig: core.CertConfig{CrtPath: cert, KeyPath: key}, ServerConfig: core.ServerConfig{Port: auth.Listener.Addr().(*net.TCPAddr).Port}}
	t.Cleanup(func() { core.Config = oldConfig })
	serverPort, apiPort := proxytest.UDPPort(t), proxytest.TCPPort(t)
	if err := os.MkdirAll(constant.Hysteria2Path, 0755); err != nil {
		t.Fatal(err)
	}
	if err := initHysteria2(dto.Hysteria2ConfigDto{ApiPort: uint(apiPort), Port: uint(serverPort), ObfsPassword: "test-salamander", UpMbps: 100, DownMbps: 100}); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, constant.Hysteria2Path, fmt.Sprintf("config-%d.json", apiPort))
	proxytest.LoopbackListeners(t, path)
	logPath := proxytest.Start(t, binary, "-c", path, "server")
	proxytest.WaitTCP(t, fmt.Sprintf("127.0.0.1:%d", apiPort), logPath)
	startClient := func(name, password string) (int, string) {
		port := proxytest.TCPPort(t)
		config := map[string]any{"server": fmt.Sprintf("127.0.0.1:%d", serverPort), "auth": password, "tls": map[string]any{"sni": "localhost", "insecure": true}, "obfs": map[string]any{"type": "salamander", "salamander": map[string]any{"password": "test-salamander"}}, "http": map[string]any{"listen": fmt.Sprintf("127.0.0.1:%d", port)}}
		data, _ := json.Marshal(config)
		clientPath := filepath.Join(dir, name+".json")
		if err := os.WriteFile(clientPath, data, 0600); err != nil {
			t.Fatal(err)
		}
		return port, proxytest.Start(t, binary, "-c", clientPath, "client")
	}
	startClient("denied", "incorrect-password")
	select {
	case <-rejected:
	case <-time.After(5 * time.Second):
		t.Fatal("Hysteria2 did not consult panel auth for denied client")
	}
	proxyPort, clientLog := startClient("allowed", "test-account-password")
	proxytest.WaitTCP(t, fmt.Sprintf("127.0.0.1:%d", proxyPort), clientLog)
	payload := strings.Repeat("hysteria2-authenticated-loopback-", 1024)
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, payload) }))
	defer origin.Close()
	proxyURL, _ := url.Parse(fmt.Sprintf("http://127.0.0.1:%d", proxyPort))
	transport := &http.Transport{Proxy: http.ProxyURL(proxyURL)}
	defer transport.CloseIdleConnections()
	response, err := (&http.Client{Transport: transport, Timeout: 5 * time.Second}).Get(origin.URL)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(response.Body)
	response.Body.Close()
	transport.CloseIdleConnections()
	if string(body) != payload {
		t.Fatal("Hysteria2 authenticated forwarding failed")
	}
	api := NewHysteria2Api(uint(apiPort))
	deadline := time.Now().Add(5 * time.Second)
	var tx, rx int64
	for time.Now().Before(deadline) {
		users, err := api.ListUsers(false)
		if err != nil {
			t.Fatal(err)
		}
		tx, rx = users["test-account-password"].Tx, users["test-account-password"].Rx
		if tx > 0 && rx > 0 {
			break
		}
		time.Sleep(25 * time.Millisecond)
	}
	if tx == 0 || rx == 0 {
		t.Fatalf("per-account traffic was not reported: tx=%d rx=%d", tx, rx)
	}
	users, err := api.ListUsers(true)
	if err != nil || users["test-account-password"].Tx == 0 {
		t.Fatalf("traffic read/clear failed: %v %v", users, err)
	}
	users, err = api.ListUsers(false)
	if err != nil || len(users) != 0 {
		t.Fatalf("traffic was not cleared: %v %v", users, err)
	}
}
