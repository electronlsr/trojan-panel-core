package hysteria

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
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

func TestHysteria1OfficialRuntime(t *testing.T) {
	binary := proxytest.Binary(t, "HYSTERIA_TEST_BINARY")
	dir := proxytest.Workdir(t)
	cert, key := proxytest.Certificate(t, dir)
	rejected := make(chan struct{}, 1)
	auth := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/auth/hysteria" {
			t.Errorf("unexpected auth path %s", r.URL.Path)
		}
		var request dto.HysteriaAuthDto
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil || request.Payload == nil {
			t.Error("invalid official auth request")
			w.WriteHeader(400)
			return
		}
		password, err := base64.StdEncoding.DecodeString(*request.Payload)
		if err != nil {
			t.Error(err)
		}
		allowed := string(password) == "test-account-password"
		json.NewEncoder(w).Encode(map[string]any{"ok": allowed, "msg": "test auth result"})
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
	serverPort := proxytest.UDPPort(t)
	if err := os.MkdirAll(constant.HysteriaPath, 0755); err != nil {
		t.Fatal(err)
	}
	if err := initHysteria(dto.HysteriaConfigDto{ApiPort: 31000, Port: uint(serverPort), Protocol: "udp", Obfs: "test-obfs", UpMbps: 100, DownMbps: 100}); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, constant.HysteriaPath, "config-31000.json")
	proxytest.LoopbackListeners(t, path)
	logPath := proxytest.Start(t, binary, "-c", path, "server")
	proxytest.WaitUDP(t, fmt.Sprintf("127.0.0.1:%d", serverPort), logPath)
	startClient := func(name, password string) (int, string) {
		port := proxytest.TCPPort(t)
		config := map[string]any{"server": fmt.Sprintf("127.0.0.1:%d", serverPort), "protocol": "udp", "auth_str": password, "server_name": "localhost", "insecure": true, "obfs": "test-obfs", "up_mbps": 100, "down_mbps": 100, "retry": 0, "http": map[string]any{"listen": fmt.Sprintf("127.0.0.1:%d", port)}}
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
		t.Fatal("Hysteria1 did not consult panel auth for denied client")
	}
	proxyPort, clientLog := startClient("allowed", "test-account-password")
	proxytest.WaitTCP(t, fmt.Sprintf("127.0.0.1:%d", proxyPort), clientLog)
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, "hysteria1-authenticated-loopback") }))
	defer origin.Close()
	proxyURL, _ := url.Parse(fmt.Sprintf("http://127.0.0.1:%d", proxyPort))
	transport := &http.Transport{Proxy: http.ProxyURL(proxyURL)}
	defer transport.CloseIdleConnections()
	response, err := (&http.Client{Transport: transport, Timeout: 5 * time.Second}).Get(origin.URL)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	body, _ := io.ReadAll(response.Body)
	if string(body) != "hysteria1-authenticated-loopback" {
		t.Fatalf("Hysteria1 forwarding failed: %s", body)
	}
}
