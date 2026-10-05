package xray

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/xtls/xray-core/app/proxyman/command"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/proxy/shadowsocks"
	"github.com/xtls/xray-core/proxy/trojan"
	"github.com/xtls/xray-core/proxy/vless"
	"github.com/xtls/xray-core/proxy/vmess"

	"trojan-panel-core/model/bo"
	"trojan-panel-core/model/dto"
	"trojan-panel-core/util"
)

// Set XRAY_TEST_BINARY to a checksum-verified official stable binary. These
// tests use disposable loopback listeners and no production database or Redis.
func stableXrayBinary(t *testing.T) string {
	t.Helper()
	binary := os.Getenv("XRAY_TEST_BINARY")
	if binary == "" {
		t.Skip("set XRAY_TEST_BINARY to run the real Xray compatibility smoke tests")
	}
	absolute, err := filepath.Abs(binary)
	if err != nil {
		t.Fatal(err)
	}
	output, err := exec.Command(absolute, "version").CombinedOutput()
	if err != nil {
		t.Fatalf("Xray version: %v\n%s", err, output)
	}
	t.Log(strings.TrimSpace(string(output)))
	return absolute
}

func smokePort(t *testing.T) uint {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := uint(listener.Addr().(*net.TCPAddr).Port)
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	return port
}

func writeSmokeConfig(t *testing.T, content []byte) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(path, content, 0600); err != nil {
		t.Fatal(err)
	}
	return path
}

func startSmokeXray(t *testing.T, binary string, config []byte, readyPort uint) {
	t.Helper()
	path := writeSmokeConfig(t, config)
	if output, err := exec.Command(binary, "run", "-test", "-config", path).CombinedOutput(); err != nil {
		t.Fatalf("Xray rejected config: %v\n%s\n%s", err, output, config)
	}
	logPath := filepath.Join(t.TempDir(), "xray.log")
	logFile, err := os.Create(logPath)
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(binary, "run", "-config", path)
	cmd.Stdout, cmd.Stderr = logFile, logFile
	if err := cmd.Start(); err != nil {
		_ = logFile.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		_ = logFile.Close()
		if t.Failed() {
			content, _ := os.ReadFile(logPath)
			t.Logf("Xray log:\n%s", content)
		}
	})
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", readyPort), 100*time.Millisecond)
		if err == nil {
			_ = conn.Close()
			return
		}
		time.Sleep(25 * time.Millisecond)
	}
	t.Fatal("Xray did not open its loopback listener")
}

func loopbackConfig(t *testing.T, input dto.XrayConfigDto) []byte {
	t.Helper()
	content, err := buildXrayConfig(input, bo.Certificate{})
	if err != nil {
		t.Fatal(err)
	}
	config := decodeObject(t, content)
	var inbounds []map[string]json.RawMessage
	if err := json.Unmarshal(config["inbounds"], &inbounds); err != nil {
		t.Fatal(err)
	}
	for _, inbound := range inbounds {
		inbound["listen"] = json.RawMessage(`"127.0.0.1"`)
	}
	config["inbounds"], _ = json.Marshal(inbounds)
	result, err := json.Marshal(config)
	if err != nil {
		t.Fatal(err)
	}
	return result
}

func TestStableXrayGeneratedTransports(t *testing.T) {
	binary := stableXrayBinary(t)
	for _, stream := range []string{
		`{"network":"tcp","tcpSettings":{"header":{"type":"none"}}}`,
		`{"network":"ws","wsSettings":{"path":"/ws"}}`,
		`{"network":"grpc","grpcSettings":{"serviceName":"smoke"}}`,
		`{"network":"xhttp","xhttpSettings":{"path":"/xhttp","mode":"auto"}}`,
		`{"network":"httpupgrade","httpupgradeSettings":{"path":"/upgrade"}}`,
		`{"network":"kcp","kcpSettings":{"mtu":1350,"tti":50}}`,
	} {
		t.Run(stream, func(t *testing.T) {
			content := loopbackConfig(t, dto.XrayConfigDto{ApiPort: smokePort(t), Port: smokePort(t), Protocol: "vless", Tag: "user", Settings: `{"clients":[],"decryption":"none"}`, StreamSettings: stream})
			path := writeSmokeConfig(t, content)
			if output, err := exec.Command(binary, "run", "-test", "-config", path).CombinedOutput(); err != nil {
				t.Fatalf("Xray rejected generated transport: %v\n%s", err, output)
			}
		})
	}
}

func TestStableXrayGRPCAndTraffic(t *testing.T) {
	binary := stableXrayBinary(t)
	const password = "isolated-xray-smoke-user"
	id := util.GenerateUUID(password)
	cases := []struct {
		protocol       string
		settings       string
		account        *serial.TypedMessage
		clientSettings func(uint) string
	}{
		{"vmess", `{"clients":[]}`, serial.ToTypedMessage(&vmess.Account{Id: id, AlterId: 0}), func(port uint) string {
			return fmt.Sprintf(`{"vnext":[{"address":"127.0.0.1","port":%d,"users":[{"id":%q,"security":"auto","alterId":0}]}]}`, port, id)
		}},
		{"vless", `{"clients":[],"decryption":"none"}`, serial.ToTypedMessage(&vless.Account{Id: id, Encryption: "none"}), func(port uint) string {
			return fmt.Sprintf(`{"vnext":[{"address":"127.0.0.1","port":%d,"users":[{"id":%q,"encryption":"none"}]}]}`, port, id)
		}},
		{"trojan", `{"clients":[]}`, serial.ToTypedMessage(&trojan.Account{Password: password}), func(port uint) string {
			return fmt.Sprintf(`{"servers":[{"address":"127.0.0.1","port":%d,"password":%q}]}`, port, password)
		}},
		{"shadowsocks", `{"clients":[],"network":"tcp,udp"}`, serial.ToTypedMessage(&shadowsocks.Account{Password: password, CipherType: shadowsocks.CipherType_AES_128_GCM}), func(port uint) string {
			return fmt.Sprintf(`{"servers":[{"address":"127.0.0.1","port":%d,"password":%q,"method":"aes-128-gcm"}]}`, port, password)
		}},
	}
	for _, tc := range cases {
		t.Run(tc.protocol, func(t *testing.T) {
			apiPort, serverPort, proxyPort := smokePort(t), smokePort(t), smokePort(t)
			serverConfig := loopbackConfig(t, dto.XrayConfigDto{ApiPort: apiPort, Port: serverPort, Protocol: tc.protocol, Tag: "user", Settings: tc.settings, StreamSettings: `{"network":"tcp","security":"none"}`})
			startSmokeXray(t, binary, serverConfig, apiPort)
			api := NewXrayApi(apiPort)
			if _, err := api.GetSysStats(); err != nil {
				t.Fatal(err)
			}
			if _, err := api.QueryStats("", false); err != nil {
				t.Fatal(err)
			}
			conn, ctx, closeClient, err := apiClient(apiPort)
			if err != nil {
				t.Fatal(err)
			}
			defer closeClient()
			handler := command.NewHandlerServiceClient(conn)
			// Serialize the exact legacy SDK account messages used by AddUser.
			_, err = handler.AlterInbound(ctx, &command.AlterInboundRequest{Tag: "user", Operation: serial.ToTypedMessage(&command.AddUserOperation{User: &protocol.User{Email: password, Level: 0, Account: tc.account}})})
			if err != nil {
				t.Fatalf("legacy SDK AddUser: %v", err)
			}
			clientConfig := []byte(fmt.Sprintf(`{"log":{"loglevel":"warning"},"inbounds":[{"listen":"127.0.0.1","port":%d,"protocol":"http","settings":{}}],"outbounds":[{"protocol":%q,"settings":%s,"streamSettings":{"network":"tcp","security":"none"}}]}`, proxyPort, tc.protocol, tc.clientSettings(serverPort)))
			startSmokeXray(t, binary, clientConfig, proxyPort)
			target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = io.WriteString(w, "xray-loopback-smoke") }))
			defer target.Close()
			proxyURL, _ := url.Parse(fmt.Sprintf("http://127.0.0.1:%d", proxyPort))
			transport := &http.Transport{Proxy: http.ProxyURL(proxyURL), DisableKeepAlives: true}
			defer transport.CloseIdleConnections()
			client := &http.Client{Transport: transport, Timeout: 5 * time.Second}
			response, err := client.Get(target.URL)
			if err != nil {
				t.Fatalf("real %s traffic: %v", tc.protocol, err)
			}
			body, err := io.ReadAll(response.Body)
			_ = response.Body.Close()
			if err != nil || string(body) != "xray-loopback-smoke" {
				t.Fatalf("unexpected proxy response: %q, %v", body, err)
			}
			stats, err := api.GetUserStats(password, "downlink", false)
			if err != nil || stats == nil || stats.Value <= 0 {
				t.Fatalf("GetUserStats after real traffic: %+v, %v", stats, err)
			}
			if _, err := api.GetBoundStats("inbound", "user", "uplink", true); err != nil {
				t.Fatal(err)
			}
			if _, err := api.QueryStats("user>>>", true); err != nil {
				t.Fatal(err)
			}
			stats, err = api.GetUserStats(password, "downlink", false)
			if err != nil || stats == nil || stats.Value != 0 {
				t.Fatalf("counter reset failed: %+v, %v", stats, err)
			}
			if err := api.DeleteUser(password); err != nil {
				t.Fatalf("panel DeleteUser: %v", err)
			}
			removeContext, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			_, err = handler.AlterInbound(removeContext, &command.AlterInboundRequest{Tag: "user", Operation: serial.ToTypedMessage(&command.RemoveUserOperation{Email: password})})
			if err == nil {
				t.Fatal("second removal unexpectedly succeeded; panel DeleteUser did not remove user")
			}
			if err := api.RemoveInboundHandler("user"); err != nil {
				t.Fatalf("panel RemoveInboundHandler: %v", err)
			}
		})
	}
}

func TestStableXrayRejectsRemovedConfig(t *testing.T) {
	binary := stableXrayBinary(t)
	for _, tc := range []struct {
		name, stream, settings, template, message string
	}{
		{name: "legacy-http", stream: `{"network":"http"}`, message: "HTTP transport"},
		{name: "legacy-quic", stream: `{"network":"quic"}`, message: "QUIC transport"},
		{name: "legacy-xtls", stream: `{"security":"xtls"}`, message: "Legacy XTLS"},
		{name: "legacy-kcp-header", stream: `{"network":"kcp","kcpSettings":{"header":{"type":"none"}}}`, message: "mkcp header & seed"},
		{name: "legacy-kcp-seed", stream: `{"network":"kcp","kcpSettings":{"seed":"test-seed"}}`, message: "mkcp header & seed"},
		{name: "legacy-vless-flow", settings: `{"clients":[],"decryption":"none","flow":"xtls-rprx-direct"}`, message: "doesn't support"},
		{name: "global-transport", template: `{"inbounds":[],"outbounds":[{"protocol":"freedom"}],"transport":{"tcpSettings":{"header":{"type":"none"}}}}`, message: "Global transport config"},
		{name: "tls-peer-names", template: `{"inbounds":[],"outbounds":[{"protocol":"freedom","streamSettings":{"security":"tls","tlsSettings":{"verifyPeerCertInNames":["example.invalid"]}}}]}`, message: "verifyPeerCertInNames"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if tc.settings == "" {
				tc.settings = `{"clients":[],"decryption":"none"}`
			}
			config := loopbackConfig(t, dto.XrayConfigDto{ApiPort: smokePort(t), Port: smokePort(t), Protocol: "vless", Tag: "user", Settings: tc.settings, StreamSettings: tc.stream, Template: tc.template})
			output, err := exec.Command(binary, "run", "-test", "-config", writeSmokeConfig(t, config)).CombinedOutput()
			if err == nil || !strings.Contains(string(output), tc.message) {
				t.Fatalf("expected explicit %q rejection, got %v:\n%s", tc.message, err, output)
			}
		})
	}
}
