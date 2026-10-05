package trojango

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"trojan-panel-core/core"
	"trojan-panel-core/internal/proxytest"
	"trojan-panel-core/model/constant"
	"trojan-panel-core/model/dto"
)

func TestTrojanGoOfficialRuntime(t *testing.T) {
	binary := proxytest.Binary(t, "TROJAN_GO_TEST_BINARY")
	dir := proxytest.Workdir(t)
	cert, key := proxytest.Certificate(t, dir)
	oldConfig := core.Config
	core.Config = &core.AppConfig{CertConfig: core.CertConfig{CrtPath: cert, KeyPath: key}}
	t.Cleanup(func() { core.Config = oldConfig })
	apiPort, proxyPort := proxytest.TCPPort(t), proxytest.TCPPort(t)
	if err := os.MkdirAll(constant.TrojanGoPath, 0755); err != nil {
		t.Fatal(err)
	}
	if err := initTrojanGo(dto.TrojanGoConfigDto{ApiPort: uint(apiPort), Port: uint(proxyPort), Sni: "localhost", MuxEnable: 1, WebsocketEnable: 1, WebsocketPath: "/test", WebsocketHost: "localhost"}); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, constant.TrojanGoPath, fmt.Sprintf("config-%d.json", apiPort))
	fallback := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, "local-fallback") }))
	defer fallback.Close()
	fallbackPort := fallback.Listener.Addr().(*net.TCPAddr).Port
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var config map[string]any
	if err := json.Unmarshal(data, &config); err != nil {
		t.Fatal(err)
	}
	config["local_addr"] = "127.0.0.1"
	config["remote_port"] = fallbackPort
	config["ssl"].(map[string]any)["fallback_port"] = fallbackPort
	data, _ = json.Marshal(config)
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	logPath := proxytest.Start(t, binary, "-config", path)
	proxytest.WaitTCP(t, fmt.Sprintf("127.0.0.1:%d", apiPort), logPath)
	testTrojanAccountLifecycle(t, NewTrojanGoApi(uint(apiPort)))
}
