package hysteria2

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
	"trojan-panel-core/model/constant"
	"trojan-panel-core/model/dto"
)

func TestHysteria2ConfigContract(t *testing.T) {
	oldDir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(t.TempDir()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chdir(oldDir) })
	oldConfig := core.Config
	core.Config = &core.AppConfig{CertConfig: core.CertConfig{CrtPath: "server.crt", KeyPath: "server.key"}, ServerConfig: core.ServerConfig{Port: 8082}}
	t.Cleanup(func() { core.Config = oldConfig })
	if err := os.MkdirAll(constant.Hysteria2Path, 0755); err != nil {
		t.Fatal(err)
	}
	for _, obfs := range []string{"", "salamander-password"} {
		if err := initHysteria2(dto.Hysteria2ConfigDto{ApiPort: 30900, Port: 443, UpMbps: 20, DownMbps: 40, ObfsPassword: obfs}); err != nil {
			t.Fatal(err)
		}
		data, err := os.ReadFile(filepath.Join(constant.Hysteria2Path, "config-30900.json"))
		if err != nil {
			t.Fatal(err)
		}
		var got struct {
			Listen    string
			TLS       struct{ Cert, Key string }
			Bandwidth struct{ Up, Down string }
			Auth      struct {
				Type string
				HTTP struct {
					URL      string
					Insecure bool
				}
			}
			TrafficStats struct{ Listen string } `json:"trafficStats"`
			Obfs         *struct {
				Type       string
				Salamander struct{ Password string }
			}
		}
		if err := json.Unmarshal(data, &got); err != nil {
			t.Fatal(err)
		}
		if got.Listen != ":443" || got.TLS.Cert != "server.crt" || got.TLS.Key != "server.key" || got.Bandwidth.Up != "20 mbps" || got.Bandwidth.Down != "40 mbps" {
			t.Fatalf("Hysteria2 config changed: %+v", got)
		}
		if got.Auth.Type != "http" || got.Auth.HTTP.URL != "http://127.0.0.1:8082/api/auth/hysteria2" || got.TrafficStats.Listen != ":30900" {
			t.Fatal("panel auth or stats API changed")
		}
		if obfs == "" && got.Obfs != nil {
			t.Fatal("obfs unexpectedly enabled")
		}
		if obfs != "" && (got.Obfs == nil || got.Obfs.Type != "salamander" || got.Obfs.Salamander.Password != obfs) {
			t.Fatal("obfs settings lost")
		}
	}
}

func TestHysteria2TrafficContract(t *testing.T) {
	cleared := false
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != "/traffic" {
			t.Errorf("unexpected stats request: %s %s", r.Method, r.URL)
		}
		if cleared {
			fmt.Fprint(w, `{}`)
			return
		}
		fmt.Fprint(w, `{"account-password":{"tx":1234,"rx":5678}}`)
		if r.URL.Query().Get("clear") == "1" {
			cleared = true
		}
	}))
	defer server.Close()
	api := NewHysteria2Api(uint(server.Listener.Addr().(*net.TCPAddr).Port))
	user, err := api.GetUser("account-password", false)
	if err != nil || user.Pass != "account-password" || user.Tx != 1234 || user.Rx != 5678 {
		t.Fatalf("traffic contract changed: %+v, %v", user, err)
	}
	users, err := api.ListUsers(true)
	if err != nil || users["account-password"].Rx != 5678 || !cleared {
		t.Fatal("atomic read/clear contract changed")
	}
	users, err = api.ListUsers(false)
	if err != nil || len(users) != 0 {
		t.Fatal("traffic counters were not cleared")
	}
}

func TestHysteria2ExternalAuthPayload(t *testing.T) {
	var got dto.Hysteria2AuthDto
	if err := json.Unmarshal([]byte(`{"addr":"127.0.0.1:3000","auth":"account-password","tx":1250000}`), &got); err != nil {
		t.Fatal(err)
	}
	if got.Auth == nil || *got.Auth != "account-password" {
		t.Fatal("Hysteria2 HTTP auth DTO no longer matches upstream")
	}
}
