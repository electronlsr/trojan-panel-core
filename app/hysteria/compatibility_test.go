package hysteria

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"trojan-panel-core/core"
	"trojan-panel-core/model/constant"
	"trojan-panel-core/model/dto"
)

func TestHysteria1ConfigContract(t *testing.T) {
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
	if err := os.MkdirAll(constant.HysteriaPath, 0755); err != nil {
		t.Fatal(err)
	}
	for _, protocol := range []string{"udp", "faketcp", "wechat-video"} {
		config := dto.HysteriaConfigDto{ApiPort: 30800, Port: 443, Protocol: protocol, Obfs: "legacy-obfs", UpMbps: 20, DownMbps: 40}
		if err := initHysteria(config); err != nil {
			t.Fatal(err)
		}
		data, err := os.ReadFile(filepath.Join(constant.HysteriaPath, "config-30800.json"))
		if err != nil {
			t.Fatal(err)
		}
		var got struct {
			Listen, Protocol, Cert, Key, Obfs string
			UpMbps                            int `json:"up_mbps"`
			DownMbps                          int `json:"down_mbps"`
			Auth                              struct {
				Mode   string
				Config struct {
					HTTP string `json:"http"`
				}
			}
		}
		if err := json.Unmarshal(data, &got); err != nil {
			t.Fatal(err)
		}
		if got.Listen != ":443" || got.Protocol != protocol || got.Obfs != "legacy-obfs" || got.UpMbps != 20 || got.DownMbps != 40 || got.Cert != "server.crt" || got.Key != "server.key" {
			t.Fatalf("Hysteria1 config contract changed: %+v", got)
		}
		if got.Auth.Mode != "external" || got.Auth.Config.HTTP != "http://127.0.0.1:8082/api/auth/hysteria" {
			t.Fatal("Hysteria1 panel auth callback changed")
		}
	}
}

func TestHysteria1ExternalAuthPayload(t *testing.T) {
	// Hysteria1 v1.3.5 marshals its []byte payload as one layer of base64.
	request, _ := json.Marshal(struct {
		Payload []byte `json:"payload"`
	}{[]byte("account-password")})
	var got dto.HysteriaAuthDto
	if err := json.Unmarshal(request, &got); err != nil {
		t.Fatal(err)
	}
	if got.Payload == nil {
		t.Fatal("external auth payload was lost")
	}
	decoded, err := base64.StdEncoding.DecodeString(*got.Payload)
	if err != nil || string(decoded) != "account-password" {
		t.Fatal("Hysteria1 auth DTO no longer matches upstream")
	}
}
