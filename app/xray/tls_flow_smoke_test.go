package xray

import (
	"bufio"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"trojan-panel-core/core"
	"trojan-panel-core/dao"
	rds "trojan-panel-core/dao/redis"
	"trojan-panel-core/internal/proxytest"
	"trojan-panel-core/model"
	"trojan-panel-core/model/constant"
	"trojan-panel-core/model/dto"
	"trojan-panel-core/util"
)

// Exercise the real AddUser path, including persisted SQLite node metadata,
// a Redis protocol fixture, the legacy RPC SDK, and real Trojan/VLESS TCP+TLS traffic.
// This is deliberately not described as a full MariaDB/Redis deployment test.
func TestStableXrayTLSWithPersistedFlow(t *testing.T) {
	xrayBinary := stableXrayBinary(t)
	dir := proxytest.Workdir(t)
	if err := os.MkdirAll(constant.SqlitePath, 0700); err != nil {
		t.Fatal(err)
	}
	dao.InitSqlLite()
	t.Cleanup(dao.CloseSqliteDb)
	old := *core.Config
	t.Cleanup(func() { *core.Config = old })
	core.Config.RedisConfig = core.RedisConfig{Host: "127.0.0.1", Port: flowRedisFixture(t), MaxIdle: 2, MaxActive: 4, Wait: true}
	rds.InitRedis()
	t.Cleanup(rds.CloseRedis)
	cert, key := proxytest.Certificate(t, dir)
	certBytes, err := os.ReadFile(cert)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(certBytes) {
		t.Fatal("test certificate was not loaded")
	}
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = io.WriteString(w, "trojan-tls-persisted-flow") }))
	t.Cleanup(target.Close)
	_, targetPortString, _ := net.SplitHostPort(strings.TrimPrefix(target.URL, "http://"))
	targetPort, _ := strconv.Atoi(targetPortString)
	for _, protocol := range []string{"trojan", "vless"} {
		flows := []string{"", "none"}
		if protocol == "trojan" {
			flows = append(flows, "xtls-rprx-vision", "xtls-rprx-direct", "NONE", " none ")
		}
		for _, flow := range flows {
			t.Run(protocol+"/flow="+flow, func(t *testing.T) {
				apiPort, serverPort := smokePort(t), smokePort(t)
				stream := fmt.Sprintf(`{"network":"tcp","security":"tls","tcpSettings":{"header":{"type":"none"}},"tlsSettings":{"serverName":"localhost","allowInsecure":false,"certificates":[{"certificateFile":%q,"keyFile":%q}]}}`, cert, key)
				settings := `{"clients":[],"fallbacks":[]}`
				if protocol == "vless" {
					settings = `{"clients":[],"decryption":"none"}`
				}
				config := loopbackConfig(t, dto.XrayConfigDto{ApiPort: apiPort, Port: serverPort, Protocol: protocol, Tag: "user", Settings: settings, StreamSettings: stream})
				startSmokeXray(t, xrayBinary, config, apiPort)
				if err := dao.InsertNodeConfig(model.NodeConfig{ApiPort: apiPort, NodeTypeId: constant.Xray, Protocol: protocol, XrayFlow: flow}); err != nil {
					t.Fatal(err)
				}
				// Reopen the database to ensure the fixture uses persisted metadata.
				dao.CloseSqliteDb()
				dao.InitSqlLite()
				api := NewXrayApi(apiPort)
				const password = "isolated-trojan-tls-flow-user"
				for attempt := 0; attempt < 2; attempt++ {
					if err := api.AddUser(dto.XrayAddUserDto{Protocol: protocol, Password: password}); err != nil {
						t.Fatalf("actual AddUser for persisted flow %q: %v", flow, err)
					}
				}
				// A distinct second user exercises the cached metadata path too.
				if err := api.AddUser(dto.XrayAddUserDto{Protocol: protocol, Password: "second-flow-user"}); err != nil {
					t.Fatal(err)
				}
				stored, err := dao.SelectNodeConfigByNodeTypeIdAndApiPort(apiPort, constant.Xray)
				if err != nil || stored.XrayFlow != flow {
					t.Fatalf("saved flow changed: %+v, %v", stored, err)
				}
				conn, err := tls.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", serverPort), &tls.Config{RootCAs: roots, ServerName: "localhost", MinVersion: tls.VersionTLS12})
				if err != nil {
					t.Fatal(err)
				}
				defer conn.Close()
				_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
				hash := sha256.Sum224([]byte(password))
				header := append([]byte(hex.EncodeToString(hash[:])+"\r\n"), 1, 1, 127, 0, 0, 1)
				header = binary.BigEndian.AppendUint16(header, uint16(targetPort))
				header = append(header, '\r', '\n')
				if protocol == "vless" {
					id, err := hex.DecodeString(strings.ReplaceAll(util.GenerateUUID(password), "-", ""))
					if err != nil {
						t.Fatal(err)
					}
					header = append([]byte{0}, id...)
					header = append(header, 0, 1) // no addons, TCP command
					header = binary.BigEndian.AppendUint16(header, uint16(targetPort))
					header = append(header, 1, 127, 0, 0, 1) // IPv4 target
				}
				header = append(header, []byte("GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")...)
				if _, err = conn.Write(header); err != nil {
					t.Fatal(err)
				}
				if protocol == "vless" {
					responseHeader := make([]byte, 2)
					if _, err := io.ReadFull(conn, responseHeader); err != nil {
						t.Fatal(err)
					}
					if responseHeader[0] != 0 || responseHeader[1] != 0 {
						t.Fatalf("invalid VLESS response header: %x", responseHeader)
					}
				}
				response, err := http.ReadResponse(bufio.NewReader(conn), nil)
				if err != nil {
					t.Fatalf("%s TCP+TLS forwarding: %v", protocol, err)
				}
				body, err := io.ReadAll(response.Body)
				_ = response.Body.Close()
				if err != nil || string(body) != "trojan-tls-persisted-flow" {
					t.Fatalf("forwarding body %q: %v", body, err)
				}
				stats, err := api.GetUserStats(password, "downlink", false)
				if err != nil || stats == nil || stats.Value <= 0 {
					t.Fatalf("traffic stats: %+v, %v", stats, err)
				}
				if err := api.DeleteUser(password); err != nil {
					t.Fatal(err)
				}
			})
		}
	}
}

// Minimal loopback RESP cache: all node metadata originates in the real
// disposable SQLite database. Cache hits use the same JSON as production.
func flowRedisFixture(t *testing.T) int {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	cache := map[string]string{}
	var mu sync.Mutex
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				reader := bufio.NewReader(conn)
				for {
					line, err := reader.ReadString('\n')
					if err != nil {
						return
					}
					count, err := strconv.Atoi(strings.TrimSpace(strings.TrimPrefix(line, "*")))
					if err != nil || count < 1 {
						return
					}
					args := make([]string, count)
					for i := range args {
						line, err = reader.ReadString('\n')
						if err != nil {
							return
						}
						size, err := strconv.Atoi(strings.TrimSpace(strings.TrimPrefix(line, "$")))
						if err != nil || size < 0 {
							return
						}
						data := make([]byte, size+2)
						if _, err = io.ReadFull(reader, data); err != nil {
							return
						}
						args[i] = string(data[:size])
					}
					switch strings.ToUpper(args[0]) {
					case "PING":
						_, _ = io.WriteString(conn, "+PONG\r\n")
					case "SELECT", "AUTH":
						_, _ = io.WriteString(conn, "+OK\r\n")
					case "GET":
						mu.Lock()
						value, ok := cache[args[1]]
						mu.Unlock()
						if ok {
							_, _ = fmt.Fprintf(conn, "$%d\r\n%s\r\n", len(value), value)
						} else {
							_, _ = io.WriteString(conn, "$-1\r\n")
						}
					case "SET":
						if !json.Valid([]byte(args[2])) {
							return
						}
						mu.Lock()
						cache[args[1]] = args[2]
						mu.Unlock()
						_, _ = io.WriteString(conn, "+OK\r\n")
					default:
						_, _ = io.WriteString(conn, "-ERR unsupported fixture command\r\n")
					}
				}
			}()
		}
	}()
	return listener.Addr().(*net.TCPAddr).Port
}
