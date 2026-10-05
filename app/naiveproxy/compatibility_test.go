package naiveproxy

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"trojan-panel-core/model/bo"
	"trojan-panel-core/model/dto"
)

func testNaiveAPI(t *testing.T, handler http.HandlerFunc) *naiveProxyApi {
	t.Helper()
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)
	return NewNaiveProxyApi(uint(server.Listener.Addr().(*net.TCPAddr).Port))
}

func TestCurrentCredentialEncoding(t *testing.T) {
	wire, err := marshalAuthHandler(bo.HandleAuth{AuthUserDeprecated: "alice", AuthPassDeprecated: "secret:with:colons"})
	if err != nil {
		t.Fatal(err)
	}
	var object map[string]json.RawMessage
	if err := json.Unmarshal(wire, &object); err != nil {
		t.Fatal(err)
	}
	if _, exists := object["auth_pass_deprecated"]; exists {
		t.Fatal("removed credential field was emitted")
	}
	if _, exists := object["auth_user_deprecated"]; exists {
		t.Fatal("removed username field was emitted")
	}
	var credentials [][]byte
	if err := json.Unmarshal(object["auth_credentials"], &credentials); err != nil {
		t.Fatal(err)
	}
	want := base64.StdEncoding.EncodeToString([]byte("alice:secret:with:colons"))
	if len(credentials) != 1 || string(credentials[0]) != want {
		t.Fatalf("HTTP Basic credential mismatch: %q", credentials)
	}
	// Exactly the bytes compared to Proxy-Authorization by official forwardproxy.
	var handler authHandler
	if err := json.Unmarshal(wire, &handler); err != nil {
		t.Fatal(err)
	}
	users, err := decodeUsers([]authHandler{handler})
	if err != nil || len(users) != 1 || users[0].user.AuthPassDeprecated != "secret:with:colons" {
		t.Fatalf("credential round trip failed: %#v, %v", users, err)
	}
}

func TestNaiveAccountLifecycleCurrentAPI(t *testing.T) {
	const path = "/config/apps/http/servers/srv0/routes/0/handle/0/routes/0/handle/"
	handlers := []json.RawMessage{}
	posts, deletes := 0, 0
	api := testNaiveAPI(t, func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == path:
			json.NewEncoder(w).Encode(handlers)
		case r.Method == http.MethodPost && r.URL.Path == path+"0":
			if r.Header.Get("Content-Type") != "application/json" {
				t.Error("missing JSON content type")
			}
			var handler json.RawMessage
			if err := json.NewDecoder(r.Body).Decode(&handler); err != nil {
				t.Error(err)
				w.WriteHeader(400)
				return
			}
			if strings.Contains(string(handler), "_deprecated") {
				t.Error("deprecated fields sent to new Caddy")
			}
			handlers = append([]json.RawMessage{handler}, handlers...)
			posts++
		case r.Method == http.MethodDelete && r.URL.Path == path+"0":
			handlers = handlers[1:]
			deletes++
		default:
			t.Errorf("unexpected request %s %s", r.Method, r.URL)
			w.WriteHeader(400)
		}
	})
	account := dto.NaiveProxyAddUserDto{Username: "alice", Pass: "secret"}
	if err := api.AddUser(account); err != nil {
		t.Fatal(err)
	}
	if err := api.AddUser(account); err != nil {
		t.Fatal(err)
	}
	if posts != 1 {
		t.Fatalf("duplicate account created: %d posts", posts)
	}
	users, err := api.ListUsers()
	if err != nil || len(*users) != 1 || (*users)[0].AuthUserDeprecated != "alice" || (*users)[0].AuthPassDeprecated != "secret" {
		t.Fatalf("panel identity contract changed: %#v, %v", users, err)
	}
	if err := api.DeleteUser("secret"); err != nil {
		t.Fatal(err)
	}
	if err := api.DeleteUser("secret"); err != nil {
		t.Fatal(err)
	}
	if deletes != 1 || len(handlers) != 0 {
		t.Fatal("account removal is not idempotent")
	}
}

func TestNaiveLegacyAndMultiCredentialHandlers(t *testing.T) {
	credentials, _ := json.Marshal([][]byte{encodeCredential("first", "first-pass"), encodeCredential("second", "second:pass")})
	body := fmt.Sprintf(`[{"handler":"forward_proxy","auth_user_deprecated":"legacy","auth_pass_deprecated":"legacy-pass"},{"handler":"forward_proxy","auth_credentials":%s}]`, credentials)
	patched := false
	api := testNaiveAPI(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			fmt.Fprint(w, body)
			return
		}
		if r.Method != http.MethodPatch || !strings.HasSuffix(r.URL.Path, "/handle/1/auth_credentials") {
			t.Errorf("wrong account removal: %s %s", r.Method, r.URL.Path)
			w.WriteHeader(400)
			return
		}
		var remaining [][]byte
		if err := json.NewDecoder(r.Body).Decode(&remaining); err != nil {
			t.Error(err)
		}
		if len(remaining) != 1 || string(remaining[0]) != string(encodeCredential("first", "first-pass")) {
			t.Errorf("another account was changed: %q", remaining)
		}
		patched = true
	})
	users, err := api.ListUsers()
	if err != nil || len(*users) != 3 {
		t.Fatalf("users=%#v, err=%v", users, err)
	}
	user, index, err := api.GetUser("second:pass")
	if err != nil || user == nil || index == nil || *index != 1 {
		t.Fatalf("handler index changed: %v %v %v", user, index, err)
	}
	if err := api.DeleteUser("second:pass"); err != nil {
		t.Fatal(err)
	}
	if !patched {
		t.Fatal("account was not removed")
	}
}

func TestNaiveAPIErrors(t *testing.T) {
	for _, body := range []string{`{`, `[{"auth_credentials":["bm90LWJhc2U2NA=="]}]`} {
		t.Run(body, func(t *testing.T) {
			api := testNaiveAPI(t, func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, body) })
			if _, err := api.ListUsers(); err == nil {
				t.Fatal("invalid upstream response accepted")
			}
		})
	}
	api := testNaiveAPI(t, func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusServiceUnavailable) })
	if _, err := api.ListUsers(); err == nil {
		t.Fatal("upstream failure accepted")
	}
}

func TestMigrateExistingNaiveConfig(t *testing.T) {
	original := []byte(`{"apps":{"http":{"routes":[{"handler":"forward_proxy","auth_user_deprecated":"alice","auth_pass_deprecated":"secret:colon","hide_ip":true,"probe_resistance":{},"custom_counter":9007199254740993}]}},"other":{"auth_user_deprecated":"unrelated"}}`)
	path := filepath.Join(t.TempDir(), "config-31000.json")
	if err := os.WriteFile(path, original, 0600); err != nil {
		t.Fatal(err)
	}
	if err := migrateNaiveProxyConfig(path); err != nil {
		t.Fatal(err)
	}
	backup, err := os.ReadFile(path + ".pre-auth-credentials")
	if err != nil || string(backup) != string(original) {
		t.Fatalf("rollback backup missing or changed: %v", err)
	}
	migrated, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(migrated), "9007199254740993") || !strings.Contains(string(migrated), "unrelated") {
		t.Fatal("migration lost unknown data")
	}
	var root struct {
		Apps struct {
			HTTP struct {
				Routes []authHandler `json:"routes"`
			} `json:"http"`
		} `json:"apps"`
	}
	if err := json.Unmarshal(migrated, &root); err != nil {
		t.Fatal(err)
	}
	users, err := decodeUsers(root.Apps.HTTP.Routes)
	if err != nil || len(users) != 1 || users[0].user.AuthPassDeprecated != "secret:colon" {
		t.Fatal("migrated account cannot authenticate")
	}
	info, _ := os.Stat(path)
	if info.Mode().Perm() != 0600 {
		t.Fatal("migration changed config permissions")
	}
	if err := migrateNaiveProxyConfig(path); err != nil {
		t.Fatal(err)
	}
	again, _ := os.ReadFile(path)
	if string(again) != string(migrated) {
		t.Fatal("migration is not idempotent")
	}
}

func TestMigrationKeepsCurrentCredentials(t *testing.T) {
	credentials, _ := json.Marshal([][]byte{encodeCredential("current", "current-pass")})
	original := []byte(fmt.Sprintf(`{"handler":"forward_proxy","auth_credentials":%s,"auth_user_deprecated":"old","auth_pass_deprecated":"old-pass"}`, credentials))
	migrated, changed, err := migrateLegacyAuth(original)
	if err != nil || !changed {
		t.Fatalf("migration failed: %v", err)
	}
	var handler authHandler
	if err := json.Unmarshal(migrated, &handler); err != nil {
		t.Fatal(err)
	}
	users, err := decodeUsers([]authHandler{handler})
	if err != nil || users[0].user.AuthPassDeprecated != "current-pass" {
		t.Fatal("current credential was replaced")
	}
	if strings.Contains(string(migrated), "_deprecated") {
		t.Fatal("removed fields remain")
	}
}

func TestMigrationFailureDoesNotSkipOtherNodes(t *testing.T) {
	oldDir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(t.TempDir()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chdir(oldDir) })
	if err := os.MkdirAll("bin/naiveproxy/config", 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile("bin/naiveproxy/config/config-31001.json", []byte(`{`), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile("bin/naiveproxy/config/config-31002.json", []byte(`{"apps":{}}`), 0600); err != nil {
		t.Fatal(err)
	}
	var started []uint
	err = startNaiveProxyConfigs([]uint{31001, 31002}, func(port uint) error { started = append(started, port); return nil })
	if err == nil || !strings.Contains(err.Error(), "31001") {
		t.Fatal("migration failure was not reported")
	}
	if len(started) != 1 || started[0] != 31002 {
		t.Fatalf("valid node was skipped: %v", started)
	}
}

func TestMigrationNullAndEmptyCredentials(t *testing.T) {
	for _, current := range []string{"null", "[]"} {
		t.Run(current, func(t *testing.T) {
			original := []byte(fmt.Sprintf(`{"handler":"forward_proxy","auth_credentials":%s,"auth_user_deprecated":"legacy","auth_pass_deprecated":"secret"}`, current))
			migrated, changed, err := migrateLegacyAuth(original)
			if err != nil || !changed {
				t.Fatal("legacy fields were not migrated")
			}
			var handler authHandler
			if err := json.Unmarshal(migrated, &handler); err != nil {
				t.Fatal(err)
			}
			if handler.AuthCredentials == nil {
				t.Fatal("migration left authentication disabled")
			}
			users, err := decodeUsers([]authHandler{handler})
			if err != nil {
				t.Fatal(err)
			}
			if current == "null" && (len(users) != 1 || users[0].user.AuthPassDeprecated != "secret") {
				t.Fatal("null credentials suppressed legacy account")
			}
			if current == "[]" && len(users) != 0 {
				t.Fatal("explicit empty credentials did not retain deny-all behavior")
			}
		})
	}
}

type failingBackup struct {
	*os.File
	phase string
}

func (w failingBackup) Write(data []byte) (int, error) {
	if w.phase == "write" {
		n, _ := w.File.Write(data[:1])
		return n, fmt.Errorf("simulated write failure")
	}
	return w.File.Write(data)
}
func (w failingBackup) Sync() error {
	if w.phase == "sync" {
		return fmt.Errorf("simulated sync failure")
	}
	return w.File.Sync()
}
func (w failingBackup) Close() error {
	err := w.File.Close()
	if w.phase == "close" {
		return fmt.Errorf("simulated close failure")
	}
	return err
}

func TestFailedBackupIsRemovedBeforeRetry(t *testing.T) {
	for _, phase := range []string{"write", "sync", "close"} {
		t.Run(phase, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "config.json.pre-auth-credentials")
			file, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
			if err != nil {
				t.Fatal(err)
			}
			original := []byte(`{"handler":"forward_proxy","auth_pass_deprecated":"secret"}`)
			if err := finishConfigBackup(path, failingBackup{File: file, phase: phase}, original); err == nil {
				t.Fatal("backup failure ignored")
			}
			if _, err := os.Stat(path); !os.IsNotExist(err) {
				t.Fatal("partial backup survived failure")
			}
			if err := persistConfigBackup(path, original, 0600); err != nil {
				t.Fatal(err)
			}
			backup, _ := os.ReadFile(path)
			if string(backup) != string(original) {
				t.Fatal("retry did not save full original")
			}
		})
	}
}

func TestMigrationRejectsInvalidBackup(t *testing.T) {
	original := []byte(`{"handler":"forward_proxy","auth_user_deprecated":"legacy","auth_pass_deprecated":"secret"}`)
	for _, kind := range []string{"empty", "invalid", "directory", "symlink", "different"} {
		t.Run(kind, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "config.json")
			if err := os.WriteFile(path, original, 0600); err != nil {
				t.Fatal(err)
			}
			backup := path + ".pre-auth-credentials"
			switch kind {
			case "directory":
				if err := os.Mkdir(backup, 0700); err != nil {
					t.Fatal(err)
				}
			case "symlink":
				if err := os.Symlink(path, backup); err != nil {
					t.Fatal(err)
				}
			case "empty":
				if err := os.WriteFile(backup, nil, 0600); err != nil {
					t.Fatal(err)
				}
			case "invalid":
				if err := os.WriteFile(backup, []byte(`{`), 0600); err != nil {
					t.Fatal(err)
				}
			case "different":
				if err := os.WriteFile(backup, []byte(`{}`), 0600); err != nil {
					t.Fatal(err)
				}
			}
			if err := migrateNaiveProxyConfig(path); err == nil {
				t.Fatal("unsafe rollback backup accepted")
			}
			after, _ := os.ReadFile(path)
			if string(after) != string(original) {
				t.Fatal("failed migration changed original config")
			}
		})
	}
}
