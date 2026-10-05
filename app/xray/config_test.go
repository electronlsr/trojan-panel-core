package xray

import (
	"bytes"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"

	"trojan-panel-core/model/bo"
	"trojan-panel-core/model/dto"
)

func decodeObject(t *testing.T, data []byte) map[string]json.RawMessage {
	t.Helper()
	var value map[string]json.RawMessage
	if err := json.Unmarshal(data, &value); err != nil {
		t.Fatal(err)
	}
	return value
}

func assertJSONEqual(t *testing.T, got, want []byte) {
	t.Helper()
	var a, b interface{}
	decoder := json.NewDecoder(bytes.NewReader(got))
	decoder.UseNumber()
	if err := decoder.Decode(&a); err != nil {
		t.Fatal(err)
	}
	decoder = json.NewDecoder(bytes.NewReader(want))
	decoder.UseNumber()
	if err := decoder.Decode(&b); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(a, b) {
		t.Fatalf("JSON differs:\ngot  %s\nwant %s", got, want)
	}
}

func TestBuildXrayConfigPreservesTemplate(t *testing.T) {
	template := `{"log":{"loglevel":"warning"},"inbounds":[{"port":"10000-10001","protocol":"socks","tag":"custom","settings":{"udp":true},"unknownFutureOption":{"enabled":true}}],"outbounds":[{"protocol":"freedom","settings":{"domainStrategy":"UseIP"}}],"observatory":{"subjectSelector":["upstream"]},"futureOption":{"exactInteger":9007199254740993}}`
	config, err := buildXrayConfig(dto.XrayConfigDto{
		ApiPort: 10085, Port: 10086, Protocol: "vless", Tag: "user",
		Settings: `{"clients":[],"decryption":"none"}`, Template: template,
		Sniffing: `{"enabled":true,"destOverride":["http","tls"]}`,
	}, bo.Certificate{})
	if err != nil {
		t.Fatal(err)
	}
	got, want := decodeObject(t, config), decodeObject(t, []byte(template))
	for key, value := range want {
		if key != "inbounds" {
			assertJSONEqual(t, got[key], value)
		}
	}
	// RawMessage must also retain integers beyond JSON float64 precision.
	if string(got["futureOption"]) == "" || !json.Valid(got["futureOption"]) {
		t.Fatal("missing opaque template field")
	}
	var inbounds []json.RawMessage
	if err := json.Unmarshal(got["inbounds"], &inbounds); err != nil {
		t.Fatal(err)
	}
	var original []json.RawMessage
	_ = json.Unmarshal(want["inbounds"], &original)
	if len(inbounds) != 3 {
		t.Fatalf("got %d inbounds, want 3", len(inbounds))
	}
	assertJSONEqual(t, inbounds[0], original[0])
	api := decodeObject(t, inbounds[1])
	assertJSONEqual(t, api["listen"], []byte(`"127.0.0.1"`))
	assertJSONEqual(t, api["tag"], []byte(`"api"`))
	user := decodeObject(t, inbounds[2])
	assertJSONEqual(t, user["tag"], []byte(`"user"`))
	assertJSONEqual(t, user["settings"], []byte(`{"clients":[],"decryption":"none"}`))
	assertJSONEqual(t, user["sniffing"], []byte(`{"enabled":true,"destOverride":["http","tls"]}`))
}

func TestBuildStreamSettingsPreservesFields(t *testing.T) {
	for _, input := range []string{
		`{"network":"xhttp","xhttpSettings":{"path":"/x","mode":"auto","extra":{"noSSEHeader":true}},"sockopt":{"tcpFastOpen":true}}`,
		`{"network":"grpc","grpcSettings":{"serviceName":"service","multiMode":true}}`,
		`{"network":"tcp","tcpSettings":{"header":{"type":"http","request":{"path":["/probe"]}}}}`,
		`{"network":"httpupgrade","httpupgradeSettings":{"path":"/upgrade","host":"example.invalid"}}`,
		`{"network":"tcp","security":"reality","realitySettings":{"target":"example.invalid:443","shortIds":["abcd"]},"wsSettings":{"path":"/ws"}}`,
		`{"network":"kcp","kcpSettings":{"mtu":1350,"tti":50},"finalmask":{"udp":[]}}`,
		`{"security":"tls","tlsSettings":{"certificates":[{"certificate":["inline-certificate"],"key":["inline-key"],"usage":"encipherment"}],"minVersion":"1.3","pinnedPeerCertSha256":"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef","verifyPeerCertByName":"example.invalid"}}`,
		// Unsupported legacy options must not be silently rewritten to a new protocol.
		`{"network":"quic","security":"xtls","quicSettings":{"security":"aes-128-gcm","key":"example"}}`,
	} {
		t.Run(input, func(t *testing.T) {
			got, err := buildStreamSettings(input, bo.Certificate{CertificateFile: "default.crt", KeyFile: "default.key"})
			if err != nil {
				t.Fatal(err)
			}
			assertJSONEqual(t, got, []byte(input))
		})
	}
}

func TestBuildStreamSettingsInjectsOnlyMissingTLSCertificates(t *testing.T) {
	for _, input := range []string{`{"security":"tls"}`, `{"security":"tls","tlsSettings":null}`, `{"security":"tls","tlsSettings":{"certificates":[],"minVersion":"1.3"}}`} {
		got, err := buildStreamSettings(input, bo.Certificate{CertificateFile: "default.crt", KeyFile: "default.key"})
		if err != nil {
			t.Fatal(err)
		}
		tls := decodeObject(t, decodeObject(t, got)["tlsSettings"])
		assertJSONEqual(t, tls["certificates"], []byte(`[{"certificateFile":"default.crt","keyFile":"default.key"}]`))
		if originalTLS, ok := decodeObject(t, []byte(input))["tlsSettings"]; ok && string(originalTLS) != "null" {
			for key, value := range decodeObject(t, originalTLS) {
				if key != "certificates" {
					assertJSONEqual(t, tls[key], value)
				}
			}
		}
	}
}

func TestBuildXrayConfigRejectsMalformedJSON(t *testing.T) {
	for _, input := range []dto.XrayConfigDto{
		{Template: `null`}, {Template: `[]`}, {Template: `{"inbounds":{}}`},
		{StreamSettings: `null`}, {StreamSettings: `[]`}, {StreamSettings: `{"security":42}`},
		{StreamSettings: `{"security":"tls","tlsSettings":[]}`},
		{StreamSettings: `{"security":"tls","tlsSettings":{"certificates":{}}}`},
		{Settings: `{broken`}, {Sniffing: `broken`},
	} {
		if _, err := buildXrayConfig(input, bo.Certificate{}); err == nil {
			t.Fatalf("expected an error for %#v", input)
		}
	}
}

func TestValidateXrayUserFlow(t *testing.T) {
	for _, tc := range []struct {
		protocol string
		flow     string
		allowed  bool
	}{
		{"trojan", "", true},
		{"trojan", "none", true},
		{"trojan", "NONE", true},
		{"trojan", " none ", true},
		{"trojan", "xtls-rprx-direct", true},
		{"trojan", "xtls-rprx-vision", true},
		{"vless", "", true},
		{"vless", "none", true},
		{"vless", "NONE", false},
		{"vless", " none ", false},
		{"vless", "xtls-rprx-vision", true},
		{"vless", "xtls-rprx-direct", false},
		{"vless", "xtls-rprx-origin", false},
		// The -udp443 suffix is a client-side option, not a server flow.
		{"vless", "xtls-rprx-vision-udp443", false},
		{"vmess", "", true},
		{"shadowsocks", "", true},
	} {
		err := validateXrayUserFlow(tc.protocol, tc.flow)
		if (err == nil) != tc.allowed {
			t.Errorf("validateXrayUserFlow(%q, %q) = %v, allowed=%v", tc.protocol, tc.flow, err, tc.allowed)
		}
	}
}

func TestNormalizeXrayUserFlow(t *testing.T) {
	for input, want := range map[string]string{"": "", "none": "", "NONE": "NONE", " none ": " none ", "xtls-rprx-vision": "xtls-rprx-vision", "xtls-rprx-direct": "xtls-rprx-direct"} {
		if got := normalizeXrayUserFlow(input); got != want {
			t.Errorf("normalizeXrayUserFlow(%q) = %q, want %q", input, got, want)
		}
	}
}

func TestStartupContinuesAfterIncompatibleNode(t *testing.T) {
	rejected := errors.New("legacy QUIC transport removed")
	var started []uint
	err := startXrayInstances([]uint{30001, 30002, 30003}, func(port uint) error {
		started = append(started, port)
		if port == 30001 {
			return rejected
		}
		return nil
	})
	if !reflect.DeepEqual(started, []uint{30001, 30002, 30003}) {
		t.Fatalf("valid later nodes were skipped: %v", started)
	}
	if !errors.Is(err, rejected) || !strings.Contains(err.Error(), "30001") {
		t.Fatalf("missing node-specific diagnostic: %v", err)
	}
	if err := startXrayInstances(nil, func(uint) error { return nil }); err != nil {
		t.Fatal(err)
	}
}
