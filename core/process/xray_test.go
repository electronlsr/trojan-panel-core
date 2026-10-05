package process

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestXrayPreflightPreservesRejectedConfiguration(t *testing.T) {
	dir := t.TempDir()
	config := filepath.Join(dir, "config.json")
	original := []byte(`{"legacy":"preserve for manual migration"}`)
	if err := os.WriteFile(config, original, 0600); err != nil {
		t.Fatal(err)
	}
	binary := filepath.Join(dir, "xray")
	script := "#!/bin/sh\n[ \"$1\" = run ] && [ \"$2\" = -test ] && [ \"$3\" = -config ] || exit 3\necho 'QUIC transport has been removed' >&2\nexit 23\n"
	if err := os.WriteFile(binary, []byte(script), 0700); err != nil {
		t.Fatal(err)
	}
	err := validateXrayConfig(binary, config)
	if err == nil || !strings.Contains(err.Error(), "QUIC transport has been removed") {
		t.Fatalf("missing actionable diagnostic: %v", err)
	}
	got, err := os.ReadFile(config)
	if err != nil || string(got) != string(original) {
		t.Fatalf("saved config changed: %q, %v", got, err)
	}
}

func TestXrayPreflightAcceptsValidConfiguration(t *testing.T) {
	binary := filepath.Join(t.TempDir(), "xray")
	if err := os.WriteFile(binary, []byte("#!/bin/sh\nexit 0\n"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := validateXrayConfig(binary, "config.json"); err != nil {
		t.Fatal(err)
	}
}
