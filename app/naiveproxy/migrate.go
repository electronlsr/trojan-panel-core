package naiveproxy

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

// migrateLegacyAuth preserves unknown configuration fields and converts only
// forward_proxy handlers. Caddy's strict decoder rejects the removed fields.
func migrateLegacyAuth(data json.RawMessage) (json.RawMessage, bool, error) {
	var value any
	if err := json.Unmarshal(data, &value); err != nil {
		return nil, false, err
	}
	switch value.(type) {
	case map[string]any:
		var object map[string]json.RawMessage
		if err := json.Unmarshal(data, &object); err != nil {
			return nil, false, err
		}
		changed := false
		var handler string
		_ = json.Unmarshal(object["handler"], &handler)
		if handler == "forward_proxy" {
			user, hasUser := object["auth_user_deprecated"]
			pass, hasPass := object["auth_pass_deprecated"]
			if hasUser || hasPass {
				// An explicitly configured current credential list takes precedence.
				if credentials, exists := object["auth_credentials"]; !exists || bytes.Equal(bytes.TrimSpace(credentials), []byte("null")) {
					var username, password string
					if hasUser {
						if err := json.Unmarshal(user, &username); err != nil {
							return nil, false, err
						}
					}
					if hasPass {
						if err := json.Unmarshal(pass, &password); err != nil {
							return nil, false, err
						}
					}
					object["auth_credentials"], _ = json.Marshal([][]byte{encodeCredential(username, password)})
				}
				delete(object, "auth_user_deprecated")
				delete(object, "auth_pass_deprecated")
				changed = true
			}
		}
		for key, child := range object {
			migrated, childChanged, err := migrateLegacyAuth(child)
			if err != nil {
				return nil, false, err
			}
			if childChanged {
				object[key] = migrated
				changed = true
			}
		}
		if !changed {
			return data, false, nil
		}
		result, err := json.MarshalIndent(object, "", "    ")
		return result, true, err
	case []any:
		var array []json.RawMessage
		if err := json.Unmarshal(data, &array); err != nil {
			return nil, false, err
		}
		changed := false
		for index, child := range array {
			migrated, childChanged, err := migrateLegacyAuth(child)
			if err != nil {
				return nil, false, err
			}
			if childChanged {
				array[index] = migrated
				changed = true
			}
		}
		if !changed {
			return data, false, nil
		}
		result, err := json.MarshalIndent(array, "", "    ")
		return result, true, err
	default:
		return data, false, nil
	}
}

func migrateNaiveProxyConfig(path string) error {
	original, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	migrated, changed, err := migrateLegacyAuth(original)
	if err != nil {
		return fmt.Errorf("migrate NaiveProxy config %s: %w", path, err)
	}
	if !changed {
		return nil
	}
	info, err := os.Stat(path)
	if err != nil {
		return err
	}
	// Retain the untouched original for rollback; never replace an earlier backup.
	if err := persistConfigBackup(path+".pre-auth-credentials", original, info.Mode().Perm()); err != nil {
		return fmt.Errorf("back up NaiveProxy config %s: %w", path, err)
	}
	temporary, err := os.CreateTemp(filepath.Dir(path), ".naiveproxy-config-*")
	if err != nil {
		return err
	}
	defer os.Remove(temporary.Name())
	defer temporary.Close()
	if err := temporary.Chmod(info.Mode().Perm()); err != nil {
		return err
	}
	if _, err := temporary.Write(migrated); err != nil {
		return err
	}
	if err := temporary.Sync(); err != nil {
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	return os.Rename(temporary.Name(), path)
}

type backupWriter interface {
	Write([]byte) (int, error)
	Sync() error
	Close() error
}

func finishConfigBackup(path string, writer backupWriter, original []byte) error {
	written, writeErr := writer.Write(original)
	if writeErr == nil && written != len(original) {
		writeErr = io.ErrShortWrite
	}
	var syncErr error
	if writeErr == nil {
		syncErr = writer.Sync()
	}
	closeErr := writer.Close()
	if err := errors.Join(writeErr, syncErr, closeErr); err != nil {
		// This path was exclusively created by this attempt. A partial backup
		// must never become the rollback copy accepted by a later attempt.
		return errors.Join(err, os.Remove(path))
	}
	return nil
}

func persistConfigBackup(path string, original []byte, mode os.FileMode) error {
	backup, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if err == nil {
		return finishConfigBackup(path, backup, original)
	}
	if !os.IsExist(err) {
		return err
	}
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("existing rollback backup is not a regular file")
	}
	saved, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	if !json.Valid(saved) || !bytes.Equal(saved, original) {
		return fmt.Errorf("existing rollback backup does not match the original config; preserve it elsewhere before retrying")
	}
	return nil
}
