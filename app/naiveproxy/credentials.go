package naiveproxy

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"trojan-panel-core/model/bo"
)

// forwardproxy's [][]byte JSON field encodes the bytes of the HTTP Basic
// credential, which are already base64 encoded. Do not encode username:password
// only once: those credentials parse successfully but cannot authenticate.
func encodeCredential(username, password string) []byte {
	return []byte(base64.StdEncoding.EncodeToString([]byte(username + ":" + password)))
}

type authHandler struct {
	bo.HandleAuth
	AuthCredentials [][]byte `json:"auth_credentials"`
}

type userEntry struct {
	user            bo.HandleAuth
	handlerIndex    int
	credentialIndex int
	credentialCount int
}

func decodeUsers(handlers []authHandler) ([]userEntry, error) {
	entries := make([]userEntry, 0, len(handlers))
	for index, handler := range handlers {
		if handler.AuthCredentials == nil {
			// Old saved configs and old Caddy admin responses remain readable.
			entries = append(entries, userEntry{user: handler.HandleAuth, handlerIndex: index})
			continue
		}
		for credentialIndex, encoded := range handler.AuthCredentials {
			decoded, err := base64.StdEncoding.DecodeString(string(encoded))
			if err != nil {
				return nil, fmt.Errorf("invalid forward_proxy credential: %w", err)
			}
			username, password, ok := strings.Cut(string(decoded), ":")
			if !ok {
				return nil, fmt.Errorf("forward_proxy credential is missing its username separator")
			}
			user := handler.HandleAuth
			user.AuthUserDeprecated = username
			user.AuthPassDeprecated = password
			entries = append(entries, userEntry{user: user, handlerIndex: index,
				credentialIndex: credentialIndex, credentialCount: len(handler.AuthCredentials)})
		}
	}
	return entries, nil
}

func marshalAuthHandler(user bo.HandleAuth) ([]byte, error) {
	data, err := json.Marshal(user)
	if err != nil {
		return nil, err
	}
	var handler map[string]json.RawMessage
	if err := json.Unmarshal(data, &handler); err != nil {
		return nil, err
	}
	delete(handler, "auth_user_deprecated")
	delete(handler, "auth_pass_deprecated")
	handler["auth_credentials"], err = json.Marshal([][]byte{encodeCredential(user.AuthUserDeprecated, user.AuthPassDeprecated)})
	if err != nil {
		return nil, err
	}
	return json.Marshal(handler)
}
