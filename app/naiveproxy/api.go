package naiveproxy

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/sirupsen/logrus"
	"io"
	"net/http"
	"time"
	"trojan-panel-core/model/bo"
	"trojan-panel-core/model/constant"
	"trojan-panel-core/model/dto"
)

type naiveProxyApi struct {
	apiPort uint
}

func NewNaiveProxyApi(apiPort uint) *naiveProxyApi {
	return &naiveProxyApi{
		apiPort: apiPort,
	}
}

// ListUsers query all users on a node
func (n *naiveProxyApi) listHandlers() ([]authHandler, error) {
	url := fmt.Sprintf("http://127.0.0.1:%d/config/apps/http/servers/srv0/routes/0/handle/0/routes/0/handle/", n.apiPort)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		logrus.Errorf("NaiveProxy ListUsers NewRequest err: %v", err)
		return nil, errors.New(constant.SysError)
	}
	resp, err := http.DefaultClient.Do(req)
	defer func() {
		if resp != nil {
			resp.Body.Close()
		}
	}()
	if err != nil || resp.StatusCode != http.StatusOK {
		logrus.Errorf("NaiveProxy ListUsers http resp err: %v", err)
		return nil, errors.New(constant.SysError)
	}
	contentByte, err := io.ReadAll(resp.Body)
	if err != nil {
		logrus.Errorf("NaiveProxy ListUsers IO err: %v", err)
		return nil, errors.New(constant.SysError)
	}
	var handleAuths []authHandler
	if err = json.Unmarshal(contentByte, &handleAuths); err != nil {
		logrus.Errorf("NaiveProxy ListUsers Unmarshal err: %v", err)
		return nil, errors.New(constant.SysError)
	}
	return handleAuths, nil
}

// ListUsers keeps the panel-facing identity fields stable while reading either
// the legacy or current forwardproxy configuration format.
func (n *naiveProxyApi) ListUsers() (*[]bo.HandleAuth, error) {
	handlers, err := n.listHandlers()
	if err != nil {
		return nil, err
	}
	entries, err := decodeUsers(handlers)
	if err != nil {
		return nil, err
	}
	users := make([]bo.HandleAuth, 0, len(entries))
	for _, entry := range entries {
		users = append(users, entry.user)
	}
	return &users, nil
}

// GetUser returns the actual Caddy handler index, including multi-user handlers.
func (n *naiveProxyApi) GetUser(pass string) (*bo.HandleAuth, *int, error) {
	handlers, err := n.listHandlers()
	if err != nil {
		return nil, nil, err
	}
	entries, err := decodeUsers(handlers)
	if err != nil {
		return nil, nil, err
	}
	for _, entry := range entries {
		if entry.user.AuthPassDeprecated == pass {
			return &entry.user, &entry.handlerIndex, nil
		}
	}
	return nil, nil, nil
}

// AddUser add user on node
func (n *naiveProxyApi) AddUser(dto dto.NaiveProxyAddUserDto) error {
	user, _, err := n.GetUser(dto.Pass)
	if err != nil {
		return err
	}
	if user != nil {
		return nil
	}

	authJsonStr := `{
    "handler":"forward_proxy",
    "hide_ip":true,
    "hide_via":true,
    "probe_resistance":{}
}`
	var handleAuth *bo.HandleAuth
	if err = json.Unmarshal([]byte(authJsonStr), &handleAuth); err != nil {
		logrus.Errorf("NaiveProxy AddUser Unmarshal err: %v", err)
		return errors.New(constant.SysError)
	}
	handleAuth.AuthUserDeprecated = dto.Username
	handleAuth.AuthPassDeprecated = dto.Pass
	addUserDtoByte, err := marshalAuthHandler(*handleAuth)
	if err != nil {
		logrus.Errorf("NaiveProxy AddUser Marshal err: %v", err)
		return errors.New(constant.SysError)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	url := fmt.Sprintf("http://127.0.0.1:%d/config/apps/http/servers/srv0/routes/0/handle/0/routes/0/handle/0", n.apiPort)
	req, err := http.NewRequestWithContext(ctx, "POST", url,
		bytes.NewBuffer(addUserDtoByte))
	if err != nil {
		logrus.Errorf("NaiveProxy AddUser NewRequest err: %v", err)
		return errors.New(constant.SysError)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	defer func() {
		if resp != nil {
			resp.Body.Close()
		}
	}()
	if err != nil || resp.StatusCode != http.StatusOK {
		logrus.Errorf("NaiveProxy AddUser resp err: %v", err)
		return errors.New(constant.SysError)
	}
	return nil
}

// DeleteUser removes only the requested account. When a manually configured
// handler contains several credentials, retain the other accounts and options.
func (n *naiveProxyApi) DeleteUser(pass string) error {
	handlers, err := n.listHandlers()
	if err != nil {
		return err
	}
	entries, err := decodeUsers(handlers)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		if entry.user.AuthPassDeprecated != pass {
			continue
		}
		method := http.MethodDelete
		url := fmt.Sprintf("http://127.0.0.1:%d/config/apps/http/servers/srv0/routes/0/handle/0/routes/0/handle/%d", n.apiPort, entry.handlerIndex)
		var body []byte
		if entry.credentialCount > 1 {
			method = http.MethodPatch
			url += "/auth_credentials"
			credentials := handlers[entry.handlerIndex].AuthCredentials
			credentials = append(credentials[:entry.credentialIndex], credentials[entry.credentialIndex+1:]...)
			body, err = json.Marshal(credentials)
			if err != nil {
				return err
			}
		}
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		req, err := http.NewRequestWithContext(ctx, method, url, bytes.NewReader(body))
		if err != nil {
			return errors.New(constant.SysError)
		}
		if body != nil {
			req.Header.Set("Content-Type", "application/json")
		}
		resp, err := http.DefaultClient.Do(req)
		if resp != nil {
			defer resp.Body.Close()
		}
		if err != nil || resp.StatusCode != http.StatusOK {
			logrus.Errorf("NaiveProxy DeleteUser resp err: %v", err)
			return errors.New(constant.SysError)
		}
		return nil
	}
	return nil
}
