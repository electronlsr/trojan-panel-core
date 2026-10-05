package xray

import (
	"encoding/json"
	"errors"
	"fmt"
	"github.com/sirupsen/logrus"
	"os"
	"trojan-panel-core/core"
	"trojan-panel-core/core/process"
	"trojan-panel-core/model/bo"
	"trojan-panel-core/model/constant"
	"trojan-panel-core/model/dto"
	"trojan-panel-core/util"
)

func InitXrayApp() error {
	apiPorts, err := util.GetConfigApiPorts(constant.XrayPath)
	if err != nil {
		return err
	}
	return startXrayInstances(apiPorts, process.NewXrayProcess().StartXray)
}

// One rejected legacy config must not keep independent valid nodes offline.
func startXrayInstances(apiPorts []uint, start func(uint) error) error {
	var failures []error
	for _, apiPort := range apiPorts {
		if err := start(apiPort); err != nil {
			failures = append(failures, fmt.Errorf("xray node API port %d: %w", apiPort, err))
		}
	}
	return errors.Join(failures...)
}

func StartXray(xrayConfigDto dto.XrayConfigDto) error {
	var err error
	if err = initXray(xrayConfigDto); err != nil {
		return err
	}
	if err = process.NewXrayProcess().StartXray(xrayConfigDto.ApiPort); err != nil {
		return err
	}
	return nil
}

func StopXray(apiPort uint, removeFile bool) error {
	if err := process.NewXrayProcess().Stop(apiPort, removeFile); err != nil {
		logrus.Errorf("xray stop err: %v", err)
		return err
	}
	return nil
}

func RestartXray(apiPort uint) error {
	if err := StopXray(apiPort, false); err != nil {
		return err
	}
	if err := StartXray(dto.XrayConfigDto{
		ApiPort: apiPort,
	}); err != nil {
		return err
	}
	return nil
}

func initXray(xrayConfigDto dto.XrayConfigDto) error {
	certConfig := core.Config.CertConfig
	configContentByte, err := buildXrayConfig(xrayConfigDto, bo.Certificate{
		CertificateFile: certConfig.CrtPath,
		KeyFile:         certConfig.KeyPath,
	})
	if err != nil {
		return err
	}
	// Do not truncate an existing config until the replacement has been built.
	xrayConfigFilePath := fmt.Sprintf("%s/config-%d-%s.json", constant.XrayPath, xrayConfigDto.ApiPort, xrayConfigDto.Protocol)
	if err := os.WriteFile(xrayConfigFilePath, configContentByte, 0666); err != nil {
		logrus.Errorf("xray file config.json write err: %v", err)
		return err
	}
	return nil
}

// buildXrayConfig keeps the template and stream settings opaque. Xray adds new
// settings independently of the panel; decoding them into a partial DTO silently
// discards options such as xhttpSettings, grpcSettings, sockopt and TLS options.
func buildXrayConfig(xrayConfigDto dto.XrayConfigDto, certificate bo.Certificate) ([]byte, error) {
	// generate corresponding configuration files according to different protocols, and account information is created through a new synchronous coroutine
	if xrayConfigDto.Template == "" {
		xrayConfigDto.Template = `{
    "log": {
        "loglevel": "warning"
    },
    "inbounds": [],
    "outbounds": [
        {
            "protocol": "freedom"
        }
    ],
    "api": {
        "tag": "api",
        "services": [
            "HandlerService",
            "LoggerService",
            "StatsService"
        ]
    },
    "routing": {
        "rules": [
            {
                "inboundTag": [
                    "api"
                ],
                "outboundTag": "api",
                "type": "field"
            }
        ]
    },
    "stats": {},
    "policy": {
        "levels": {
            "0": {
                "statsUserUplink": true,
                "statsUserDownlink": true
            }
        },
        "system": {
            "statsInboundUplink": true,
            "statsInboundDownlink": true
        }
    }
}`
	}
	xrayConfig := map[string]json.RawMessage{}
	if err := json.Unmarshal([]byte(xrayConfigDto.Template), &xrayConfig); err != nil {
		return nil, fmt.Errorf("xray template config deserialization: %w", err)
	}
	if xrayConfig == nil {
		return nil, errors.New("xray template config must be an object")
	}
	var inbounds []json.RawMessage
	if raw, ok := xrayConfig["inbounds"]; ok {
		if err := json.Unmarshal(raw, &inbounds); err != nil {
			return nil, fmt.Errorf("xray template inbounds deserialization: %w", err)
		}
	}
	streamSettingsStr, err := buildStreamSettings(xrayConfigDto.StreamSettings, certificate)
	if err != nil {
		return nil, err
	}

	// add inbound protocol
	apiInbound, err := json.Marshal(bo.InboundBo{
		Listen:   "127.0.0.1",
		Port:     xrayConfigDto.ApiPort,
		Protocol: "dokodemo-door",
		Settings: bo.TypeMessage("{\"address\": \"127.0.0.1\"}"),
		Tag:      "api",
	})

	if err != nil {
		return nil, err
	}
	userInbound, err := json.Marshal(bo.InboundBo{
		Listen:         "0.0.0.0",
		Port:           xrayConfigDto.Port,
		Protocol:       xrayConfigDto.Protocol,
		Settings:       bo.TypeMessage(xrayConfigDto.Settings),
		StreamSettings: streamSettingsStr,
		Tag:            xrayConfigDto.Tag,
		Sniffing:       bo.TypeMessage(xrayConfigDto.Sniffing),
		Allocate:       bo.TypeMessage(xrayConfigDto.Allocate),
	})
	if err != nil {
		return nil, err
	}
	inbounds = append(inbounds, apiInbound, userInbound)
	xrayConfig["inbounds"], err = json.Marshal(inbounds)
	if err != nil {
		return nil, err
	}
	return json.MarshalIndent(xrayConfig, "", "    ")
}

func buildStreamSettings(raw string, certificate bo.Certificate) ([]byte, error) {
	if raw == "" {
		return []byte("{}"), nil
	}
	settings := map[string]json.RawMessage{}
	if err := json.Unmarshal([]byte(raw), &settings); err != nil {
		return nil, fmt.Errorf("xray streamSettings deserialization: %w", err)
	}
	if settings == nil {
		return nil, errors.New("xray streamSettings must be an object")
	}
	var security string
	if value, ok := settings["security"]; ok {
		if err := json.Unmarshal(value, &security); err != nil {
			return nil, fmt.Errorf("xray streamSettings security: %w", err)
		}
	}
	if security == "tls" {
		tls := map[string]json.RawMessage{}
		if value, ok := settings["tlsSettings"]; ok {
			if err := json.Unmarshal(value, &tls); err != nil {
				return nil, fmt.Errorf("xray tlsSettings deserialization: %w", err)
			}
		}
		if tls == nil {
			tls = map[string]json.RawMessage{}
		}
		var certificates []json.RawMessage
		if value, ok := tls["certificates"]; ok {
			if err := json.Unmarshal(value, &certificates); err != nil {
				return nil, fmt.Errorf("xray TLS certificates deserialization: %w", err)
			}
		}
		if len(certificates) == 0 {
			value, err := json.Marshal([]bo.Certificate{certificate})
			if err != nil {
				return nil, err
			}
			tls["certificates"] = value
		}
		value, err := json.Marshal(tls)
		if err != nil {
			return nil, err
		}
		settings["tlsSettings"] = value
	}
	return json.Marshal(settings)
}

func InitXrayBinFile() error {
	xrayPath := constant.XrayPath
	if !util.Exists(xrayPath) {
		if err := os.MkdirAll(xrayPath, os.ModePerm); err != nil {
			logrus.Errorf("create xray folder err: %v", err)
			return err
		}
	}

	binaryFilePath, err := util.GetBinaryFilePath(constant.Xray)
	if err != nil {
		return err
	}
	if !util.Exists(binaryFilePath) {
		logrus.Errorf("xray binary does not exist")
		return errors.New(constant.BinaryFileNotExist)
	}
	return nil
}
