package process

import (
	"context"
	"errors"
	"fmt"
	"github.com/sirupsen/logrus"
	"os/exec"
	"strings"
	"sync"
	"time"
	"trojan-panel-core/model/constant"
	"trojan-panel-core/util"
)

var mutexXray sync.Mutex
var cmdMapXray sync.Map

type XrayProcess struct {
	process
}

func NewXrayProcess() *XrayProcess {
	return &XrayProcess{process{mutex: &mutexXray, binaryType: constant.Xray, cmdMap: &cmdMapXray}}
}

func (x *XrayProcess) StopXrayProcess() error {
	apiPorts, err := util.GetConfigApiPorts(constant.XrayPath)
	if err != nil {
		return err
	}
	for _, apiPort := range apiPorts {
		if err = x.Stop(apiPort, true); err != nil {
			return err
		}
	}
	return nil
}

func (x *XrayProcess) StartXray(apiPort uint) error {
	defer x.mutex.Unlock()
	if x.mutex.TryLock() {
		if x.IsRunning(apiPort) {
			return nil
		}
		binaryFilePath, err := util.GetBinaryFile(constant.Xray)
		if err != nil {
			return err
		}
		configFilePath, err := util.GetConfigFile(constant.Xray, apiPort)
		if err != nil {
			return err
		}
		// Validate with the bundled version before spawning. Removed legacy
		// options must fail visibly without deleting the saved configuration.
		if err := validateXrayConfig(binaryFilePath, configFilePath); err != nil {
			return err
		}
		cmd := exec.Command(binaryFilePath, "run", "-config", configFilePath)
		if cmd.Err != nil {
			if err = util.RemoveFile(configFilePath); err != nil {
				return err
			}
			logrus.Errorf("xray command error err: %v", err)
			return errors.New(constant.XrayStartError)
		}
		if err := cmd.Start(); err != nil {
			if err = util.RemoveFile(configFilePath); err != nil {
				return err
			}
			logrus.Errorf("start xray error err: %v", err)
			return errors.New(constant.XrayStartError)
		}
		x.cmdMap.Store(apiPort, cmd)

		// timeout
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		done := make(chan error)
		go func() {
			done <- cmd.Wait()
			select {
			case err := <-done:
				if err != nil {
					logrus.Errorf("xray process wait error err: %v", err)
					x.releaseProcess(apiPort, configFilePath)
				}
			case <-ctx.Done():
				logrus.Errorf("xray process wait timeout err: %v", err)
				x.releaseProcess(apiPort, configFilePath)
			}
		}()
		return nil
	}
	logrus.Errorf("start xray error err: lock not acquired")
	return errors.New(constant.XrayStartError)
}

func (x *XrayProcess) releaseProcess(apiPort uint, configFilePath string) {
	load, ok := NewXrayProcess().GetCmdMap().Load(apiPort)
	if ok {
		cmd := load.(*exec.Cmd)
		if !cmd.ProcessState.Success() {
			x.cmdMap.Delete(apiPort)
			if err := cmd.Process.Release(); err != nil {
				logrus.Errorf("xray process release error err: %v", err)
			}
			if err := util.RemoveFile(configFilePath); err != nil {
				logrus.Errorf("xray process remove file error err: %v", err)
			}
		}
	}
}

func GetXrayState(apiPort uint) bool {
	_, ok := NewXrayProcess().GetCmdMap().Load(apiPort)
	return ok
}

// validateXrayConfig reports the real core diagnostic instead of treating a
// short-lived process as healthy. It never rewrites or removes the config.
func validateXrayConfig(binaryFilePath, configFilePath string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	output, err := exec.CommandContext(ctx, binaryFilePath, "run", "-test", "-config", configFilePath).CombinedOutput()
	if err != nil {
		if ctx.Err() != nil {
			return fmt.Errorf("xray configuration validation timed out: %w", ctx.Err())
		}
		return fmt.Errorf("xray configuration rejected by the bundled core: %w: %s", err, strings.TrimSpace(string(output)))
	}
	return nil
}
