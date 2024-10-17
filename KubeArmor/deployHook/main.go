package main

import (
	"encoding/json"
    "io"
    "log"
    "os"
    "path/filepath"
	hooks "github.com/containers/common/pkg/hooks/1.0.0"
	"github.com/opencontainers/runtime-spec/specs-go"
)

func applyPodmanHook() error {
	hookDir := "/etc/containers/oci/hooks.d/"
	if err := os.MkdirAll(hookDir, 0750); err != nil {
		return err
	}

	dst, err := os.OpenFile(filepath.Join(hookDir, "ka.json"), os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}
	defer dst.Close()

	always := true
	hook := hooks.Hook{
		Version: "1.0.0",
		Hook: specs.Hook{
			Path: "/usr/share/kubearmor/hook", 
			Args: []string{
				"/usr/share/kubearmor/hook",
				"--runtime-socket",
				"/run/podman/podman.sock",

			},
		},
		When: hooks.When{Always: &always},
		Stages: []string{
			"poststart", 
			"poststop",  
		},
	}

	hookBytes, err := json.Marshal(hook)
	if err != nil {
		return err
	}

	_, err = dst.Write(hookBytes)
	if err != nil {
		return err
	}

	kaDir := "/usr/share/kubearmor"
	if err := os.MkdirAll(kaDir, 0750); err != nil {
		return err
	}

	dstBin, err := os.OpenFile(filepath.Join(kaDir, "hook"), os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0755)
	if err != nil {
		return err
	}
	defer dstBin.Close()

	srcBin, err := os.Open("/hook") 
	if err != nil {
		return err
	}
	defer srcBin.Close()

	if _, err := io.Copy(dstBin, srcBin); err != nil {
		return err
	}

	return nil
}
func main(){
	err := applyPodmanHook()
    if err != nil {
        log.Printf("Podman hook injection failed: %v", err)
    } else {
        log.Printf("Podman OCI hook injected successfully")
    }
}
