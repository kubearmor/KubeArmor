package main

import (
    "io"
    "log"
    "os"
    "path/filepath"
)

func applyPodmanHook() error {
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
