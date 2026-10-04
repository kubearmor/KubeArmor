// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 Authors of KubeArmor

package core

import (
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/fsnotify/fsnotify"
	tp "github.com/kubearmor/KubeArmor/KubeArmor/types"
)

func (dm *KubeArmorDaemon) HandleFile(file string) {
	var f *os.File
	var err error
	fileFound := false
	timeNow := time.Now()
	for {
		if time.Since(timeNow) > 300*time.Second {
			dm.Logger.Errf("Timed out waiting for OCI hook file '%s'", file)
			return
		}
		if _, err := os.Stat(filepath.Clean(file)); errors.Is(err, os.ErrNotExist) {
			if !fileFound {
				dm.Logger.Warnf("OCI hook file '%s' not found; retrying", file)
				fileFound = true
			}
			select {
			case <-StopChan:
				return
			case <-time.After(time.Second):
			}
			continue
		}
		f, err = os.Open(filepath.Clean(file)) // #nosec G304
		if err != nil {
			dm.Logger.Errf("Failed to open file '%s': %v. Ensure the file exists and has appropriate permissions.", file, err)
			return
		}
		break
	}

	decoder := json.NewDecoder(f)
	for {
		var containerData tp.Container

		err = decoder.Decode(&containerData)
		if err != nil {
			if err == io.EOF {
				dm.Logger.Warnf("Reached the end of file '%s'.", file)
				break
			}
			dm.Logger.Errf("Error decoding JSON from file '%s': %v. Verify the file's format and content.", file, err)
			break
		}
		dm.HandleContainerCreateForKata(containerData)
	}

	defer f.Close()

	w, err := fsnotify.NewWatcher()
	if err != nil {
		dm.Logger.Errf("Error creating new watcher: (%s)", err.Error())
	}
	defer w.Close()

	err = w.Add(file)
	if err != nil {
		dm.Logger.Errf("Error adding file to watcher: (%s)", err.Error())
	}

	for {
		select {
		case <-StopChan:
			return

		case err, ok := <-w.Errors:
			if !ok {
				dm.Logger.Warnf("Watcher error channel closed unexpectedly. Exiting watcher loop.")
				return
			}
			dm.Logger.Errf("Watcher error: (%s)", err.Error())

		case e, ok := <-w.Events:
			if !ok {
				dm.Logger.Warnf("File watcher event channel closed unexpectedly. Exiting watcher loop.")
				return
			}

			if e.Op&fsnotify.Write == fsnotify.Write {
				f, err := os.Open(filepath.Clean(file)) // #nosec G304
				if err != nil {
					dm.Logger.Errf("Error opening file: (%s)", err.Error())
					continue
				}
				defer f.Close()

				decoder := json.NewDecoder(f)
				for {
					var containerData tp.Container

					err = decoder.Decode(&containerData)
					if err != nil {
						if err == io.EOF {
							dm.Logger.Warnf("Reached the end of file '%s' after reload.", file)
							break
						}
						dm.Logger.Errf("Error decoding JSON from file '%s' after reload: %v. Verify the file's format and content.", file, err)
						break
					}
					dm.HandleContainerCreateForKata(containerData)
				}
			}
		}
	}
}
