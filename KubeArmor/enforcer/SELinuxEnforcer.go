// SPDX-License-Identifier: Apache-2.0
// Copyright 2026  Authors of KubeArmor

package enforcer

import (
	"os"
	"path/filepath"
	"strings"
	"sync"

	kl "github.com/kubearmor/KubeArmor/KubeArmor/common"
	cfg "github.com/kubearmor/KubeArmor/KubeArmor/config"
	fd "github.com/kubearmor/KubeArmor/KubeArmor/feeder"
	tp "github.com/kubearmor/KubeArmor/KubeArmor/types"
)

// ====================== //
// == SELinux Enforcer == //
// ====================== //

// SELinuxEnforcer Structure
type SELinuxEnforcer struct {
	// logs
	Logger *fd.Feeder

	// policy enforcer
	SELinuxTemplatePath string

	// host profile
	HostProfile         string
	SELinuxProfilesLock *sync.Mutex
}

// NewSELinuxEnforcer Function
func NewSELinuxEnforcer(node tp.Node, logger *fd.Feeder) *SELinuxEnforcer {
	se := &SELinuxEnforcer{}

	// logs
	se.Logger = logger

	homeDir, err := filepath.Abs(filepath.Dir(os.Args[0]))
	if err != nil {
		se.Logger.Errf("Failed to get the current directory (%s)", err.Error())
		return nil
	}

	// to get SELinux modules and inject/remove new modules
	if _, err := os.Stat(filepath.Clean("/usr/sbin/semanage")); err != nil {
		se.Logger.Errf("Failed to find /usr/sbin/semanage (%s)", err.Error())
		return nil
	}

	// to change the labels of files and directories
	if _, err := os.Stat(filepath.Clean("/usr/bin/chcon")); err != nil {
		se.Logger.Errf("Failed to find /usr/bin/chcon (%s)", err.Error())
		return nil
	}

	// to recover the original labels of files and directories
	if _, err := os.Stat(filepath.Clean("/usr/sbin/restorecon")); err != nil {
		se.Logger.Errf("Failed to find /usr/sbin/restorecon (%s)", err.Error())
		return nil
	}

	// SELinux templates
	templatePath := homeDir + "/templates"
	if _, err := os.Stat(filepath.Clean(templatePath + "/install.sh")); err != nil {
		// go test
		templatePath = os.Getenv("PWD") + "/../templates"
		if _, err := os.Stat(filepath.Clean(templatePath + "/install.sh")); err != nil {
			se.Logger.Err("Failed to find templates/install.sh")
			return nil
		}
	}
	se.SELinuxTemplatePath = templatePath

	// check the SELinux profile directory
	if ok := strings.HasSuffix(cfg.GlobalCfg.SELinuxProfileDir, "/"); !ok {
		cfg.GlobalCfg.SELinuxProfileDir = cfg.GlobalCfg.SELinuxProfileDir + "/"
	}

	// remove old profiles if exists
	if err = os.RemoveAll(filepath.Clean(cfg.GlobalCfg.SELinuxProfileDir)); err != nil {
		se.Logger.Errf("Failed to remove existing SELinux profiles (%s)", err.Error())
		return nil
	}

	// create a profile directory if not exists
	if err := os.MkdirAll(filepath.Clean(cfg.GlobalCfg.SELinuxProfileDir), 0750); err != nil {
		se.Logger.Errf("Failed to create %s (%s)", cfg.GlobalCfg.SELinuxProfileDir, err.Error())
		return nil
	}

	// host profile
	se.HostProfile = "kubearmor.host"
	se.SELinuxProfilesLock = &sync.Mutex{}

	if cfg.GlobalCfg.HostPolicy {
		if ok := se.RegisterSELinuxHostProfile(); !ok {
			return nil
		}
	}

	// karmor modules
	if ok := se.InstallSELinuxModulesIfNeeded(); !ok {
		se.Logger.Warnf("Unable to install SELinux modules required by the KubeArmor host profile in %s", cfg.GlobalCfg.Host)
		return nil
	}

	return se
}

// DestroySELinuxEnforcer Function
func (se *SELinuxEnforcer) DestroySELinuxEnforcer() error {
	// skip if SELinuxEnforcer is not active
	if se == nil {
		return nil
	}

	if cfg.GlobalCfg.HostPolicy {
		se.UnregisterSELinuxHostProfile()
	}

	se = nil
	return nil
}

// ===================================== //
// == SELinux Host Profile Management == //
// ===================================== //

// RegisterSELinuxHostProfile Function
func (se *SELinuxEnforcer) RegisterSELinuxHostProfile() bool {
	// skip if SELinuxEnforcer is not active
	if se == nil {
		return true
	}

	se.SELinuxProfilesLock.Lock()
	defer se.SELinuxProfilesLock.Unlock()

	newFile, err := os.Create(filepath.Clean(cfg.GlobalCfg.SELinuxProfileDir + se.HostProfile))
	if err != nil {
		se.Logger.Warnf("Unable to create the KubeArmor host profile in %s (%s)", cfg.GlobalCfg.Host, err.Error())
		return false
	}

	if _, err := newFile.WriteString(""); err != nil {
		se.Logger.Warnf("Unable to update the KubeArmor host profile in %s (%s)", cfg.GlobalCfg.Host, err.Error())
		return false
	}

	if err := newFile.Close(); err != nil {
		se.Logger.Warnf("Unable to close the KubeArmor host profile in %s (%s)", cfg.GlobalCfg.Host, err.Error())
		return false
	}

	if ok := se.UpdateSELinuxLabels(cfg.GlobalCfg.SELinuxProfileDir + se.HostProfile); !ok {
		se.Logger.Warnf("Unable to register the KubeArmor host profile in %s", cfg.GlobalCfg.Host)
		return false
	}

	se.Logger.Printf("Registered the KubeArmor host profile in %s", cfg.GlobalCfg.Host)

	return true
}

// UnregisterSELinuxHostProfile Function
func (se *SELinuxEnforcer) UnregisterSELinuxHostProfile() bool {
	// skip if SELinuxEnforcer is not active
	if se == nil {
		return true
	}

	se.SELinuxProfilesLock.Lock()
	defer se.SELinuxProfilesLock.Unlock()

	newFile, err := os.Create(filepath.Clean(cfg.GlobalCfg.SELinuxProfileDir + se.HostProfile))
	if err != nil {
		se.Logger.Warnf("Unable to open the KubeArmor host profile in %s (%s)", cfg.GlobalCfg.Host, err.Error())
		return false
	}

	if _, err := newFile.WriteString(""); err != nil {
		se.Logger.Warnf("Unable to update the KubeArmor host profile in %s (%s)", cfg.GlobalCfg.Host, err.Error())
		return false
	}

	if err := newFile.Close(); err != nil {
		se.Logger.Warnf("Unable to close the KubeArmor host profile in %s (%s)", cfg.GlobalCfg.Host, err.Error())
		return false
	}

	if ok := se.UpdateSELinuxLabels(cfg.GlobalCfg.SELinuxProfileDir + se.HostProfile); !ok {
		se.Logger.Warnf("Unable to unregister the KubeArmor host profile in %s", cfg.GlobalCfg.Host)
		return false
	}

	se.Logger.Printf("Unregistered the KubeArmor host profile from %s", cfg.GlobalCfg.Host)

	return true
}

// ====================================== //
// == Host Security Policy Enforcement == //
// ====================================== //

// UpdateSELinuxHostProfile Function
func (se *SELinuxEnforcer) UpdateSELinuxHostProfile(secPolicies []tp.HostSecurityPolicy) {
	globalDefaultPosture := tp.DefaultPosture{
		FileAction:         cfg.GlobalCfg.HostDefaultFilePosture,
		NetworkAction:      cfg.GlobalCfg.HostDefaultNetworkPosture,
		CapabilitiesAction: cfg.GlobalCfg.HostDefaultCapabilitiesPosture,
	}

	if policyCount, newProfile, ok := se.GenerateSELinuxHostProfile(secPolicies, globalDefaultPosture); ok {
		newFile, err := os.Create(filepath.Clean(cfg.GlobalCfg.SELinuxProfileDir + se.HostProfile))
		if err != nil {
			se.Logger.Warnf("Unable to open the KubeArmor host profile in %s (%s)", cfg.GlobalCfg.Host, err.Error())
			return
		}

		if _, err := newFile.WriteString(newProfile); err != nil {
			se.Logger.Warnf("Unable to update the KubeArmor host profile in %s (%s)", cfg.GlobalCfg.Host, err.Error())

			if err := newFile.Close(); err != nil {
				se.Logger.Warnf("Unable to close the KubeArmor host profile in %s (%s)", cfg.GlobalCfg.Host, err.Error())
			}

			return
		}

		if err := newFile.Sync(); err != nil {
			se.Logger.Warnf("Unable to sync the KubeArmor host profile in %s (%s)", cfg.GlobalCfg.Host, err.Error())

			if err := newFile.Close(); err != nil {
				se.Logger.Warnf("Unable to close the KubeArmor host profile in %s (%s)", cfg.GlobalCfg.Host, err.Error())
			}

			return
		}

		if err := newFile.Close(); err != nil {
			se.Logger.Warnf("Unable to close the KubeArmor host profile in %s (%s)", cfg.GlobalCfg.Host, err.Error())
			return
		}

		if ok := se.UpdateSELinuxLabels(cfg.GlobalCfg.SELinuxProfileDir + se.HostProfile); !ok {
			se.Logger.Warnf("Unable to update SELinux labels affected by the KubeArmor host profile in %s", cfg.GlobalCfg.Host)
			return
		}

		se.Logger.Printf("Updated %d host security rule(s) to the KubeArmor host profile in %s", policyCount, cfg.GlobalCfg.Host)
	}
}

// UpdateHostSecurityPolicies Function
func (se *SELinuxEnforcer) UpdateHostSecurityPolicies(secPolicies []tp.HostSecurityPolicy) {
	// skip if SELinuxEnforcer is not active
	if se == nil {
		return
	}

	if cfg.GlobalCfg.HostPolicy {
		se.UpdateSELinuxHostProfile(secPolicies)
	} else {
		se.UpdateSELinuxHostProfile([]tp.HostSecurityPolicy{})
	}
}

// ============================= //
// == SELinux Rule Management == //
// ============================= //

// ContainsElement Function
func (se *SELinuxEnforcer) ContainsElement(rules []tp.SELinuxRule, newRule tp.SELinuxRule) bool {
	for _, rule := range rules {
		if rule.SubjectPath == newRule.SubjectPath && rule.ObjectPath == newRule.ObjectPath {
			return true
		}
	}
	return false
}

// InstallSELinuxModulesIfNeeded Function
func (se *SELinuxEnforcer) InstallSELinuxModulesIfNeeded() bool {
	modules := []string{}

	res, err := kl.GetCommandOutputWithErr("/usr/sbin/semanage", []string{"module", "-l"})
	if err != nil {
		se.Logger.Warnf("Unable to read the list of SELinux modules (%s)", err.Error())
		return false
	}

	for line := range strings.SplitSeq(res, "\n") {
		// fields: ModuleName Priority Language
		words := strings.Fields(line)

		if len(words) == 3 && strings.HasPrefix(words[0], "karmor") {
			modules = append(modules, words[0])
		}
	}

	if kl.ContainsElement(modules, "karmor") {
		return true
	}

	se.Logger.Printf("Installing a SELinux module (it will take a couple of minutes)")

	if err := kl.RunCommandAndWaitWithErr(se.SELinuxTemplatePath+"/install.sh", []string{}); err == nil {
		se.Logger.Printf("Installed the SELinux module")
	} else {
		se.Logger.Warnf("Unable to install a SELinux module")
		return false
	}

	return true
}

// RestoreSELinuxLabels Function
func (se *SELinuxEnforcer) RestoreSELinuxLabels(profilePath string) bool {
	if _, err := os.Stat(filepath.Clean(profilePath + ".old")); err != nil {
		return true
	}

	profile, err := os.ReadFile(filepath.Clean(profilePath + ".old"))
	if err != nil {
		se.Logger.Warnf("Unable to read %s", profilePath+".old")
		return false
	}

	res := true

	for line := range strings.SplitSeq(string(profile), "\n") {
		// fields: SubjectLabel SubjectPath ObjectLabel ObjectPath Permissive Directory Recursive

		words := strings.Fields(line)
		if len(words) != 7 {
			continue
		}

		subjectPath := words[1]
		objectPath := words[3]

		permissive := words[4]

		directory := words[5]
		recursive := words[6]

		if permissive == "true" {
			continue
		}

		if subjectPath == "-" {
			if directory == "true" {
				if recursive == "true" {
					err := filepath.Walk(objectPath, func(file string, info os.FileInfo, err error) error {
						if err == nil {
							if info.IsDir() {
								return nil
							}

							if err := kl.RunCommandAndWaitWithErr("restorecon", []string{"-v", "-F", file}); err != nil {
								se.Logger.Warnf("Unable to restore the SELinux label of %s (%s)", file, err.Error())
								res = false
							}

							return nil
						}

						return err
					})

					if err != nil {
						se.Logger.Warnf("Failed to walk %s", objectPath)
						res = false
					}
				} else {
					if files, err := os.ReadDir(objectPath); err == nil {
						for _, file := range files {
							if file.IsDir() {
								continue
							}

							if err := kl.RunCommandAndWaitWithErr("restorecon", []string{"-v", "-F", objectPath + file.Name()}); err != nil {
								se.Logger.Warnf("Unable to restore the SELinux label of %s (%s)", objectPath+file.Name(), err.Error())
								res = false
							}
						}
					}
				}
			} else { // file
				if err := kl.RunCommandAndWaitWithErr("restorecon", []string{"-v", "-F", objectPath}); err != nil {
					se.Logger.Warnf("Unable to restore the SELinux label of %s (%s)", objectPath, err.Error())
					res = false
				}
			}
		} else { // fromSource
			if directory == "true" {
				if recursive == "true" {
					if err := kl.RunCommandAndWaitWithErr("restorecon", []string{"-v", "-F", subjectPath}); err != nil {
						se.Logger.Warnf("Unable to restore the SELinux label of %s (%s)", subjectPath, err.Error())
						res = false
					}

					err := filepath.Walk(objectPath, func(file string, info os.FileInfo, err error) error {
						if err == nil {
							if info.IsDir() {
								return nil
							}

							if err := kl.RunCommandAndWaitWithErr("restorecon", []string{"-v", "-F", file}); err != nil {
								se.Logger.Warnf("Unable to restore the SELinux label of %s (%s)", file, err.Error())
								res = false
							}

							return nil
						}

						return err
					})

					if err != nil {
						se.Logger.Warnf("Failed to walk %s", objectPath)
						res = false
					}
				} else {
					if err := kl.RunCommandAndWaitWithErr("restorecon", []string{"-v", "-F", subjectPath}); err != nil {
						se.Logger.Warnf("Unable to restore the SELinux label of %s (%s)", subjectPath, err.Error())
						res = false
					}

					if files, err := os.ReadDir(objectPath); err == nil {
						for _, file := range files {
							if file.IsDir() {
								continue
							}

							if err := kl.RunCommandAndWaitWithErr("restorecon", []string{"-v", "-F", objectPath + file.Name()}); err != nil {
								se.Logger.Warnf("Unable to restore the SELinux label of %s (%s)", objectPath+file.Name(), err.Error())
								res = false
							}
						}
					}
				}
			} else { // file
				if err := kl.RunCommandAndWaitWithErr("restorecon", []string{"-v", "-F", subjectPath}); err != nil {
					se.Logger.Warnf("Unable to restore the SELinux label of %s (%s)", subjectPath, err.Error())
					res = false
				}

				if err := kl.RunCommandAndWaitWithErr("restorecon", []string{"-v", "-F", objectPath}); err != nil {
					se.Logger.Warnf("Unable to restore the SELinux label of %s (%s)", objectPath, err.Error())
					res = false
				}
			}
		}
	}

	return res
}

// UpdateSELinuxLabels Function
func (se *SELinuxEnforcer) UpdateSELinuxLabels(profilePath string) bool {
	if _, err := os.Stat(filepath.Clean(profilePath)); err != nil {
		se.Logger.Warnf("Unable to find %s", profilePath)
		return false
	}

	if ok := se.RestoreSELinuxLabels(profilePath); !ok {
		se.Logger.Warnf("Unable to restore the original SELinux labels affected by %s", profilePath)
	}

	if err := kl.CopyFile(profilePath, profilePath+".old"); err != nil {
		se.Logger.Warnf("Unable to create %s.old", profilePath)
	}

	profile, err := os.ReadFile(filepath.Clean(profilePath))
	if err != nil {
		se.Logger.Warnf("Unable to read %s", profilePath)
		return false
	}

	res := true

	for line := range strings.SplitSeq(string(profile), "\n") {
		// fields: SubjectLabel SubjectPath ObjectLabel ObjectPath Permissive Directory Recursive

		words := strings.Fields(line)
		if len(words) != 7 {
			continue
		}

		subjectLabel := words[0]
		subjectPath := words[1]

		objectLabel := words[2]
		objectPath := words[3]

		permissive := words[4]

		directory := words[5]
		recursive := words[6]

		if permissive == "true" {
			continue
		}

		if subjectLabel == "-" {
			if directory == "true" {
				if recursive == "true" {
					err := filepath.Walk(objectPath, func(file string, info os.FileInfo, err error) error {
						if err == nil {
							if info.IsDir() {
								return nil
							}

							if err := kl.RunCommandAndWaitWithErr("chcon", []string{"-t", objectLabel, file}); err != nil {
								se.Logger.Warnf("Unable to update the SELinux label (%s) of %s (%s)", objectLabel, file, err.Error())
								res = false
							}

							return nil
						}

						return err
					})

					if err != nil {
						se.Logger.Warnf("Failed to walk %s", objectPath)
						res = false
					}
				} else {
					if files, err := os.ReadDir(objectPath); err == nil {
						for _, file := range files {
							if file.IsDir() {
								continue
							}

							if err := kl.RunCommandAndWaitWithErr("chcon", []string{"-t", objectLabel, objectPath + file.Name()}); err != nil {
								se.Logger.Warnf("Unable to update the SELinux label (%s) of %s (%s)", objectLabel, objectPath+file.Name(), err.Error())
								res = false
							}
						}
					}
				}
			} else { // file
				if err := kl.RunCommandAndWaitWithErr("chcon", []string{"-t", objectLabel, objectPath}); err != nil {
					se.Logger.Warnf("Unable to update the SELinux label (%s) of %s (%s)", objectLabel, objectPath, err.Error())
					res = false
				}
			}
		} else { // fromSource
			if directory == "true" {
				if recursive == "true" {
					if err := kl.RunCommandAndWaitWithErr("chcon", []string{"-t", subjectLabel, subjectPath}); err != nil {
						se.Logger.Warnf("Unable to update the SELinux label (%s) of %s (%s)", subjectLabel, subjectPath, err.Error())
						res = false
					}

					err := filepath.Walk(objectPath, func(file string, info os.FileInfo, err error) error {
						if err == nil {
							if info.IsDir() {
								return nil
							}

							if err := kl.RunCommandAndWaitWithErr("chcon", []string{"-t", objectLabel, file}); err != nil {
								se.Logger.Warnf("Unable to update the SELinux label (%s) of %s (%s)", objectLabel, file, err.Error())
								res = false
							}

							return nil
						}

						return err
					})

					if err != nil {
						se.Logger.Warnf("Failed to walk %s", objectPath)
						res = false
					}
				} else {
					if err := kl.RunCommandAndWaitWithErr("chcon", []string{"-t", subjectLabel, subjectPath}); err != nil {
						se.Logger.Warnf("Unable to update the SELinux label (%s) of %s (%s)", subjectLabel, subjectPath, err.Error())
						res = false
					}

					if files, err := os.ReadDir(objectPath); err == nil {
						for _, file := range files {
							if file.IsDir() {
								continue
							}

							if err := kl.RunCommandAndWaitWithErr("chcon", []string{"-t", objectLabel, objectPath + file.Name()}); err != nil {
								se.Logger.Warnf("Unable to update the SELinux label (%s) of %s (%s)", objectLabel, objectPath+file.Name(), err.Error())
								res = false
							}
						}
					}
				}
			} else { // file
				if err := kl.RunCommandAndWaitWithErr("chcon", []string{"-t", subjectLabel, subjectPath}); err != nil {
					se.Logger.Warnf("Unable to update the SELinux label (%s) of %s (%s)", subjectLabel, subjectPath, err.Error())
					res = false
				}

				if err := kl.RunCommandAndWaitWithErr("chcon", []string{"-t", objectLabel, objectPath}); err != nil {
					se.Logger.Warnf("Unable to update the SELinux label (%s) of %s (%s)", objectLabel, objectPath, err.Error())
					res = false
				}
			}
		}
	}

	return res
}
