// SPDX-License-Identifier: Apache-2.0
// Copyright 2021 Authors of KubeArmor

package enforcer

import (
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"

	kl "github.com/kubearmor/KubeArmor/KubeArmor/common"
	cfg "github.com/kubearmor/KubeArmor/KubeArmor/config"
	tp "github.com/kubearmor/KubeArmor/KubeArmor/types"
)

// == //

// AllowedProcessMatchPaths Function
func (se *SELinuxEnforcer) AllowedProcessMatchPaths(path tp.ProcessPathType, processWhiteList *[]tp.SELinuxRule, fromSources map[string][]tp.SELinuxRule) {
	if len(path.FromSource) == 0 {
		if path.OwnerOnly {
			rule := tp.SELinuxRule{SubjectLabel: "karmor_exec_t", SubjectPath: "-", ObjectLabel: "karmor_allow_t", ObjectPath: path.Path} // owner
			if !kl.ContainsElement(*processWhiteList, rule) {
				*processWhiteList = append(*processWhiteList, rule)
			}
		} else { // !path.OwnerOnly
			rule := tp.SELinuxRule{SubjectLabel: "karmor_exec_t", SubjectPath: "-", ObjectLabel: "karmor_allow_t", ObjectPath: path.Path}
			if !kl.ContainsElement(*processWhiteList, rule) {
				*processWhiteList = append(*processWhiteList, rule)
			}
		}
	} else {
		for _, src := range path.FromSource {
			source := "*"

			if len(src.Path) > 0 {
				source = src.Path
				if _, ok := fromSources[source]; !ok {
					fromSources[source] = []tp.SELinuxRule{}
				}
			} else {
				continue
			}

			if path.OwnerOnly {
				rule := tp.SELinuxRule{SubjectLabel: "karmor_exec_t", SubjectPath: source, ObjectLabel: "karmor_allow_t", ObjectPath: path.Path} // owner
				if !kl.ContainsElement(fromSources[source], rule) {
					fromSources[source] = append(fromSources[source], rule)
				}
			} else { // !path.OwnerOnly
				rule := tp.SELinuxRule{SubjectLabel: "karmor_exec_t", SubjectPath: source, ObjectLabel: "karmor_allow_t", ObjectPath: path.Path}
				if !kl.ContainsElement(fromSources[source], rule) {
					fromSources[source] = append(fromSources[source], rule)
				}
			}
		}
	}
}

// AllowedProcessMatchDirectories Function
func (se *SELinuxEnforcer) AllowedProcessMatchDirectories(dir tp.ProcessDirectoryType, processWhiteList *[]tp.SELinuxRule, fromSources map[string][]tp.SELinuxRule) {
	if len(dir.FromSource) == 0 {
		if dir.Recursive && dir.OwnerOnly {
			rule := tp.SELinuxRule{SubjectLabel: "karmor_exec_t", SubjectPath: "-", ObjectLabel: "karmor_allow_t", ObjectPath: dir.Directory, Directory: true, Recursive: true} // owner
			if !kl.ContainsElement(*processWhiteList, rule) {
				*processWhiteList = append(*processWhiteList, rule)
			}
		} else if dir.Recursive && !dir.OwnerOnly {
			rule := tp.SELinuxRule{SubjectLabel: "karmor_exec_t", SubjectPath: "-", ObjectLabel: "karmor_allow_t", ObjectPath: dir.Directory, Directory: true, Recursive: true}
			if !kl.ContainsElement(*processWhiteList, rule) {
				*processWhiteList = append(*processWhiteList, rule)
			}
		} else if !dir.Recursive && dir.OwnerOnly {
			rule := tp.SELinuxRule{SubjectLabel: "karmor_exec_t", SubjectPath: "-", ObjectLabel: "karmor_allow_t", ObjectPath: dir.Directory, Directory: true} // owner
			if !kl.ContainsElement(*processWhiteList, rule) {
				*processWhiteList = append(*processWhiteList, rule)
			}
		} else { // !dir.Recursive && !dir.OwnerOnly
			rule := tp.SELinuxRule{SubjectLabel: "karmor_exec_t", SubjectPath: "-", ObjectLabel: "karmor_allow_t", ObjectPath: dir.Directory, Directory: true}
			if !kl.ContainsElement(*processWhiteList, rule) {
				*processWhiteList = append(*processWhiteList, rule)
			}
		}
	} else {
		for _, src := range dir.FromSource {
			source := "*"

			if len(src.Path) > 0 {
				source = src.Path
				if _, ok := fromSources[source]; !ok {
					fromSources[source] = []tp.SELinuxRule{}
				}
			} else {
				continue
			}

			if dir.Recursive && dir.OwnerOnly {
				rule := tp.SELinuxRule{SubjectLabel: "karmor_exec_t", SubjectPath: source, ObjectLabel: "karmor_allow_t", ObjectPath: dir.Directory, Directory: true, Recursive: true} // owner
				if !kl.ContainsElement(fromSources[source], rule) {
					fromSources[source] = append(fromSources[source], rule)
				}
			} else if dir.Recursive && !dir.OwnerOnly {
				rule := tp.SELinuxRule{SubjectLabel: "karmor_exec_t", SubjectPath: source, ObjectLabel: "karmor_allow_t", ObjectPath: dir.Directory, Directory: true, Recursive: true}
				if !kl.ContainsElement(fromSources[source], rule) {
					fromSources[source] = append(fromSources[source], rule)
				}
			} else if !dir.Recursive && dir.OwnerOnly {
				rule := tp.SELinuxRule{SubjectLabel: "karmor_exec_t", SubjectPath: source, ObjectLabel: "karmor_allow_t", ObjectPath: dir.Directory, Directory: true} // owner
				if !kl.ContainsElement(fromSources[source], rule) {
					fromSources[source] = append(fromSources[source], rule)
				}
			} else { // !dir.Recursive && !dir.OwnerOnly
				rule := tp.SELinuxRule{SubjectLabel: "karmor_exec_t", SubjectPath: source, ObjectLabel: "karmor_allow_t", ObjectPath: dir.Directory, Directory: true}
				if !kl.ContainsElement(fromSources[source], rule) {
					fromSources[source] = append(fromSources[source], rule)
				}
			}
		}
	}
}

// AllowedProcessMatchPatterns Function
func (se *SELinuxEnforcer) AllowedProcessMatchPatterns(pat tp.ProcessPatternType, processWhiteList *[]tp.SELinuxRule) {
	if pat.OwnerOnly {
		rule := tp.SELinuxRule{SubjectLabel: "karmor_exec_t", SubjectPath: "-", ObjectLabel: "karmor_allow_t", ObjectPath: pat.Pattern, Pattern: true} // owner
		if !kl.ContainsElement(*processWhiteList, rule) {
			*processWhiteList = append(*processWhiteList, rule)
		}
	} else { // !pat.OwnerOnly
		rule := tp.SELinuxRule{SubjectLabel: "karmor_exec_t", SubjectPath: "-", ObjectLabel: "karmor_allow_t", ObjectPath: pat.Pattern, Pattern: true}
		if !kl.ContainsElement(*processWhiteList, rule) {
			*processWhiteList = append(*processWhiteList, rule)
		}
	}
}

// AllowedFileMatchPaths Function
func (se *SELinuxEnforcer) AllowedFileMatchPaths(path tp.FilePathType, fileWhiteList *[]tp.SELinuxRule, fromSources map[string][]tp.SELinuxRule) {
	if len(path.FromSource) == 0 {
		if path.ReadOnly && path.OwnerOnly {
			rule := tp.SELinuxRule{SubjectLabel: "karmor_exec_t", SubjectPath: "-", ObjectLabel: "karmor_read_t", ObjectPath: path.Path} // owner
			if !kl.ContainsElement(*fileWhiteList, rule) {
				*fileWhiteList = append(*fileWhiteList, rule)
			}
		} else if path.ReadOnly && !path.OwnerOnly {
			rule := tp.SELinuxRule{SubjectLabel: "karmor_exec_t", SubjectPath: "-", ObjectLabel: "karmor_read_t", ObjectPath: path.Path}
			if !kl.ContainsElement(*fileWhiteList, rule) {
				*fileWhiteList = append(*fileWhiteList, rule)
			}
		} else if !path.ReadOnly && path.OwnerOnly {
			rule := tp.SELinuxRule{SubjectLabel: "karmor_exec_t", SubjectPath: "-", ObjectLabel: "karmor_file_t", ObjectPath: path.Path} // owner
			if !kl.ContainsElement(*fileWhiteList, rule) {
				*fileWhiteList = append(*fileWhiteList, rule)
			}
		} else { // !path.ReadOnly && !path.OwnerOnly
			rule := tp.SELinuxRule{SubjectLabel: "karmor_exec_t", SubjectPath: "-", ObjectLabel: "karmor_file_t", ObjectPath: path.Path}
			if !kl.ContainsElement(*fileWhiteList, rule) {
				*fileWhiteList = append(*fileWhiteList, rule)
			}
		}
	} else {
		for _, src := range path.FromSource {
			source := "*"

			if len(src.Path) > 0 {
				source = src.Path
				if _, ok := fromSources[source]; !ok {
					fromSources[source] = []tp.SELinuxRule{}
				}
			} else {
				continue
			}

			if path.ReadOnly && path.OwnerOnly {
				rule := tp.SELinuxRule{SubjectLabel: "karmor_exec_t", SubjectPath: source, ObjectLabel: "karmor_read_t", ObjectPath: path.Path} // owner
				if !kl.ContainsElement(fromSources[source], rule) {
					fromSources[source] = append(fromSources[source], rule)
				}
			} else if path.ReadOnly && !path.OwnerOnly {
				rule := tp.SELinuxRule{SubjectLabel: "karmor_exec_t", SubjectPath: source, ObjectLabel: "karmor_read_t", ObjectPath: path.Path}
				if !kl.ContainsElement(fromSources[source], rule) {
					fromSources[source] = append(fromSources[source], rule)
				}
			} else if !path.ReadOnly && path.OwnerOnly {
				rule := tp.SELinuxRule{SubjectLabel: "karmor_exec_t", SubjectPath: source, ObjectLabel: "karmor_file_t", ObjectPath: path.Path} // owner
				if !kl.ContainsElement(fromSources[source], rule) {
					fromSources[source] = append(fromSources[source], rule)
				}
			} else { // !path.ReadOnly && !path.OwnerOnly
				rule := tp.SELinuxRule{SubjectLabel: "karmor_exec_t", SubjectPath: source, ObjectLabel: "karmor_file_t", ObjectPath: path.Path}
				if !kl.ContainsElement(fromSources[source], rule) {
					fromSources[source] = append(fromSources[source], rule)
				}
			}
		}
	}
}

// AllowedFileMatchDirectories Function
func (se *SELinuxEnforcer) AllowedFileMatchDirectories(dir tp.FileDirectoryType, fileWhiteList *[]tp.SELinuxRule, fromSources map[string][]tp.SELinuxRule) {
	if len(dir.FromSource) == 0 {
		if dir.ReadOnly && dir.OwnerOnly {
			if dir.Recursive {
				rule := tp.SELinuxRule{SubjectLabel: "karmor_exec_t", SubjectPath: "-", ObjectLabel: "karmor_read_t", ObjectPath: dir.Directory, Directory: true, Recursive: true} // owner
				if !kl.ContainsElement(*fileWhiteList, rule) {
					*fileWhiteList = append(*fileWhiteList, rule)
				}
			} else {
				rule := tp.SELinuxRule{SubjectLabel: "karmor_exec_t", SubjectPath: "-", ObjectLabel: "karmor_read_t", ObjectPath: dir.Directory, Directory: true} // owner
				if !kl.ContainsElement(*fileWhiteList, rule) {
					*fileWhiteList = append(*fileWhiteList, rule)
				}
			}
		} else if dir.ReadOnly && !dir.OwnerOnly {
			if dir.Recursive {
				rule := tp.SELinuxRule{SubjectLabel: "karmor_exec_t", SubjectPath: "-", ObjectLabel: "karmor_read_t", ObjectPath: dir.Directory, Directory: true, Recursive: true}
				if !kl.ContainsElement(*fileWhiteList, rule) {
					*fileWhiteList = append(*fileWhiteList, rule)
				}
			} else {
				rule := tp.SELinuxRule{SubjectLabel: "karmor_exec_t", SubjectPath: "-", ObjectLabel: "karmor_read_t", ObjectPath: dir.Directory, Directory: true}
				if !kl.ContainsElement(*fileWhiteList, rule) {
					*fileWhiteList = append(*fileWhiteList, rule)
				}
			}
		} else if !dir.ReadOnly && dir.OwnerOnly {
			if dir.Recursive {
				rule := tp.SELinuxRule{SubjectLabel: "karmor_exec_t", SubjectPath: "-", ObjectLabel: "karmor_file_t", ObjectPath: dir.Directory, Directory: true, Recursive: true} // owner
				if !kl.ContainsElement(*fileWhiteList, rule) {
					*fileWhiteList = append(*fileWhiteList, rule)
				}
			} else {
				rule := tp.SELinuxRule{SubjectLabel: "karmor_exec_t", SubjectPath: "-", ObjectLabel: "karmor_file_t", ObjectPath: dir.Directory, Directory: true} // owner
				if !kl.ContainsElement(*fileWhiteList, rule) {
					*fileWhiteList = append(*fileWhiteList, rule)
				}
			}
		} else { // !dir.ReadOnly && !dir.OwnerOnly
			if dir.Recursive {
				rule := tp.SELinuxRule{SubjectLabel: "karmor_exec_t", SubjectPath: "-", ObjectLabel: "karmor_file_t", ObjectPath: dir.Directory, Directory: true, Recursive: true}
				if !kl.ContainsElement(*fileWhiteList, rule) {
					*fileWhiteList = append(*fileWhiteList, rule)
				}
			} else {
				rule := tp.SELinuxRule{SubjectLabel: "karmor_exec_t", SubjectPath: "-", ObjectLabel: "karmor_file_t", ObjectPath: dir.Directory, Directory: true}
				if !kl.ContainsElement(*fileWhiteList, rule) {
					*fileWhiteList = append(*fileWhiteList, rule)
				}
			}
		}
	} else {
		for _, src := range dir.FromSource {
			source := "*"

			if len(src.Path) > 0 {
				source = src.Path
				if _, ok := fromSources[source]; !ok {
					fromSources[source] = []tp.SELinuxRule{}
				}
			} else {
				continue
			}

			if dir.ReadOnly && dir.OwnerOnly {
				if dir.Recursive {
					rule := tp.SELinuxRule{SubjectLabel: "karmor_exec_t", SubjectPath: source, ObjectLabel: "karmor_read_t", ObjectPath: dir.Directory, Directory: true, Recursive: true} // owner
					if !kl.ContainsElement(fromSources[source], rule) {
						fromSources[source] = append(fromSources[source], rule)
					}
				} else {
					rule := tp.SELinuxRule{SubjectLabel: "karmor_exec_t", SubjectPath: source, ObjectLabel: "karmor_read_t", ObjectPath: dir.Directory, Directory: true} // owner
					if !kl.ContainsElement(fromSources[source], rule) {
						fromSources[source] = append(fromSources[source], rule)
					}
				}
			} else if dir.ReadOnly && !dir.OwnerOnly {
				if dir.Recursive {
					rule := tp.SELinuxRule{SubjectLabel: "karmor_exec_t", SubjectPath: source, ObjectLabel: "karmor_read_t", ObjectPath: dir.Directory, Directory: true, Recursive: true}
					if !kl.ContainsElement(fromSources[source], rule) {
						fromSources[source] = append(fromSources[source], rule)
					}
				} else {
					rule := tp.SELinuxRule{SubjectLabel: "karmor_exec_t", SubjectPath: source, ObjectLabel: "karmor_read_t", ObjectPath: dir.Directory, Directory: true}
					if !kl.ContainsElement(fromSources[source], rule) {
						fromSources[source] = append(fromSources[source], rule)
					}
				}
			} else if !dir.ReadOnly && dir.OwnerOnly {
				if dir.Recursive {
					rule := tp.SELinuxRule{SubjectLabel: "karmor_exec_t", SubjectPath: source, ObjectLabel: "karmor_file_t", ObjectPath: dir.Directory, Directory: true, Recursive: true} // owner
					if !kl.ContainsElement(fromSources[source], rule) {
						fromSources[source] = append(fromSources[source], rule)
					}
				} else {
					rule := tp.SELinuxRule{SubjectLabel: "karmor_exec_t", SubjectPath: source, ObjectLabel: "karmor_file_t", ObjectPath: dir.Directory, Directory: true} // owner
					if !kl.ContainsElement(fromSources[source], rule) {
						fromSources[source] = append(fromSources[source], rule)
					}
				}
			} else { // !dir.ReadOnly && !dir.OwnerOnly
				if dir.Recursive {
					rule := tp.SELinuxRule{SubjectLabel: "karmor_exec_t", SubjectPath: source, ObjectLabel: "karmor_file_t", ObjectPath: dir.Directory, Directory: true, Recursive: true}
					if !kl.ContainsElement(fromSources[source], rule) {
						fromSources[source] = append(fromSources[source], rule)
					}
				} else {
					rule := tp.SELinuxRule{SubjectLabel: "karmor_exec_t", SubjectPath: source, ObjectLabel: "karmor_file_t", ObjectPath: dir.Directory, Directory: true}
					if !kl.ContainsElement(fromSources[source], rule) {
						fromSources[source] = append(fromSources[source], rule)
					}
				}
			}
		}
	}
}

// AllowedFileMatchPatterns Function
func (se *SELinuxEnforcer) AllowedFileMatchPatterns(pat tp.FilePatternType, fileWhiteList *[]tp.SELinuxRule) {
	if pat.ReadOnly && pat.OwnerOnly {
		rule := tp.SELinuxRule{SubjectLabel: "karmor_exec_t", SubjectPath: "-", ObjectLabel: "karmor_read_t", ObjectPath: pat.Pattern, Pattern: true} // owner
		if !kl.ContainsElement(*fileWhiteList, rule) {
			*fileWhiteList = append(*fileWhiteList, rule)
		}
	} else if pat.ReadOnly && !pat.OwnerOnly {
		rule := tp.SELinuxRule{SubjectLabel: "karmor_exec_t", SubjectPath: "-", ObjectLabel: "karmor_read_t", ObjectPath: pat.Pattern, Pattern: true}
		if !kl.ContainsElement(*fileWhiteList, rule) {
			*fileWhiteList = append(*fileWhiteList, rule)
		}
	} else if !pat.ReadOnly && pat.OwnerOnly {
		rule := tp.SELinuxRule{SubjectLabel: "karmor_exec_t", SubjectPath: "-", ObjectLabel: "karmor_file_t", ObjectPath: pat.Pattern, Pattern: true} // owner
		if !kl.ContainsElement(*fileWhiteList, rule) {
			*fileWhiteList = append(*fileWhiteList, rule)
		}
	} else { // !pat.ReadOnly && !pat.OwnerOnly
		rule := tp.SELinuxRule{SubjectLabel: "karmor_exec_t", SubjectPath: "-", ObjectLabel: "karmor_file_t", ObjectPath: pat.Pattern, Pattern: true}
		if !kl.ContainsElement(*fileWhiteList, rule) {
			*fileWhiteList = append(*fileWhiteList, rule)
		}
	}
}

//

// AuditedProcessMatchPaths Function
func (se *SELinuxEnforcer) AuditedProcessMatchPaths(path tp.ProcessPathType, processAuditList *[]tp.SELinuxRule, fromSources map[string][]tp.SELinuxRule) {
	if len(path.FromSource) == 0 {
		if path.OwnerOnly {
			rule := tp.SELinuxRule{SubjectLabel: "karmor_exec_t", SubjectPath: "-", ObjectLabel: "karmor_block_t", ObjectPath: path.Path, Permissive: true} // owner
			if !kl.ContainsElement(*processAuditList, rule) {
				*processAuditList = append(*processAuditList, rule)
			}
		} else { // !path.OwnerOnly
			rule := tp.SELinuxRule{SubjectLabel: "karmor_exec_t", SubjectPath: "-", ObjectLabel: "karmor_block_t", ObjectPath: path.Path, Permissive: true}
			if !kl.ContainsElement(*processAuditList, rule) {
				*processAuditList = append(*processAuditList, rule)
			}
		}
	} else {
		for _, src := range path.FromSource {
			source := "*"

			if len(src.Path) > 0 {
				source = src.Path
				if _, ok := fromSources[source]; !ok {
					fromSources[source] = []tp.SELinuxRule{}
				}
			} else {
				continue
			}

			if path.OwnerOnly {
				rule := tp.SELinuxRule{SubjectLabel: "karmor_exec_t", SubjectPath: source, ObjectLabel: "karmor_block_t", ObjectPath: path.Path, Permissive: true} // owner
				if !kl.ContainsElement(fromSources[source], rule) {
					fromSources[source] = append(fromSources[source], rule)
				}
			} else { // !path.OwnerOnly
				rule := tp.SELinuxRule{SubjectLabel: "karmor_exec_t", SubjectPath: source, ObjectLabel: "karmor_block_t", ObjectPath: path.Path, Permissive: true}
				if !kl.ContainsElement(fromSources[source], rule) {
					fromSources[source] = append(fromSources[source], rule)
				}
			}
		}
	}
}

// AuditedProcessMatchDirectories Function
func (se *SELinuxEnforcer) AuditedProcessMatchDirectories(dir tp.ProcessDirectoryType, processAuditList *[]tp.SELinuxRule, fromSources map[string][]tp.SELinuxRule) {
	if len(dir.FromSource) == 0 {
		if dir.Recursive && dir.OwnerOnly {
			rule := tp.SELinuxRule{SubjectLabel: "karmor_exec_t", SubjectPath: "-", ObjectLabel: "karmor_block_t", ObjectPath: dir.Directory, Directory: true, Recursive: true, Permissive: true} // owner
			if !kl.ContainsElement(*processAuditList, rule) {
				*processAuditList = append(*processAuditList, rule)
			}
		} else if dir.Recursive && !dir.OwnerOnly {
			rule := tp.SELinuxRule{SubjectLabel: "karmor_exec_t", SubjectPath: "-", ObjectLabel: "karmor_block_t", ObjectPath: dir.Directory, Directory: true, Recursive: true, Permissive: true}
			if !kl.ContainsElement(*processAuditList, rule) {
				*processAuditList = append(*processAuditList, rule)
			}
		} else if !dir.Recursive && dir.OwnerOnly {
			rule := tp.SELinuxRule{SubjectLabel: "karmor_exec_t", SubjectPath: "-", ObjectLabel: "karmor_block_t", ObjectPath: dir.Directory, Directory: true, Permissive: true} // owner
			if !kl.ContainsElement(*processAuditList, rule) {
				*processAuditList = append(*processAuditList, rule)
			}
		} else { // !dir.Recursive && !dir.OwnerOnly
			rule := tp.SELinuxRule{SubjectLabel: "karmor_exec_t", SubjectPath: "-", ObjectLabel: "karmor_block_t", ObjectPath: dir.Directory, Directory: true, Permissive: true}
			if !kl.ContainsElement(*processAuditList, rule) {
				*processAuditList = append(*processAuditList, rule)
			}
		}
	} else {
		for _, src := range dir.FromSource {
			source := "*"

			if len(src.Path) > 0 {
				source = src.Path
				if _, ok := fromSources[source]; !ok {
					fromSources[source] = []tp.SELinuxRule{}
				}
			} else {
				continue
			}

			if dir.Recursive && dir.OwnerOnly {
				rule := tp.SELinuxRule{SubjectLabel: "karmor_exec_t", SubjectPath: source, ObjectLabel: "karmor_block_t", ObjectPath: dir.Directory, Directory: true, Recursive: true, Permissive: true} // owner
				if !kl.ContainsElement(fromSources[source], rule) {
					fromSources[source] = append(fromSources[source], rule)
				}
			} else if dir.Recursive && !dir.OwnerOnly {
				rule := tp.SELinuxRule{SubjectLabel: "karmor_exec_t", SubjectPath: source, ObjectLabel: "karmor_block_t", ObjectPath: dir.Directory, Directory: true, Recursive: true, Permissive: true}
				if !kl.ContainsElement(fromSources[source], rule) {
					fromSources[source] = append(fromSources[source], rule)
				}
			} else if !dir.Recursive && dir.OwnerOnly {
				rule := tp.SELinuxRule{SubjectLabel: "karmor_exec_t", SubjectPath: source, ObjectLabel: "karmor_block_t", ObjectPath: dir.Directory, Directory: true, Permissive: true} // owner
				if !kl.ContainsElement(fromSources[source], rule) {
					fromSources[source] = append(fromSources[source], rule)
				}
			} else { // !dir.Recursive && !dir.OwnerOnly
				rule := tp.SELinuxRule{SubjectLabel: "karmor_exec_t", SubjectPath: source, ObjectLabel: "karmor_block_t", ObjectPath: dir.Directory, Directory: true, Permissive: true}
				if !kl.ContainsElement(fromSources[source], rule) {
					fromSources[source] = append(fromSources[source], rule)
				}
			}
		}
	}
}

// AuditedProcessMatchPatterns Function
func (se *SELinuxEnforcer) AuditedProcessMatchPatterns(pat tp.ProcessPatternType, processAuditList *[]tp.SELinuxRule) {
	if pat.OwnerOnly {
		rule := tp.SELinuxRule{SubjectLabel: "karmor_exec_t", SubjectPath: "-", ObjectLabel: "karmor_block_t", ObjectPath: pat.Pattern, Pattern: true, Permissive: true} // owner
		if !kl.ContainsElement(*processAuditList, rule) {
			*processAuditList = append(*processAuditList, rule)
		}
	} else { // !pat.OwnerOnly
		rule := tp.SELinuxRule{SubjectLabel: "karmor_exec_t", SubjectPath: "-", ObjectLabel: "karmor_block_t", ObjectPath: pat.Pattern, Pattern: true, Permissive: true}
		if !kl.ContainsElement(*processAuditList, rule) {
			*processAuditList = append(*processAuditList, rule)
		}
	}
}

// AuditedFileMatchPaths Function
func (se *SELinuxEnforcer) AuditedFileMatchPaths(path tp.FilePathType, fileAuditList *[]tp.SELinuxRule, fromSources map[string][]tp.SELinuxRule) {
	if len(path.FromSource) == 0 {
		if path.ReadOnly && path.OwnerOnly {
			rule := tp.SELinuxRule{SubjectLabel: "karmor_exec_t", SubjectPath: "-", ObjectLabel: "karmor_read_t", ObjectPath: path.Path, Permissive: true} // owner
			if !kl.ContainsElement(*fileAuditList, rule) {
				*fileAuditList = append(*fileAuditList, rule)
			}
		} else if path.ReadOnly && !path.OwnerOnly {
			rule := tp.SELinuxRule{SubjectLabel: "karmor_exec_t", SubjectPath: "-", ObjectLabel: "karmor_read_t", ObjectPath: path.Path, Permissive: true}
			if !kl.ContainsElement(*fileAuditList, rule) {
				*fileAuditList = append(*fileAuditList, rule)
			}
		} else if !path.ReadOnly && path.OwnerOnly {
			rule := tp.SELinuxRule{SubjectLabel: "karmor_exec_t", SubjectPath: "-", ObjectLabel: "karmor_file_t", ObjectPath: path.Path, Permissive: true} // owner
			if !kl.ContainsElement(*fileAuditList, rule) {
				*fileAuditList = append(*fileAuditList, rule)
			}
		} else { // !path.ReadOnly && !path.OwnerOnly
			rule := tp.SELinuxRule{SubjectLabel: "karmor_exec_t", SubjectPath: "-", ObjectLabel: "karmor_file_t", ObjectPath: path.Path, Permissive: true}
			if !kl.ContainsElement(*fileAuditList, rule) {
				*fileAuditList = append(*fileAuditList, rule)
			}
		}
	} else {
		for _, src := range path.FromSource {
			source := "*"

			if len(src.Path) > 0 {
				source = src.Path
				if _, ok := fromSources[source]; !ok {
					fromSources[source] = []tp.SELinuxRule{}
				}
			} else {
				continue
			}

			if path.ReadOnly && path.OwnerOnly {
				rule := tp.SELinuxRule{SubjectLabel: "karmor_exec_t", SubjectPath: source, ObjectLabel: "karmor_read_t", ObjectPath: path.Path, Permissive: true} // owner
				if !kl.ContainsElement(fromSources[source], rule) {
					fromSources[source] = append(fromSources[source], rule)
				}
			} else if path.ReadOnly && !path.OwnerOnly {
				rule := tp.SELinuxRule{SubjectLabel: "karmor_exec_t", SubjectPath: source, ObjectLabel: "karmor_read_t", ObjectPath: path.Path, Permissive: true}
				if !kl.ContainsElement(fromSources[source], rule) {
					fromSources[source] = append(fromSources[source], rule)
				}
			} else if !path.ReadOnly && path.OwnerOnly {
				rule := tp.SELinuxRule{SubjectLabel: "karmor_exec_t", SubjectPath: source, ObjectLabel: "karmor_file_t", ObjectPath: path.Path, Permissive: true} // owner
				if !kl.ContainsElement(fromSources[source], rule) {
					fromSources[source] = append(fromSources[source], rule)
				}
			} else { // !path.ReadOnly && !path.OwnerOnly
				rule := tp.SELinuxRule{SubjectLabel: "karmor_exec_t", SubjectPath: source, ObjectLabel: "karmor_file_t", ObjectPath: path.Path, Permissive: true}
				if !kl.ContainsElement(fromSources[source], rule) {
					fromSources[source] = append(fromSources[source], rule)
				}
			}
		}
	}
}

// AuditedFileMatchDirectories Function
func (se *SELinuxEnforcer) AuditedFileMatchDirectories(dir tp.FileDirectoryType, fileAuditList *[]tp.SELinuxRule, fromSources map[string][]tp.SELinuxRule) {
	if len(dir.FromSource) == 0 {
		if dir.ReadOnly && dir.OwnerOnly {
			if dir.Recursive {
				rule := tp.SELinuxRule{SubjectLabel: "karmor_exec_t", SubjectPath: "-", ObjectLabel: "karmor_read_t", ObjectPath: dir.Directory, Directory: true, Recursive: true, Permissive: true} // owner
				if !kl.ContainsElement(*fileAuditList, rule) {
					*fileAuditList = append(*fileAuditList, rule)
				}
			} else {
				rule := tp.SELinuxRule{SubjectLabel: "karmor_exec_t", SubjectPath: "-", ObjectLabel: "karmor_read_t", ObjectPath: dir.Directory, Directory: true, Permissive: true} // owner
				if !kl.ContainsElement(*fileAuditList, rule) {
					*fileAuditList = append(*fileAuditList, rule)
				}
			}
		} else if dir.ReadOnly && !dir.OwnerOnly {
			if dir.Recursive {
				rule := tp.SELinuxRule{SubjectLabel: "karmor_exec_t", SubjectPath: "-", ObjectLabel: "karmor_read_t", ObjectPath: dir.Directory, Directory: true, Recursive: true, Permissive: true}
				if !kl.ContainsElement(*fileAuditList, rule) {
					*fileAuditList = append(*fileAuditList, rule)
				}
			} else {
				rule := tp.SELinuxRule{SubjectLabel: "karmor_exec_t", SubjectPath: "-", ObjectLabel: "karmor_read_t", ObjectPath: dir.Directory, Directory: true, Permissive: true}
				if !kl.ContainsElement(*fileAuditList, rule) {
					*fileAuditList = append(*fileAuditList, rule)
				}
			}
		} else if !dir.ReadOnly && dir.OwnerOnly {
			if dir.Recursive {
				rule := tp.SELinuxRule{SubjectLabel: "karmor_exec_t", SubjectPath: "-", ObjectLabel: "karmor_file_t", ObjectPath: dir.Directory, Directory: true, Recursive: true, Permissive: true} // owner
				if !kl.ContainsElement(*fileAuditList, rule) {
					*fileAuditList = append(*fileAuditList, rule)
				}
			} else {
				rule := tp.SELinuxRule{SubjectLabel: "karmor_exec_t", SubjectPath: "-", ObjectLabel: "karmor_file_t", ObjectPath: dir.Directory, Directory: true, Permissive: true} // owner
				if !kl.ContainsElement(*fileAuditList, rule) {
					*fileAuditList = append(*fileAuditList, rule)
				}
			}
		} else { // !dir.ReadOnly && !dir.OwnerOnly
			if dir.Recursive {
				rule := tp.SELinuxRule{SubjectLabel: "karmor_exec_t", SubjectPath: "-", ObjectLabel: "karmor_file_t", ObjectPath: dir.Directory, Directory: true, Recursive: true, Permissive: true}
				if !kl.ContainsElement(*fileAuditList, rule) {
					*fileAuditList = append(*fileAuditList, rule)
				}
			} else {
				rule := tp.SELinuxRule{SubjectLabel: "karmor_exec_t", SubjectPath: "-", ObjectLabel: "karmor_file_t", ObjectPath: dir.Directory, Directory: true, Permissive: true}
				if !kl.ContainsElement(*fileAuditList, rule) {
					*fileAuditList = append(*fileAuditList, rule)
				}
			}
		}
	} else {
		for _, src := range dir.FromSource {
			source := "*"

			if len(src.Path) > 0 {
				source = src.Path
				if _, ok := fromSources[source]; !ok {
					fromSources[source] = []tp.SELinuxRule{}
				}
			} else {
				continue
			}

			if dir.ReadOnly && dir.OwnerOnly {
				if dir.Recursive {
					rule := tp.SELinuxRule{SubjectLabel: "karmor_exec_t", SubjectPath: source, ObjectLabel: "karmor_read_t", ObjectPath: dir.Directory, Directory: true, Recursive: true, Permissive: true} // owner
					if !kl.ContainsElement(fromSources[source], rule) {
						fromSources[source] = append(fromSources[source], rule)
					}
				} else {
					rule := tp.SELinuxRule{SubjectLabel: "karmor_exec_t", SubjectPath: source, ObjectLabel: "karmor_read_t", ObjectPath: dir.Directory, Directory: true, Permissive: true} // owner
					if !kl.ContainsElement(fromSources[source], rule) {
						fromSources[source] = append(fromSources[source], rule)
					}
				}
			} else if dir.ReadOnly && !dir.OwnerOnly {
				if dir.Recursive {
					rule := tp.SELinuxRule{SubjectLabel: "karmor_exec_t", SubjectPath: source, ObjectLabel: "karmor_read_t", ObjectPath: dir.Directory, Directory: true, Recursive: true, Permissive: true}
					if !kl.ContainsElement(fromSources[source], rule) {
						fromSources[source] = append(fromSources[source], rule)
					}
				} else {
					rule := tp.SELinuxRule{SubjectLabel: "karmor_exec_t", SubjectPath: source, ObjectLabel: "karmor_read_t", ObjectPath: dir.Directory, Directory: true, Permissive: true}
					if !kl.ContainsElement(fromSources[source], rule) {
						fromSources[source] = append(fromSources[source], rule)
					}
				}
			} else if !dir.ReadOnly && dir.OwnerOnly {
				if dir.Recursive {
					rule := tp.SELinuxRule{SubjectLabel: "karmor_exec_t", SubjectPath: source, ObjectLabel: "karmor_file_t", ObjectPath: dir.Directory, Directory: true, Recursive: true, Permissive: true} // owner
					if !kl.ContainsElement(fromSources[source], rule) {
						fromSources[source] = append(fromSources[source], rule)
					}
				} else {
					rule := tp.SELinuxRule{SubjectLabel: "karmor_exec_t", SubjectPath: source, ObjectLabel: "karmor_file_t", ObjectPath: dir.Directory, Directory: true, Permissive: true} // owner
					if !kl.ContainsElement(fromSources[source], rule) {
						fromSources[source] = append(fromSources[source], rule)
					}
				}
			} else { // !dir.ReadOnly && !dir.OwnerOnly
				if dir.Recursive {
					rule := tp.SELinuxRule{SubjectLabel: "karmor_exec_t", SubjectPath: source, ObjectLabel: "karmor_file_t", ObjectPath: dir.Directory, Directory: true, Recursive: true, Permissive: true}
					if !kl.ContainsElement(fromSources[source], rule) {
						fromSources[source] = append(fromSources[source], rule)
					}
				} else {
					rule := tp.SELinuxRule{SubjectLabel: "karmor_exec_t", SubjectPath: source, ObjectLabel: "karmor_file_t", ObjectPath: dir.Directory, Directory: true, Permissive: true}
					if !kl.ContainsElement(fromSources[source], rule) {
						fromSources[source] = append(fromSources[source], rule)
					}
				}
			}
		}
	}
}

// AuditedFileMatchPatterns Function
func (se *SELinuxEnforcer) AuditedFileMatchPatterns(pat tp.FilePatternType, fileAuditList *[]tp.SELinuxRule) {
	if pat.ReadOnly && pat.OwnerOnly {
		rule := tp.SELinuxRule{SubjectLabel: "karmor_exec_t", SubjectPath: "-", ObjectLabel: "karmor_read_t", ObjectPath: pat.Pattern, Pattern: true, Permissive: true} // owner
		if !kl.ContainsElement(*fileAuditList, rule) {
			*fileAuditList = append(*fileAuditList, rule)
		}
	} else if pat.ReadOnly && !pat.OwnerOnly {
		rule := tp.SELinuxRule{SubjectLabel: "karmor_exec_t", SubjectPath: "-", ObjectLabel: "karmor_read_t", ObjectPath: pat.Pattern, Pattern: true, Permissive: true}
		if !kl.ContainsElement(*fileAuditList, rule) {
			*fileAuditList = append(*fileAuditList, rule)
		}
	} else if !pat.ReadOnly && pat.OwnerOnly {
		rule := tp.SELinuxRule{SubjectLabel: "karmor_exec_t", SubjectPath: "-", ObjectLabel: "karmor_file_t", ObjectPath: pat.Pattern, Pattern: true, Permissive: true} // owner
		if !kl.ContainsElement(*fileAuditList, rule) {
			*fileAuditList = append(*fileAuditList, rule)
		}
	} else { // !pat.ReadOnly && !pat.OwnerOnly
		rule := tp.SELinuxRule{SubjectLabel: "karmor_exec_t", SubjectPath: "-", ObjectLabel: "karmor_file_t", ObjectPath: pat.Pattern, Pattern: true, Permissive: true}
		if !kl.ContainsElement(*fileAuditList, rule) {
			*fileAuditList = append(*fileAuditList, rule)
		}
	}
}

//

// BlockedProcessMatchPaths Function
func (se *SELinuxEnforcer) BlockedProcessMatchPaths(path tp.ProcessPathType, processBlackList *[]tp.SELinuxRule, fromSources map[string][]tp.SELinuxRule) {
	if len(path.FromSource) == 0 {
		if path.OwnerOnly {
			rule := tp.SELinuxRule{SubjectLabel: "karmor_exec_t", SubjectPath: "-", ObjectLabel: "karmor_block_t", ObjectPath: path.Path} // owner
			if !kl.ContainsElement(*processBlackList, rule) {
				*processBlackList = append(*processBlackList, rule)
			}
		} else { // !path.OwnerOnly
			rule := tp.SELinuxRule{SubjectLabel: "karmor_exec_t", SubjectPath: "-", ObjectLabel: "karmor_block_t", ObjectPath: path.Path}
			if !kl.ContainsElement(*processBlackList, rule) {
				*processBlackList = append(*processBlackList, rule)
			}
		}
	} else {
		for _, src := range path.FromSource {
			source := "*"

			if len(src.Path) > 0 {
				source = src.Path
				if _, ok := fromSources[source]; !ok {
					fromSources[source] = []tp.SELinuxRule{}
				}
			} else {
				continue
			}

			if path.OwnerOnly {
				rule := tp.SELinuxRule{SubjectLabel: "karmor_exec_t", SubjectPath: source, ObjectLabel: "karmor_block_t", ObjectPath: path.Path} // owner
				if !kl.ContainsElement(fromSources[source], rule) {
					fromSources[source] = append(fromSources[source], rule)
				}
			} else { // !path.OwnerOnly
				rule := tp.SELinuxRule{SubjectLabel: "karmor_exec_t", SubjectPath: source, ObjectLabel: "karmor_block_t", ObjectPath: path.Path}
				if !kl.ContainsElement(fromSources[source], rule) {
					fromSources[source] = append(fromSources[source], rule)
				}
			}
		}
	}
}

// BlockedProcessMatchDirectories Function
func (se *SELinuxEnforcer) BlockedProcessMatchDirectories(dir tp.ProcessDirectoryType, processBlackList *[]tp.SELinuxRule, fromSources map[string][]tp.SELinuxRule) {
	if len(dir.FromSource) == 0 {
		if dir.Recursive && dir.OwnerOnly {
			rule := tp.SELinuxRule{SubjectLabel: "karmor_exec_t", SubjectPath: "-", ObjectLabel: "karmor_block_t", ObjectPath: dir.Directory, Directory: true, Recursive: true} // owner
			if !kl.ContainsElement(*processBlackList, rule) {
				*processBlackList = append(*processBlackList, rule)
			}
		} else if dir.Recursive && !dir.OwnerOnly {
			rule := tp.SELinuxRule{SubjectLabel: "karmor_exec_t", SubjectPath: "-", ObjectLabel: "karmor_block_t", ObjectPath: dir.Directory, Directory: true, Recursive: true}
			if !kl.ContainsElement(*processBlackList, rule) {
				*processBlackList = append(*processBlackList, rule)
			}
		} else if !dir.Recursive && dir.OwnerOnly {
			rule := tp.SELinuxRule{SubjectLabel: "karmor_exec_t", SubjectPath: "-", ObjectLabel: "karmor_block_t", ObjectPath: dir.Directory, Directory: true} // owner
			if !kl.ContainsElement(*processBlackList, rule) {
				*processBlackList = append(*processBlackList, rule)
			}
		} else { // !dir.Recursive && !dir.OwnerOnly
			rule := tp.SELinuxRule{SubjectLabel: "karmor_exec_t", SubjectPath: "-", ObjectLabel: "karmor_block_t", ObjectPath: dir.Directory, Directory: true}
			if !kl.ContainsElement(*processBlackList, rule) {
				*processBlackList = append(*processBlackList, rule)
			}
		}
	} else {
		for _, src := range dir.FromSource {
			source := "*"

			if len(src.Path) > 0 {
				source = src.Path
				if _, ok := fromSources[source]; !ok {
					fromSources[source] = []tp.SELinuxRule{}
				}
			} else {
				continue
			}

			if dir.Recursive && dir.OwnerOnly {
				rule := tp.SELinuxRule{SubjectLabel: "karmor_exec_t", SubjectPath: source, ObjectLabel: "karmor_block_t", ObjectPath: dir.Directory, Directory: true, Recursive: true} // owner
				if !kl.ContainsElement(fromSources[source], rule) {
					fromSources[source] = append(fromSources[source], rule)
				}
			} else if dir.Recursive && !dir.OwnerOnly {
				rule := tp.SELinuxRule{SubjectLabel: "karmor_exec_t", SubjectPath: source, ObjectLabel: "karmor_block_t", ObjectPath: dir.Directory, Directory: true, Recursive: true}
				if !kl.ContainsElement(fromSources[source], rule) {
					fromSources[source] = append(fromSources[source], rule)
				}
			} else if !dir.Recursive && dir.OwnerOnly {
				rule := tp.SELinuxRule{SubjectLabel: "karmor_exec_t", SubjectPath: source, ObjectLabel: "karmor_block_t", ObjectPath: dir.Directory, Directory: true} // owner
				if !kl.ContainsElement(fromSources[source], rule) {
					fromSources[source] = append(fromSources[source], rule)
				}
			} else { // !dir.Recursive && !dir.OwnerOnly
				rule := tp.SELinuxRule{SubjectLabel: "karmor_exec_t", SubjectPath: source, ObjectLabel: "karmor_block_t", ObjectPath: dir.Directory, Directory: true}
				if !kl.ContainsElement(fromSources[source], rule) {
					fromSources[source] = append(fromSources[source], rule)
				}
			}
		}
	}
}

// BlockedProcessMatchPatterns Function
func (se *SELinuxEnforcer) BlockedProcessMatchPatterns(pat tp.ProcessPatternType, processBlackList *[]tp.SELinuxRule) {
	if pat.OwnerOnly {
		rule := tp.SELinuxRule{SubjectLabel: "karmor_exec_t", SubjectPath: "-", ObjectLabel: "karmor_block_t", ObjectPath: pat.Pattern, Pattern: true} // owner
		if !kl.ContainsElement(*processBlackList, rule) {
			*processBlackList = append(*processBlackList, rule)
		}
	} else { // !path.OwnerOnly
		rule := tp.SELinuxRule{SubjectLabel: "karmor_exec_t", SubjectPath: "-", ObjectLabel: "karmor_block_t", ObjectPath: pat.Pattern, Pattern: true}
		if !kl.ContainsElement(*processBlackList, rule) {
			*processBlackList = append(*processBlackList, rule)
		}
	}
}

// BlockedFileMatchPaths Function
func (se *SELinuxEnforcer) BlockedFileMatchPaths(path tp.FilePathType, fileBlackList *[]tp.SELinuxRule, fromSources map[string][]tp.SELinuxRule) {
	if len(path.FromSource) == 0 {
		if path.ReadOnly && path.OwnerOnly {
			rule := tp.SELinuxRule{SubjectLabel: "karmor_exec_t", SubjectPath: "-", ObjectLabel: "karmor_read_t", ObjectPath: path.Path} // owner
			if !kl.ContainsElement(*fileBlackList, rule) {
				*fileBlackList = append(*fileBlackList, rule)
			}
		} else if path.ReadOnly && !path.OwnerOnly {
			rule := tp.SELinuxRule{SubjectLabel: "karmor_exec_t", SubjectPath: "-", ObjectLabel: "karmor_read_t", ObjectPath: path.Path}
			if !kl.ContainsElement(*fileBlackList, rule) {
				*fileBlackList = append(*fileBlackList, rule)
			}
		} else if !path.ReadOnly && path.OwnerOnly {
			rule := tp.SELinuxRule{SubjectLabel: "karmor_exec_t", SubjectPath: "-", ObjectLabel: "karmor_file_t", ObjectPath: path.Path} // owner
			if !kl.ContainsElement(*fileBlackList, rule) {
				*fileBlackList = append(*fileBlackList, rule)
			}
		} else { // !path.ReadOnly && !path.OwnerOnly
			rule := tp.SELinuxRule{SubjectLabel: "karmor_exec_t", SubjectPath: "-", ObjectLabel: "karmor_file_t", ObjectPath: path.Path}
			if !kl.ContainsElement(*fileBlackList, rule) {
				*fileBlackList = append(*fileBlackList, rule)
			}
		}
	} else {
		for _, src := range path.FromSource {
			source := "*"

			if len(src.Path) > 0 {
				source = src.Path
				if _, ok := fromSources[source]; !ok {
					fromSources[source] = []tp.SELinuxRule{}
				}
			} else {
				continue
			}

			if path.ReadOnly && path.OwnerOnly {
				rule := tp.SELinuxRule{SubjectLabel: "karmor_exec_t", SubjectPath: source, ObjectLabel: "karmor_read_t", ObjectPath: path.Path} // owner
				if !kl.ContainsElement(fromSources[source], rule) {
					fromSources[source] = append(fromSources[source], rule)
				}
			} else if path.ReadOnly && !path.OwnerOnly {
				rule := tp.SELinuxRule{SubjectLabel: "karmor_exec_t", SubjectPath: source, ObjectLabel: "karmor_read_t", ObjectPath: path.Path}
				if !kl.ContainsElement(fromSources[source], rule) {
					fromSources[source] = append(fromSources[source], rule)
				}
			} else if !path.ReadOnly && path.OwnerOnly {
				rule := tp.SELinuxRule{SubjectLabel: "karmor_exec_t", SubjectPath: source, ObjectLabel: "karmor_file_t", ObjectPath: path.Path} // owner
				if !kl.ContainsElement(fromSources[source], rule) {
					fromSources[source] = append(fromSources[source], rule)
				}
			} else { // !path.ReadOnly && !path.OwnerOnly
				rule := tp.SELinuxRule{SubjectLabel: "karmor_exec_t", SubjectPath: source, ObjectLabel: "karmor_file_t", ObjectPath: path.Path}
				if !kl.ContainsElement(fromSources[source], rule) {
					fromSources[source] = append(fromSources[source], rule)
				}
			}
		}
	}
}

// BlockedFileMatchDirectories Function
func (se *SELinuxEnforcer) BlockedFileMatchDirectories(dir tp.FileDirectoryType, fileBlackList *[]tp.SELinuxRule, fromSources map[string][]tp.SELinuxRule) {
	if len(dir.FromSource) == 0 {
		if dir.ReadOnly && dir.OwnerOnly {
			if dir.Recursive {
				rule := tp.SELinuxRule{SubjectLabel: "karmor_exec_t", SubjectPath: "-", ObjectLabel: "karmor_read_t", ObjectPath: dir.Directory, Directory: true, Recursive: true} // owner
				if !kl.ContainsElement(*fileBlackList, rule) {
					*fileBlackList = append(*fileBlackList, rule)
				}
			} else {
				rule := tp.SELinuxRule{SubjectLabel: "karmor_exec_t", SubjectPath: "-", ObjectLabel: "karmor_read_t", ObjectPath: dir.Directory, Directory: true} // owner
				if !kl.ContainsElement(*fileBlackList, rule) {
					*fileBlackList = append(*fileBlackList, rule)
				}
			}
		} else if dir.ReadOnly && !dir.OwnerOnly {
			if dir.Recursive {
				rule := tp.SELinuxRule{SubjectLabel: "karmor_exec_t", SubjectPath: "-", ObjectLabel: "karmor_read_t", ObjectPath: dir.Directory, Directory: true, Recursive: true}
				if !kl.ContainsElement(*fileBlackList, rule) {
					*fileBlackList = append(*fileBlackList, rule)
				}
			} else {
				rule := tp.SELinuxRule{SubjectLabel: "karmor_exec_t", SubjectPath: "-", ObjectLabel: "karmor_read_t", ObjectPath: dir.Directory, Directory: true}
				if !kl.ContainsElement(*fileBlackList, rule) {
					*fileBlackList = append(*fileBlackList, rule)
				}
			}
		} else if !dir.ReadOnly && dir.OwnerOnly {
			if dir.Recursive {
				rule := tp.SELinuxRule{SubjectLabel: "karmor_exec_t", SubjectPath: "-", ObjectLabel: "karmor_file_t", ObjectPath: dir.Directory, Directory: true, Recursive: true} // owner
				if !kl.ContainsElement(*fileBlackList, rule) {
					*fileBlackList = append(*fileBlackList, rule)
				}
			} else {
				rule := tp.SELinuxRule{SubjectLabel: "karmor_exec_t", SubjectPath: "-", ObjectLabel: "karmor_file_t", ObjectPath: dir.Directory, Directory: true} // owner
				if !kl.ContainsElement(*fileBlackList, rule) {
					*fileBlackList = append(*fileBlackList, rule)
				}
			}
		} else { // !dir.ReadOnly && !dir.OwnerOnly
			if dir.Recursive {
				rule := tp.SELinuxRule{SubjectLabel: "karmor_exec_t", SubjectPath: "-", ObjectLabel: "karmor_file_t", ObjectPath: dir.Directory, Directory: true, Recursive: true}
				if !kl.ContainsElement(*fileBlackList, rule) {
					*fileBlackList = append(*fileBlackList, rule)
				}
			} else {
				rule := tp.SELinuxRule{SubjectLabel: "karmor_exec_t", SubjectPath: "-", ObjectLabel: "karmor_file_t", ObjectPath: dir.Directory, Directory: true}
				if !kl.ContainsElement(*fileBlackList, rule) {
					*fileBlackList = append(*fileBlackList, rule)
				}
			}
		}
	} else {
		for _, src := range dir.FromSource {
			source := "*"

			if len(src.Path) > 0 {
				source = src.Path
				if _, ok := fromSources[source]; !ok {
					fromSources[source] = []tp.SELinuxRule{}
				}
			} else {
				continue
			}

			if dir.ReadOnly && dir.OwnerOnly {
				if dir.Recursive {
					rule := tp.SELinuxRule{SubjectLabel: "karmor_exec_t", SubjectPath: source, ObjectLabel: "karmor_read_t", ObjectPath: dir.Directory, Directory: true, Recursive: true} // owner
					if !kl.ContainsElement(fromSources[source], rule) {
						fromSources[source] = append(fromSources[source], rule)
					}
				} else {
					rule := tp.SELinuxRule{SubjectLabel: "karmor_exec_t", SubjectPath: source, ObjectLabel: "karmor_read_t", ObjectPath: dir.Directory, Directory: true} // owner
					if !kl.ContainsElement(fromSources[source], rule) {
						fromSources[source] = append(fromSources[source], rule)
					}
				}
			} else if dir.ReadOnly && !dir.OwnerOnly {
				if dir.Recursive {
					rule := tp.SELinuxRule{SubjectLabel: "karmor_exec_t", SubjectPath: source, ObjectLabel: "karmor_read_t", ObjectPath: dir.Directory, Directory: true, Recursive: true}
					if !kl.ContainsElement(fromSources[source], rule) {
						fromSources[source] = append(fromSources[source], rule)
					}
				} else {
					rule := tp.SELinuxRule{SubjectLabel: "karmor_exec_t", SubjectPath: source, ObjectLabel: "karmor_read_t", ObjectPath: dir.Directory, Directory: true}
					if !kl.ContainsElement(fromSources[source], rule) {
						fromSources[source] = append(fromSources[source], rule)
					}
				}
			} else if !dir.ReadOnly && dir.OwnerOnly {
				if dir.Recursive {
					rule := tp.SELinuxRule{SubjectLabel: "karmor_exec_t", SubjectPath: source, ObjectLabel: "karmor_file_t", ObjectPath: dir.Directory, Directory: true, Recursive: true} // owner
					if !kl.ContainsElement(fromSources[source], rule) {
						fromSources[source] = append(fromSources[source], rule)
					}
				} else {
					rule := tp.SELinuxRule{SubjectLabel: "karmor_exec_t", SubjectPath: source, ObjectLabel: "karmor_file_t", ObjectPath: dir.Directory, Directory: true} // owner
					if !kl.ContainsElement(fromSources[source], rule) {
						fromSources[source] = append(fromSources[source], rule)
					}
				}
			} else { // !dir.ReadOnly && !dir.OwnerOnly
				if dir.Recursive {
					rule := tp.SELinuxRule{SubjectLabel: "karmor_exec_t", SubjectPath: source, ObjectLabel: "karmor_file_t", ObjectPath: dir.Directory, Directory: true, Recursive: true}
					if !kl.ContainsElement(fromSources[source], rule) {
						fromSources[source] = append(fromSources[source], rule)
					}
				} else {
					rule := tp.SELinuxRule{SubjectLabel: "karmor_exec_t", SubjectPath: source, ObjectLabel: "karmor_file_t", ObjectPath: dir.Directory, Directory: true}
					if !kl.ContainsElement(fromSources[source], rule) {
						fromSources[source] = append(fromSources[source], rule)
					}
				}
			}
		}
	}
}

// BlockedFileMatchPatterns Function
func (se *SELinuxEnforcer) BlockedFileMatchPatterns(pat tp.FilePatternType, fileBlackList *[]tp.SELinuxRule) {
	if pat.ReadOnly && pat.OwnerOnly {
		rule := tp.SELinuxRule{SubjectLabel: "karmor_exec_t", SubjectPath: "-", ObjectLabel: "karmor_read_t", ObjectPath: pat.Pattern, Pattern: true} // owner
		if !kl.ContainsElement(*fileBlackList, rule) {
			*fileBlackList = append(*fileBlackList, rule)
		}
	} else if pat.ReadOnly && !pat.OwnerOnly {
		rule := tp.SELinuxRule{SubjectLabel: "karmor_exec_t", SubjectPath: "-", ObjectLabel: "karmor_read_t", ObjectPath: pat.Pattern, Pattern: true}
		if !kl.ContainsElement(*fileBlackList, rule) {
			*fileBlackList = append(*fileBlackList, rule)
		}
	} else if !pat.ReadOnly && pat.OwnerOnly {
		rule := tp.SELinuxRule{SubjectLabel: "karmor_exec_t", SubjectPath: "-", ObjectLabel: "karmor_file_t", ObjectPath: pat.Pattern, Pattern: true} // owner
		if !kl.ContainsElement(*fileBlackList, rule) {
			*fileBlackList = append(*fileBlackList, rule)
		}
	} else { // !pat.ReadOnly && !pat.OwnerOnly
		rule := tp.SELinuxRule{SubjectLabel: "karmor_exec_t", SubjectPath: "-", ObjectLabel: "karmor_file_t", ObjectPath: pat.Pattern, Pattern: true}
		if !kl.ContainsElement(*fileBlackList, rule) {
			*fileBlackList = append(*fileBlackList, rule)
		}
	}
}

// == //

// GenerateSELinuxProfile Function
func (se *SELinuxEnforcer) GenerateSELinuxProfile(seLinuxProfile string, securityPolicies []tp.SecurityPolicy) (int, string, []string, bool) {
	count := 0

	processWhiteList := []tp.SELinuxRule{}
	processAuditList := []tp.SELinuxRule{}
	processBlackList := []tp.SELinuxRule{}

	fileWhiteList := []tp.SELinuxRule{}
	fileAuditList := []tp.SELinuxRule{}
	fileBlackList := []tp.SELinuxRule{}

	whiteListfromSources := map[string][]tp.SELinuxRule{}
	auditListfromSources := map[string][]tp.SELinuxRule{}
	blackListfromSources := map[string][]tp.SELinuxRule{}

	// preparation

	for _, secPolicy := range securityPolicies {
		if len(secPolicy.Spec.Process.MatchPaths) > 0 {
			for _, path := range secPolicy.Spec.Process.MatchPaths {
				if path.Action == "Allow" {
					se.AllowedProcessMatchPaths(path, &processWhiteList, whiteListfromSources)
				} else if path.Action == "Audit" {
					se.AuditedProcessMatchPaths(path, &processAuditList, auditListfromSources)
				} else if path.Action == "Block" {
					se.BlockedProcessMatchPaths(path, &processBlackList, blackListfromSources)
				}
			}
		}
		if len(secPolicy.Spec.Process.MatchDirectories) > 0 {
			for _, dir := range secPolicy.Spec.Process.MatchDirectories {
				if dir.Action == "Allow" {
					se.AllowedProcessMatchDirectories(dir, &processWhiteList, whiteListfromSources)
				} else if dir.Action == "Audit" {
					se.AuditedProcessMatchDirectories(dir, &processAuditList, auditListfromSources)
				} else if dir.Action == "Block" {
					se.BlockedProcessMatchDirectories(dir, &processBlackList, blackListfromSources)
				}
			}
		}
		if len(secPolicy.Spec.Process.MatchPatterns) > 0 {
			for _, pat := range secPolicy.Spec.Process.MatchPatterns {
				if pat.Action == "Allow" {
					se.AllowedProcessMatchPatterns(pat, &processWhiteList)
				} else if pat.Action == "Audit" {
					se.AuditedProcessMatchPatterns(pat, &processAuditList)
				} else if pat.Action == "Block" {
					se.BlockedProcessMatchPatterns(pat, &processBlackList)
				}
			}
		}

		if len(secPolicy.Spec.File.MatchPaths) > 0 {
			for _, path := range secPolicy.Spec.File.MatchPaths {
				if path.Action == "Allow" {
					se.AllowedFileMatchPaths(path, &fileWhiteList, whiteListfromSources)
				} else if path.Action == "Audit" {
					se.AuditedFileMatchPaths(path, &fileAuditList, auditListfromSources)
				} else if path.Action == "Block" {
					se.BlockedFileMatchPaths(path, &fileBlackList, blackListfromSources)
				}
			}
		}
		if len(secPolicy.Spec.File.MatchDirectories) > 0 {
			for _, dir := range secPolicy.Spec.File.MatchDirectories {
				if dir.Action == "Allow" {
					se.AllowedFileMatchDirectories(dir, &fileWhiteList, whiteListfromSources)
				} else if dir.Action == "Audit" {
					se.AuditedFileMatchDirectories(dir, &fileAuditList, auditListfromSources)
				} else if dir.Action == "Block" {
					se.BlockedFileMatchDirectories(dir, &fileBlackList, blackListfromSources)
				}
			}
		}
		if len(secPolicy.Spec.File.MatchPatterns) > 0 {
			for _, pat := range secPolicy.Spec.File.MatchPatterns {
				if pat.Action == "Allow" {
					se.AllowedFileMatchPatterns(pat, &fileWhiteList)
				} else if pat.Action == "Audit" {
					se.AuditedFileMatchPatterns(pat, &fileAuditList)
				} else if pat.Action == "Block" {
					se.BlockedFileMatchPatterns(pat, &fileBlackList)
				}
			}
		}
	}

	// generate new rules

	newRules := map[string][]tp.SELinuxRule{}

	// black list

	for _, rule := range processBlackList {
		if _, ok := newRules[rule.SubjectPath]; !ok {
			newRules[rule.SubjectPath] = []tp.SELinuxRule{}
		}

		if !se.ContainsElement(newRules[rule.SubjectPath], rule) {
			newRules[rule.SubjectPath] = append(newRules[rule.SubjectPath], rule)
			count = count + 1
		}
	}

	for _, rule := range fileBlackList {
		if _, ok := newRules[rule.SubjectPath]; !ok {
			newRules[rule.SubjectPath] = []tp.SELinuxRule{}
		}

		if !se.ContainsElement(newRules[rule.SubjectPath], rule) {
			newRules[rule.SubjectPath] = append(newRules[rule.SubjectPath], rule)
			count = count + 1
		}
	}

	for _, rules := range blackListfromSources {
		for _, rule := range rules {
			if _, ok := newRules[rule.SubjectPath]; !ok {
				newRules[rule.SubjectPath] = []tp.SELinuxRule{}
			}

			if !se.ContainsElement(newRules[rule.SubjectPath], rule) {
				newRules[rule.SubjectPath] = append(newRules[rule.SubjectPath], rule)
				count = count + 1
			}
		}
	}

	// audit list

	for _, rule := range processAuditList {
		if _, ok := newRules[rule.SubjectPath]; !ok {
			newRules[rule.SubjectPath] = []tp.SELinuxRule{}
		}

		if !se.ContainsElement(newRules[rule.SubjectPath], rule) {
			newRules[rule.SubjectPath] = append(newRules[rule.SubjectPath], rule)
			count = count + 1
		}
	}

	for _, rule := range fileAuditList {
		if _, ok := newRules[rule.SubjectPath]; !ok {
			newRules[rule.SubjectPath] = []tp.SELinuxRule{}
		}

		if !se.ContainsElement(newRules[rule.SubjectPath], rule) {
			newRules[rule.SubjectPath] = append(newRules[rule.SubjectPath], rule)
			count = count + 1
		}
	}

	for _, rules := range auditListfromSources {
		for _, rule := range rules {
			if _, ok := newRules[rule.SubjectPath]; !ok {
				newRules[rule.SubjectPath] = []tp.SELinuxRule{}
			}

			if !se.ContainsElement(newRules[rule.SubjectPath], rule) {
				newRules[rule.SubjectPath] = append(newRules[rule.SubjectPath], rule)
				count = count + 1
			}
		}
	}

	// white list

	for _, rule := range processWhiteList {
		if _, ok := newRules[rule.SubjectPath]; !ok {
			newRules[rule.SubjectPath] = []tp.SELinuxRule{}
		}

		if !se.ContainsElement(newRules[rule.SubjectPath], rule) {
			newRules[rule.SubjectPath] = append(newRules[rule.SubjectPath], rule)
			count = count + 1
		}
	}

	for _, rule := range fileWhiteList {
		if _, ok := newRules[rule.SubjectPath]; !ok {
			newRules[rule.SubjectPath] = []tp.SELinuxRule{}
		}

		if !se.ContainsElement(newRules[rule.SubjectPath], rule) {
			newRules[rule.SubjectPath] = append(newRules[rule.SubjectPath], rule)
			count = count + 1
		}
	}

	for _, rules := range whiteListfromSources {
		for _, rule := range rules {
			if _, ok := newRules[rule.SubjectPath]; !ok {
				newRules[rule.SubjectPath] = []tp.SELinuxRule{}
			}

			if !se.ContainsElement(newRules[rule.SubjectPath], rule) {
				newRules[rule.SubjectPath] = append(newRules[rule.SubjectPath], rule)
				count = count + 1
			}
		}
	}

	// generate a new profile

	newProfile := ""

	sources := []string{}
	srcLabel := map[string]string{}
	srcCount := 1

	for src := range newRules {
		if src == "-" {
			if _, ok := srcLabel["-"]; !ok {
				sources = append(sources, "karmor")
				srcLabel["-"] = "karmor_"
			}
		} else {
			if _, ok := srcLabel[src]; !ok {
				sources = append(sources, fmt.Sprintf("karmor%d", srcCount))
				srcLabel[src] = fmt.Sprintf("karmor%d_", srcCount)
				srcCount++
			}
		}
	}

	for _, rules := range newRules {
		for _, rule := range rules {
			// make a string
			line := fmt.Sprintf("%s\t%s\t%s\t%s\t%t\t%t\t%t\t%t\n",
				rule.SubjectLabel, rule.SubjectPath, rule.ObjectLabel, rule.ObjectPath, rule.Permissive, rule.Directory, rule.Recursive, rule.Pattern)

			// update labels in the string
			line = strings.Replace(line, "karmor_", srcLabel[rule.SubjectPath], -1)

			// add the string
			newProfile = newProfile + line
		}
	}

	// check if the old profile exists

	if _, err := os.Stat(filepath.Clean(cfg.GlobalCfg.SELinuxProfileDir + seLinuxProfile)); os.IsNotExist(err) {
		return 0, err.Error(), []string{}, false
	}

	// get the old profile

	profile, err := ioutil.ReadFile(filepath.Clean(cfg.GlobalCfg.SELinuxProfileDir + seLinuxProfile))
	if err != nil {
		return 0, err.Error(), []string{}, false
	}
	oldProfile := string(profile)

	// check if the new profile and the old one are the same

	if oldProfile != newProfile {
		return count, newProfile, sources, true
	}

	return 0, "", []string{}, false
}