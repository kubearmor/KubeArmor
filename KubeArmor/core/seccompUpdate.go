package core

import (
	"encoding/json"
	"io"
	"sort"
	"time"

	kl "github.com/kubearmor/KubeArmor/KubeArmor/common"
	cfg "github.com/kubearmor/KubeArmor/KubeArmor/config"
	tp "github.com/kubearmor/KubeArmor/KubeArmor/types"
)

const KscmpApiResName string = "kubearmorseccomppolicies"

// WatchSeccompPolicies Function
func (dm *KubeArmorDaemon) WatchSeccompPolicies() {
	for {
		if !K8s.CheckCustomResourceDefinition(KscmpApiResName) {
			time.Sleep(time.Second * 1)
			continue
		}

		if resp := K8s.WatchK8sSecurityPolicies(KscmpApiResName); resp != nil {
			defer resp.Body.Close()

			decoder := json.NewDecoder(resp.Body)
			for {
				event := tp.K8sSeccompPolicyEvent{}
				if err := decoder.Decode(&event); err == io.EOF {
					break
				} else if err != nil {
					break
				}

				if event.Object.Status.Status != "" && event.Object.Status.Status != "OK" {
					continue
				}

				if event.Type != "ADDED" && event.Type != "MODIFIED" && event.Type != "DELETED" {
					continue
				}

				// create a security policy

				secPolicy := tp.SeccompPolicy{}

				secPolicy.Metadata = map[string]string{}
				secPolicy.Metadata["namespaceName"] = event.Object.Metadata.Namespace
				secPolicy.Metadata["policyName"] = event.Object.Metadata.Name

				if err := kl.Clone(event.Object.Spec, &secPolicy.Spec); err != nil {
					dm.Logger.Err("Failed to clone a spec")
					continue
				}

				if secPolicy.Spec.Severity == 0 {
					secPolicy.Spec.Severity = 1 // the lowest severity, by default
				}

				switch secPolicy.Spec.Action {
				case "allow":
					secPolicy.Spec.Action = "Allow"
				case "audit":
					secPolicy.Spec.Action = "Audit"
				case "block":
					secPolicy.Spec.Action = "Block"
				case "":
					secPolicy.Spec.Action = "Block" // by default
				}

				// add identities

				secPolicy.Spec.Selector.Identities = []string{"namespaceName=" + event.Object.Metadata.Namespace}

				for k, v := range secPolicy.Spec.Selector.MatchLabels {
					secPolicy.Spec.Selector.Identities = append(secPolicy.Spec.Selector.Identities, k+"="+v)
				}

				sort.Slice(secPolicy.Spec.Selector.Identities, func(i, j int) bool {
					return secPolicy.Spec.Selector.Identities[i] < secPolicy.Spec.Selector.Identities[j]
				})

				dm.Logger.Printf("Detected a Seccomp Policy (%s/%s/%s)",
					event.Type, secPolicy.Metadata["namespaceName"],
					secPolicy.Metadata["policyName"])

				if len(secPolicy.Spec.Seccomp.Syscalls) > 0 {
					if secPolicy.Spec.Seccomp.Severity == 0 {
						secPolicy.Spec.Seccomp.Severity = secPolicy.Spec.Severity
					}
				}
				dm.Logger.Printf("Policy: %+v", secPolicy.Spec.Seccomp)

				// apply security policies to pods
				dm.UpdateSeccompPolicy(event.Type, secPolicy)
			}
		}
	}
}

func matchMetadata(policy tp.SeccompPolicy, secPolicy tp.SeccompPolicy) bool {
	if policy.Metadata["namespaceName"] == secPolicy.Metadata["namespaceName"] &&
		policy.Metadata["policyName"] == secPolicy.Metadata["policyName"] {
		return true
	}
	return false
}

// UpdateSeccompPolicy Function
func (dm *KubeArmorDaemon) UpdateSeccompPolicy(action string, secPolicy tp.SeccompPolicy) {
	dm.EndPointsLock.Lock()
	defer dm.EndPointsLock.Unlock()

	dm.Logger.Printf("dm.UpdateSeccompPolicy enter")
	for idx, endPoint := range dm.EndPoints {
		// update a security policy
		if !kl.MatchIdentities(secPolicy.Spec.Selector.Identities, endPoint.Identities) {
			dm.Logger.Printf("endPoint.Identities: %+v", endPoint.Identities)
			continue
		}
		if action == "ADDED" {
			// add a new security policy if it doesn't exist
			new := true
			for _, policy := range endPoint.SeccompPolicies {
				if matchMetadata(policy, secPolicy) {
					new = false
					break
				}
			}
			if new {
				dm.EndPoints[idx].SeccompPolicies = append(dm.EndPoints[idx].SeccompPolicies, secPolicy)
			}
		} else if action == "MODIFIED" {
			for idxP, policy := range endPoint.SeccompPolicies {
				if matchMetadata(policy, secPolicy) {
					dm.EndPoints[idx].SeccompPolicies[idxP] = secPolicy
					break
				}
			}
		} else if action == "DELETED" {
			// remove the given policy from the security policy list of this endpoint
			for idxP, policy := range endPoint.SeccompPolicies {
				if matchMetadata(policy, secPolicy) {
					dm.EndPoints[idx].SeccompPolicies = append(dm.EndPoints[idx].SeccompPolicies[:idxP], dm.EndPoints[idx].SeccompPolicies[idxP+1:]...)
					break
				}
			}
		}

		if cfg.GlobalCfg.Seccomp {
			// update security policies
			// dm.Logger.UpdateSeccompPolicies("UPDATED", dm.EndPoints[idx])

			dm.Logger.Printf("dm.RuntimeEnforcer enter")
			if dm.RuntimeEnforcer != nil {
				// enforce security policies
				dm.RuntimeEnforcer.UpdateSeccompPolicies(dm.EndPoints[idx])
			}
		}
	}
}
