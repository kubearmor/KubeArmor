# KubeArmor AppArmor implementation overview

Kubearmor support enforcing policies on systems running apparmor.

## Implementation overview

![Action Conflict](./resources/kubearmor-Apparmor-internals.png)

Upon the detection of a new Pod or a new policy, KubeArmor will launch a policy matching process that works as follow:

- If a new pod is detected, KubeArmor will only search for policies that matches that perticular pod.
- If a new policy is detected, KubeArmor will search for all pods that the policy include.

When all policies are identified, KubeArmor combines all policies into a single policy. If two policies are conflicting KubeArmor will resolve this conflict.

Once we have a single policy, KubeArmor will generate and load the corresponding AppArmor profile(s).


## AppArmor profile domain transition

KubeArmor makes a heavy use of apparmor domain transition in order to honor `fromSource` rules.

The domain transion is made possible using the `px` permission in apparmor.

![Action Conflict](./resources/Apparmor-domain-transition.png)

The above figure illustrate how we decide that we need to perform a domain transition for a certain binary.