# Consideration in Policy Action

While operators can define security policies with an action (either Block or Allow), KubeArmor may handle those policies differently (blacklist vs. whitelist).

If the actions of all security policies for a container are Block, then these policies are handled in a blacklist manner. However, at least one system policy's action is Allow, then all system policies for a container are handled in a whitelist manner. It means that some security policies may be handled differently in containers.

Here is an example of this issue. There are two pods: pod A with (grp=1, role=A) and pod B with (grp=1, role=B). For them, let us say that an operator wants to block the execution of a bash shell, so he first defines a policy with (selector → grp=1, process → /bin/bash, action → block). This policy will then be enforced into both pods, and the pods cannot execute /bin/bash while some other applications are still executable (blacklist).

After that, the operator also wants for the pods with role=A to execute /app only. Then, this policy will be enforced into Pod A. At this point, a problem may pop up. Since Pod A has an Allow policy and a Block policy together, the way to handle those policies is changed from a blacklist manner to a whitelist manner, meaning that Pod A will be only able to execute /app. In contrast, /bin/bash will be blocked by default. Here, if Pod A only needs to run /app, then everything will be fine. However, Pod A also needs to execute some other applications (e.g., /logger), then there will be a severe problem since all applications except for /app will be blocked in Pod A.

![Policy Action Conflict](./resources/policy_action_conflict.png)

This issue may be solved by verifying the correlations among policies and notifying some conflicts to operators in advance. However, this would be so difficult.
