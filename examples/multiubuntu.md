# Multiubuntu

![multiubuntu](../.gitbook/assets/multiubuntu.png)

1. Deployment

    To deploy the multiubuntu microservice, please run the following commands.

    ```text
    $ cd KubeArmor/examples/multiubuntu
    ~/KubeArmor/examples/multiubuntu$ kubectl apply -f .
    ```

2. Use Cases

    To verify KubeArmor's functionalities, we provide sample security policies for the multiubuntu microservice.

    * Example 1 - Block a process execution

        * Deploy a security policy

            ```text
            $ cd KubeArmor/examples/multiubuntu/security-policies
            .../multiubuntu/security-policies$ kubectl -n multiubuntu apply -f ksp-group-1-proc-path-block.yaml
            ```

        * Execute /bin/sleep inside of the ubuntu-1 pod

            ```text
            $ kubectl -n multiubuntu exec -it {pod name for ubuntu 1} -- bash
            # sleep 1
            (Permission Denied)
            ```

        * Check audit logs

            ```text
            $ kubectl -n kube-system exec -it {KubeArmor in the node where ubuntu 1 is located} -- tail /tmp/kubearmor.log
            ```

    * Example 2 - Block a file access

        * Deploy a security policy

            ```text
            $ cd security-policies
            .../multiubuntu/security-policies$ kubectl -n multiubuntu apply -f ksp-ubuntu-5-file-dir-recursive-block.yaml
            ```

        * Access /credentials/password inside of the ubuntu-5 pod

            ```text
            $ kubectl -n multiubuntu exec -it {pod name for ubuntu 5} -- bash
            # cat cat /credentials/password
            (Permission Denied)
            ```

        * Check audit logs

            ```text
            $ kubectl -n kube-system exec -it {KubeArmor in the node where ubuntu 5 is located} -- tail /tmp/kubearmor.log
            ```
