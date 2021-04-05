# Local Test Guide

*  Test in manual
    1. Apply custom resource definitions (CRDs) into Kubernetes

        ```text
        $ cd KubeArmor/deployments/CRD
        (CRD) $ kubectl apply -f .
        ```

    2. Run 'kubectl proxy' in background

        ```text
        $ kubectl proxy &
        ```

    3. Run KubeArmor

        ```text
        $ cd KubeArmor/KubeArmor
        (KubeArmor) $ make clean && make
        (KubeArmor) $ make run
        ```

        If you want to change the gRPC port or the location of a log file, you can run KubeArmor like this.

        ```text
        (KubeArmor) $ sudo -E ./kubearmor sudo -E ./kubearmor -port=[gRPC port number] -output=[log file path]
        ```

    4. Apply security policies for testing

        ```text
        kubectl apply -f [policy file]
        ```

        Instead, you can use the security policies defined for example microservices in the [examples](../examples/README.md) directory.

    5. Generate logs by triggering policy violations

        ```text
        kubectl -n [namespace name] exec -it [pod name] -- bash -c [command]
        ```

    6. Check KubeArmor's alerts and logs
        - Log file

            ```text
            $ tail (-f) /tmp/kubearmor.log
            ```

            If you changed the location of a log file, you need to check that file instead of '/tmp/kubearmor.log'.

            ```text
            $ tail (-f) [your log file path]
            ```

        - Log client

            First, compile a log client.

            ```text
            $ cd KubeArmor/LogClient
            (LogClient) $ make
            ```

            Then, run the log client.

            ```text
            (LogClient) $ ./kubearmor-client (options...)
            ```

            Log client options:

            ```text
            -grpc=[ipaddr:port]        gRPC server information (default: localhost:32767)
            -msg={path|stdout|none}    Output for KubeArmor's messages (default: none)
            -log={path|stdout|none}    Output for KubeArmor's alerts and logs (default: none)
            -type={all|policy|system}  Filter for what kinds of logs to receive (default: policy)
            -raw                       Flag to print messages and logs in a JSON format
            ```

            Note that you will receive the messages and logs created after the log client runs, meaning that you need to run the log client to get the logs before any policy violations happen.

*  Test using the auto-testing framework

    1. Testcases

        To use the auto-testing framework, you need to define two things: microservices and scenarios for each microservice.

        - Microservices

            You need to define a microservice by creating a directory.

            ```text
            $ cd KubeArmor/tests/microservices
            (microservices) $ mkdir [microservice name]
            ```

            Then, you create YAML files for the microservice.

            ```text
            $ cd KubeArmor/tests/microservices/[microservice name]
            (microservice name) $ ...
            ```

            As an example, we created the 'multiubuntu' directory in 'microservices', and defined 'multiubuntu-deployment.yaml' in 'multiubuntu'.

        - Test scenarios

            In terms of testcases, you need to define a scenario per directory and make the directory name like '[microservice name]_[test scenario name]'. Then, you need to define a YAML file as a test policy in the directory.

            As a next step, you need to create cmd files whose names are like 'cmd#'. Here is a template for a cmd file.

            ```text
            source: [pod name]
            cmd: [command to trigger a policy violation]
            result: [expected result], { passed | failed }
            ---
            operation: [operation], { Process | File | Network }
            condition: [matching string to get a log (e.g., resource)]
            action: [action in a policy]
            ```

            This is an example of a scenario.

            ```text
            source: ubuntu-1-deployment
            cmd: sleep 1
            result: failed
            ---
            operation: Process
            condition: sleep
            action: Block
            ```

            You can refer to our scenarios in 'scenarios'.

    2. Test in local

        When you are developing KubeArmor on running Kubernetes, you can choose this option.

        First, you compile KubeArmor.

        ```text
        $ cd KubeArmor/KubeArmor
        (KubeArmor) $ make clean && make
        ```

        Next, you need to make sure that KubeArmor's CRDs are deployed and 'kubectl proxy' is running.

        ```text
        $ cd KubeArmor/deployments/CRD
        (CRD) $ kubectl apply -f .
        ```

        ```text
        $ kubectl proxy &
        ```

        Then, you run the auto-testing framework.

        ```text
        $ cd KubeArmor/tests
        (tests) $ ./test-scenarios-local.sh
        ```

    3. Test using MicroK8s

        When you are developing KubeArmor with MicroK8s, you can choose this option.

        First, you compile KubeArmor.

        ```text
        $ cd KubeArmor/KubeArmor
        (KubeArmor) $ make clean && make
        ```

        Next, you need to make sure that KubeArmor's CRDs are deployed and 'kubectl proxy' is running.

        ```text
        $ cd KubeArmor/deployments/CRD
        (CRD) $ kubectl apply -f .
        ```

        ```text
        $ kubectl proxy &
        ```

        Then, you run the auto-testing framework.

        ```text
        $ cd KubeArmor/tests
        (tests) $ ./test-scenarios-with-microk8s.sh
        ```

    4. Test in runtime

        When KubeArmor is already deployed on running Kubernetes, you can choose this option.

        ```text
        $ cd KubeArmor/tests
        (tests) $ ./test-scenarios-in-runtime.sh
        ```
