# Local Test Guide

*  Test in manual
    1. Apply [custom resource definitions (CRDs)](../deployments/CRD) into Kubernetes

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

        If you want to change the gRPC port or the location of a log file, run KubeArmor like the below.

        ```text
        (KubeArmor) $ sudo -E ./kubearmor sudo -E ./kubearmor -port=[gRPC port number] -output=[log file path]
        ```

    4. Apply security policies for the testing purpose

        ```text
        kubectl apply -f [policy file]
        ```

        You can refer to the security policies defined for example microservices in [examples](../examples).

    5. Trigger policy violations to generate logs

        ```text
        kubectl -n [namespace name] exec -it [pod name] -- bash -c [command]
        ```

    6. Check KubeArmor's alerts and logs
        - Log file

            ```text
            $ tail (-f) /tmp/kubearmor.log
            ```

            If you changed the location of a log file, check your file instead of the default file.

            ```text
            $ tail (-f) [your log file path]
            ```

        - Log client

            Compile a log client.

            ```text
            $ cd KubeArmor/LogClient
            (LogClient) $ make
            ```

            Run the log client.

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

            Note that you will see the messages and logs created right after the log client runs, which means that the log client should be ran before any policy violations happen.

*  Test using the auto-testing framework

    1. Testcases

        To use the auto-testing framework, you need to define two things: microservices and scenarios for each microservice.

        - Microservices

            Create a directory for a microservice in [microservices](../tests/microservices).

            ```text
            $ cd KubeArmor/tests/microservices
            (microservices) $ mkdir [microservice name]
            ```

            Then, create YAML files for the microservice.

            ```text
            $ cd KubeArmor/tests/microservices/[microservice name]
            (microservice name) $ ...
            ```

            As an example, we created 'multiubuntu' in [microservices](../tests/microservices), and defined 'multiubuntu-deployment.yaml' in [multiubuntu](../examples/multiubuntu).

        - Test scenarios

            Create a directory whose name is like '[microservice name]_[test scenario name]' in [scenarios](../tests/scenarios).
            
            ```text
            $ cd KubeArmor/tests/scenarios
            (scenarios) $ mkdir [microservice name]_[test scenario name]
            ```
            
            Then, define a YAML file for a test policy in the directory.
            
            ```text
            (scenarios) $ cd [microservice name]_[test scenario name]
            ([microservice name]_[test scenario name]) $ vi [policy name].yaml
            ```

            As a next step, create cmd files whose names are like 'cmd#'.
            
            ```text
            ([microservice name]_[test scenario name]) $ vi cmd1 / cmd2 / ...
            ```
            
            Here is a template for a cmd file.

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

            You can refer to our scenarios in [scenarios](../tests/scenarios).

    2. Test in local

        When you are developing KubeArmor on running Kubernetes, you can choose this option.

        Compile KubeArmor.

        ```text
        $ cd KubeArmor/KubeArmor
        (KubeArmor) $ make clean && make
        ```

        Make sure that KubeArmor's CRDs are deployed and 'kubectl proxy' is running.

        ```text
        $ cd KubeArmor/deployments/CRD
        (CRD) $ kubectl apply -f .
        ```

        ```text
        $ kubectl proxy &
        ```

        Run the auto-testing framework.

        ```text
        $ cd KubeArmor/tests
        (tests) $ ./test-scenarios-local.sh
        ```

    3. Test using MicroK8s

        When you are developing KubeArmor with MicroK8s, you can choose this option.

        Compile KubeArmor.

        ```text
        $ cd KubeArmor/KubeArmor
        (KubeArmor) $ make clean && make
        ```

        Make sure that KubeArmor's CRDs are deployed and 'kubectl proxy' is running.

        ```text
        $ cd KubeArmor/deployments/CRD
        (CRD) $ kubectl apply -f .
        ```

        ```text
        $ kubectl proxy &
        ```

        Run the auto-testing framework.

        ```text
        $ cd KubeArmor/tests
        (tests) $ ./test-scenarios-with-microk8s.sh
        ```

    4. Test in runtime

        When KubeArmor is already deployed on running Kubernetes, you can choose this option.

        Run the auto-testing framework.

        ```text
        $ cd KubeArmor/tests
        (tests) $ ./test-scenarios-in-runtime.sh
        ```
