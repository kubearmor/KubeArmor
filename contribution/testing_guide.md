# Testing Guide

*  Test in manual
    1. Run 'kubectl proxy' in background

        ```text
        $ kubectl proxy &
        ```

    2. Run KubeArmor

        ```text
        $ cd KubeArmor/KubeArmor
        ~/KubeArmor/KubeArmor$ make clean && make
        ~/KubeArmor/KubeArmor$ make run
        ```

        If you want to change the number of the gRPC port or the location of a log file, run KubeArmor like the below.

        ```text
        ~/KubeArmor/KubeArmor$ sudo -E ./kubearmor -gRPC=[gRPC port number]
                                                   -logPath=[log file path]
                                                   -enableHostPolicy
        ```

    3. Apply security policies for testing

        Beforehand, check if the KubeArmorPolicy CRD is already applied.

        ```text
        $ kubectl explain KubeArmorPolicy
        ```

        If it's still not applied, do so.

        ```text
        $ kubectl apply -f ~/KubeArmor/deployments/CRD/KubeArmorPolicy.yaml
        ```

        Now you can apply specific policies.

        ```text
        $ kubectl apply -f [policy file]
        ```

        You can refer to the security policies defined for example microservices in [examples](../examples).

    4. Trigger policy violations to generate logs

        ```text
        $ kubectl -n [namespace name] exec -it [pod name] -- bash -c [command]
        ```

    5. Check KubeArmor's alerts and logs
        - Log file

            ```text
            $ tail (-f) /tmp/kubearmor.log
            ```

            If you changed the location of a log file, check your file instead of the default file path.

            ```text
            $ tail (-f) [your log file path]
            ```

        - Log client

            Compile a log client.

            ```text
            $ git clone https://github.com/kubearmor/kubearmor-log-client
            $ cd kubearmor-log-client
            ~/kubearmor-log-client$ make
            ```

            Run the log client.

            ```text
            ~/kubearmor-log-client$ ./kubearmor-log-client (options...)
            ```

            Log client options:

            ```text
            -gRPC=[ipaddr:port]             gRPC server information (default: localhost:32767)
            -msgPath={path|stdout|none}     Output location for KubeArmor's messages (default: none)
            -logPath={path|stdout|none}     Output location for KubeArmor's alerts and logs (default: stdout)
            -logFilter={policy|system|all}  Filter for what kinds of alerts and logs to receive (default: policy)
            -json                           Flag to print messages, alerts, and logs in a JSON format
            ```

            Note that you will see the messages, alerts, and logs generated right after the log client runs, which means that the log client should be ran before any policy violations happen.

*  Test using the auto-testing framework

    1. Testcases

        To use the auto-testing framework, you need to define two things: microservices and scenarios for each microservice.

        - Microservices

            Create a directory for a microservice in [microservices](../tests/microservices).

            ```text
            $ cd KubeArmor/tests/microservices
            ~/KubeArmor/tests/microservices$ mkdir [microservice name]
            ```

            Then, create YAML files for the microservice.

            ```text
            $ cd KubeArmor/tests/microservices/[microservice name]
            ~/KubeArmor/tests/microservices/[microservice name]$ ...
            ```

            As an example, we created 'multiubuntu' in [microservices](../tests/microservices), and defined 'multiubuntu-deployment.yaml' in [multiubuntu](../examples/multiubuntu).

        - Test scenarios

            Create a directory whose name is like '[microservice name]_[test scenario name]' in [scenarios](../tests/scenarios).
            
            ```text
            $ cd KubeArmor/tests/scenarios
            ~/KubeArmor/tests/scenarios$ mkdir [microservice name]_[test scenario name]
            ```
            
            Then, define a YAML file for a test policy in the directory.
            
            ```text
            ~/KubeArmor/tests/scenarios$ cd [microservice name]_[test scenario name]
            .../[microservice name]_[test scenario name]$ vi [policy name].yaml
            ```

            As a next step, create cmd files whose names are like 'cmd#'.
            
            ```text
            .../[microservice name]_[test scenario name]$ vi cmd1 / cmd2 / ...
            ```
            
            Here is a template for a cmd file.

            ```text
            source: [pod name]
            cmd: [command to trigger a policy violation]
            result: [expected result], { passed | failed }
            ---
            operation: [operation], { Process | File | Network }
            condition: [matching string]
            action: [action in a policy] { Allow | Audit | Block }
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

    2. Test KubeArmor in a local development environment
    
        - In the case that KubeArmor is not running

            Compile KubeArmor.

            ```text
            $ cd KubeArmor/KubeArmor
            ~/KubeArmor/KubeArmor$ make clean && make
            ```

            Make sure that 'kubectl proxy' is running.

            ```text
            $ kubectl proxy &
            ```

            Run the auto-testing framework (the framework will automatically run KubeArmor).

            ```text
            $ cd KubeArmor/tests
            ~/KubeArmor/tests$ ./test-scenarios-local.sh
            ```

            Check the test report

            ```text
            ~/KubeArmor/tests$ cat /tmp/kubearmor.test
            ```

        - In the case that KubeArmor is running

            Run the auto-testing framework. Please make sure that KubeArmor is in a running state.

            ```text
            $ cd KubeArmor/tests
            ~/KubeArmor/tests$ ./test-scenarios-in-runtime.sh
            ```

            Check the test report

            ```text
            ~/KubeArmor/tests$ cat /tmp/kubearmor.test
            ```

    3. Test the containerized KubeArmor image on running Kubernetes

        Run the auto-testing framework. Please make sure that KubeArmor is in a running state.

        ```text
        $ cd KubeArmor/tests
        ~/KubeArmor/tests$ ./test-scenarios-in-runtime.sh
        ```

        Check the test report

        ```text
        ~/KubeArmor/tests$ cat /tmp/kubearmor.test
        ```
