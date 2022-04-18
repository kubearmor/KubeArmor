# Vagrant-SELinux

1. Environment Setup

    To test KubeArmor for the SELinux-enabled environment, please run the following commands.

    ```text
    $ cd KubeArmor/KubeArmor
    ~/KubeArmor/KubeArmor $ make vagrant-up OS=centos
    ```

2. Preparation

    To test host policies, please run the following commands.

    ```text
    $ cd KubeArmor/KubeArmor
    ~/KubeArmor/KubeArmor $ make vagrant-ssh
    (vagrant) $ cd KubeArmor/examples/vagrant-selinux
    (vagrant...vagrant-selinux) $ ./copy.sh
    ```

3. Test

    To verify KubeArmor's functionalities, we provide sample host security policies.

    ```text
    (vagrant) $ cd selinux-test/policies
    (vagrant...policies) $ ls
    hsp-kubearmor-dev-proc-path-block.yaml
    hsp-kubearmor-dev-proc-path-allow-fromSource.yaml
    hsp-kubearmor-dev-proc-path-block-fromSource.yaml
    hsp-kubearmor-dev-file-path-block.yaml
    hsp-kubearmor-dev-file-path-allow-fromSource.yaml
    hsp-kubearmor-dev-file-path-allow-fromSource-readOnly.yaml
    hsp-kubearmor-dev-file-path-block-fromSource.yaml
    hsp-kubearmor-dev-file-path-block-fromSource-readOnly.yaml
    hsp-kubearmor-dev-file-dir-allow-fromSource.yaml
    hsp-kubearmor-dev-file-dir-block-fromSource.yaml
    ```

    We also provide instructions to test each policy.

    - hsp-kubearmor-dev-proc-path-block.yaml

        ```text
        apiVersion: security.kubearmor.com/v1
        kind: KubeArmorHostPolicy
        metadata:
        name: hsp-kubearmor-dev-proc-path-block
        spec:
        nodeSelector:
            matchLabels:
            kubernetes.io/hostname: kubearmor-dev
        severity: 5
        process:
            matchPaths:
            - path: /home/vagrant/selinux-test/read
        action:
            Block
        ```

        ```text
        # expectation
        # anyone cannot execute /home/vagrant/selinux-test/read

        # test
        # (/home/vagrant/selinux-test/) $ ./read
        # -bash: ./read: Permission denied
        ```

    - hsp-kubearmor-dev-proc-path-allow-fromSource.yaml

        ```text
        apiVersion: security.kubearmor.com/v1
        kind: KubeArmorHostPolicy
        metadata:
        name: hsp-kubearmor-dev-proc-path-allow-fromsource
        spec:
        nodeSelector:
            matchLabels:
            kubernetes.io/hostname: kubearmor-dev
        severity: 5
        process:
            matchPaths:
            - path: /home/vagrant/selinux-test/write
              fromSource:
              - path: /home/vagrant/selinux-test/bash
        action:
            Allow
        ```

        ```text
        # expectation
        # /home/vagrant/selinux-test/bash can execute /home/vagrant/selinux-test/write
        # /home/vagrant/selinux-test/bash cannot execute any others

        # test
        # (/home/vagrant/selinux-test/) $ ./bash -c ./write
        # Usage: ./write [file]
        # (/home/vagrant/selinux-test/) $ ./bash -c ./read
        # -bash: ./read: Permission denied
        ```
    
    - hsp-kubearmor-dev-proc-path-block-fromSource.yaml

        ```text
        apiVersion: security.kubearmor.com/v1
        kind: KubeArmorHostPolicy
        metadata:
        name: hsp-kubearmor-dev-proc-path-block-fromsource
        spec:
        nodeSelector:
            matchLabels:
            kubernetes.io/hostname: kubearmor-dev
        severity: 5
        process:
            matchPaths:
            - path: /home/vagrant/selinux-test/write
              fromSource:
              - path: /home/vagrant/selinux-test/bash
        action:
            Block
        ```

        ```text
        # expectation
        # /home/vagrant/selinux-test/bash cannot execute /home/vagrant/selinux-test/write
        # /home/vagrant/selinux-test/bash can execute any others

        # test
        # (/home/vagrant/selinux-test/) $ ./bash -c ./write
        # ./bash: ./write: Permission denied
        # (/home/vagrant/selinux-test/) $ ./bash -c ./read
        # Usage: ./read [file]
        ```
    
    - hsp-kubearmor-dev-file-path-block.yaml

        ```text
        apiVersion: security.kubearmor.com/v1
        kind: KubeArmorHostPolicy
        metadata:
        name: hsp-kubearmor-dev-file-path-block
        spec:
        nodeSelector:
            matchLabels:
            kubernetes.io/hostname: kubearmor-dev
        severity: 5
        file:
            matchPaths:
            - path: /home/vagrant/selinux-test/file.txt
        action:
            Block
        ```

        ```text
        # expectation
        # anyone cannot access /home/vagrant/selinux-test/file.txt

        # test
        # (/home/vagrant/selinux-test/) $ cat file.txt
        # cat: file.txt: Permission denied
        ```
    
    - hsp-kubearmor-dev-file-path-allow-fromSource.yaml

        ```text
        apiVersion: security.kubearmor.com/v1
        kind: KubeArmorHostPolicy
        metadata:
        name: hsp-kubearmor-dev-file-path-allow-fromsource
        spec:
        nodeSelector:
            matchLabels:
            kubernetes.io/hostname: kubearmor-dev
        severity: 5
        file:
            matchPaths:
            - path: /home/vagrant/selinux-test/file.txt
              fromSource:
              - path: /home/vagrant/selinux-test/read
        action:
            Allow
        ```

        ```text
        # expectation
        # /home/vagrant/selinux-test/read can access /home/vagrant/selinux-test/file.txt
        # /home/vagrant/selinux-test/read cannot access any others

        # test
        # (/home/vagrant/selinux-test/) $ ./read file.txt
        # read hello
        #  from file.txt
        # (/home/vagrant/selinux-test/) $ ./read read.c
        # failed to open read.c with the WRITE mode
        ```
    
    - hsp-kubearmor-dev-file-path-allow-fromSource-readOnly.yaml

        ```text
        apiVersion: security.kubearmor.com/v1
        kind: KubeArmorHostPolicy
        metadata:
        name: hsp-kubearmor-dev-file-path-block-fromsource-readonly
        spec:
        nodeSelector:
            matchLabels:
            kubernetes.io/hostname: kubearmor-dev
        severity: 5
        file:
            matchPaths:
            - path: /home/vagrant/selinux-test/file.txt
              readOnly: true
              fromSource:
              - path: /home/vagrant/selinux-test/readwrite
        action:
            Block
        ```

        ```text
        # expectation
        # /home/vagrant/selinux-test/readwrite can only read /home/vagrant/selinux-test/file.txt

        # test
        # (/home/vagrant/selinux-test/) $ ./readwrite -r file.txt
        # hello
        # (/home/vagrant/selinux-test/) $ ./readwrite matchDir/test1
        # Error!
        # (/home/vagrant/selinux-test/) $ ./readwrite -w file.txt
        # Error!
        ```

    - hsp-kubearmor-dev-file-path-block-fromSource.yaml

        ```text
        apiVersion: security.kubearmor.com/v1
        kind: KubeArmorHostPolicy
        metadata:
        name: hsp-kubearmor-dev-file-path-block-fromsource
        spec:
        nodeSelector:
            matchLabels:
            kubernetes.io/hostname: kubearmor-dev
        severity: 5
        file:
            matchPaths:
            - path: /home/vagrant/selinux-test/file.txt
              fromSource:
              - path: /home/vagrant/selinux-test/read
        action:
            Block
        ```

        ```text
        # expectation
        # /home/vagrant/selinux-test/read cannot access /home/vagrant/selinux-test/file.txt
        # /home/vagrant/selinux-test/read can access any others

        # test
        # (/home/vagrant/selinux-test/) $ ./read file.txt
        # failed to open file.txt with the READONLY mode
        # (/home/vagrant/selinux-test/) $ ./read read.c
        # ...
        ```

    - hsp-kubearmor-dev-file-path-block-fromSource-readOnly.yaml

        ```text
        apiVersion: security.kubearmor.com/v1
        kind: KubeArmorHostPolicy
        metadata:
        name: hsp-kubearmor-dev-file-path-block-fromsource-readonly
        spec:
        nodeSelector:
            matchLabels:
            kubernetes.io/hostname: kubearmor-dev
        severity: 5
        file:
            matchPaths:
            - path: /home/vagrant/selinux-test/file.txt
              readOnly: true
              fromSource:
              - path: /home/vagrant/selinux-test/readwrite
        action:
            Block
        ```

        ```text
        # expectation
        # /home/vagrant/selinux-test/readwrite can read /home/vagrant/selinux-test/file.txt and write something in any others
        # /home/vagrant/selinux-test/readwrite cannot write something in /home/vagrant/selinux-test/file.txt

        # test
        # (/home/vagrant/selinux-test/) $ ./readwrite -r file.txt
        # h
        # (/home/vagrant/selinux-test/) $ ./readwrite -r matchDir/test1
        # t
        # (/home/vagrant/selinux-test/) $ ./readwrite -w file.txt
        # Error!
        # (/home/vagrant/selinux-test/) $ ./readwrite -w matchDir/test1
        # [no output]
        ```

    - hsp-kubearmor-dev-file-dir-allow-fromSource.yaml

        ```text
        apiVersion: security.kubearmor.com/v1
        kind: KubeArmorHostPolicy
        metadata:
        name: hsp-kubearmor-dev-file-dir-allow-fromsource
        spec:
        nodeSelector:
            matchLabels:
            kubernetes.io/hostname: kubearmor-dev
        severity: 5
        file:
            matchDirectories:
            - dir: /home/vagrant/selinux-test/matchDir/
              recursive: true
              fromSource:
              - path: /home/vagrant/selinux-test/read
        action:
            Allow
        ```

        ```text
        # expectation
        # /home/vagrant/selinux-test/read can access /home/vagrant/selinux-test/matchDir/*
        # /home/vagrant/selinux-test/read cannot access any others

        # test
        # (/home/vagrant/selinux-test/) $ ./read matchDir/test1 (test2 test3 test4 test5)
        # read test1
        #  from matchDir/test1
        # (/home/vagrant/selinux-test/) $ ./read file.txt
        # failed to open file.txt with the READONLY mode
        ```

    - hsp-kubearmor-dev-file-dir-block-fromSource.yaml

        ```text
        apiVersion: security.kubearmor.com/v1
        kind: KubeArmorHostPolicy
        metadata:
        name: hsp-kubearmor-dev-file-dir-block-fromsource
        spec:
        nodeSelector:
            matchLabels:
            kubernetes.io/hostname: kubearmor-dev
        severity: 5
        file:
            matchDirectories:
            - dir: /home/vagrant/selinux-test/matchDir/
              fromSource:
              - path: /home/vagrant/selinux-test/read
        action:
            Block
        ```

        ```text
        # expectation
        # /home/vagrant/selinux-test/read cannot access /home/vagrant/selinux-test/matchDir/*
        # /home/vagrant/selinux-test/read can access any others

        # test
        # (/home/vagrant/selinux-test/) $ ./read matchDir/test1 (test2 test3 test4 test5)
        # failed to open test1 with the READONLY mode
        # (/home/vagrant/selinux-test/) $ ./read file.txt
        # read hello
        #  from file.txt
        ```
