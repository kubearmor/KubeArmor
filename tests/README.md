# KubeArmor Automated Tests

## Prerequisites
1. Install ginkgo `go install -mod=mod github.com/onsi/ginkgo/v2/ginkgo`
2. `kubectl` needs to be installed

## How to add a new testsuite?

```
mkdir $BASE/newsuite && cd $BASE/newsuite
ginkgo bootstrap # This adds the skeleton for a new testcase
```

## How to add a new testcase/testspec?
Refer to `$BASE/smoke` folder.

For making assertions in testspec using gomega, [check this](https://onsi.github.io/gomega/#making-assertions).

## How to execute testsuites?

1. Execute all testsuites using `ginkgo -r`
2. Execute specific testsuite using `ginkgo --focus "Smoke"` ... where `Smoke` is the name of the testsuite.
3. Execute specific testcase/testspec. Check [this](https://stackoverflow.com/a/47179043/881949).

Check the ginkgo command in [`Makefile`](Makefile) for other options (such as flake-attempts, timeout etc) used.

## I already have a k8s cluster. Is it possible to execute tests using it?
Yes, the tests assumes that there exists a k8s setup already operational.
