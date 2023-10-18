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

By default, running a `make` in the `KubeArmor/tests` folders runs all the tests.
Check the ginkgo command in [`Makefile`](Makefile) for options used (such as `--flake-attempts`, `--timeout` etc) used.

Other ways of executing the testsuites:
1. Execute all testsuites using `ginkgo -r`
2. Execute specific testsuite using `ginkgo --focus "Smoke"` ... where `Smoke` is the name of the testsuite.
3. Execute specific testcase/testspec. Check [this](https://stackoverflow.com/a/47179043/881949).
4. Stop on first failure `ginkgo -r --fail-fast`

> * Note: Why is `--flake-attempts=5` used in `Makefile`? Lot of times, on resource constrained VMs provided by GH actions, the events from kubearmor are lost. This is essentially a performance issue, but currently we are rerunning the tests.

## I already have a k8s cluster. Is it possible to execute tests using it?
Yes, the tests assumes that there exists a k8s setup already operational.
