#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2021 Authors of KubeArmor

realpath() {
    CURR=$PWD

    cd "$(dirname "$0")"
    LINK=$(readlink "$(basename "$0")")

    while [ "$LINK" ]; do
        cd "$(dirname "$LINK")"
        LINK=$(readlink "$(basename "$1")")
    done

    REALPATH="$PWD/$(basename "$1")"
    echo "$REALPATH"

    cd $CURR
}

TEST_HOME=`dirname $(realpath "$0")`
CRD_HOME=`dirname $(realpath "$0")`/../deployments/CRD
ARMOR_HOME=`dirname $(realpath "$0")`/../KubeArmor

LSM="none"

cat /sys/kernel/security/lsm | grep selinux > /dev/null 2>&1
if [ $? == 0 ]; then
    LSM="selinux"
fi

cat /sys/kernel/security/lsm | grep apparmor > /dev/null 2>&1
if [ $? == 0 ]; then
    LSM="apparmor"
fi

if [ "$DEFAULT_POSTURE" == "" ]; then
    DEFAULT_POSTURE="block"
fi

ARMOR_OPTIONS=()

SKIP_CONTAINER_POLICY=1
SKIP_NATIVE_POLICY=1
SKIP_HOST_POLICY=1

case $1 in
    "-testPolicy")
        SKIP_CONTAINER_POLICY=0
        ARMOR_OPTIONS=${@:2}
        ;;
    "-testHostPolicy")
        echo "If you want to test host policies, please run KubeArmor separately and use test-scenarios-in-runtime.sh"
        exit
        ;;
    "-testNativePolicy")
        if [ "$LSM" != "apparmor" ]; then
            echo "KubeArmor does not support native policies if AppArmor is not enabled"
            exit
        fi
        SKIP_NATIVE_POLICY=0
        ARMOR_OPTIONS=${@:2}
        ;;
    *)
        if [ "$LSM" == "selinux" ]; then
            echo "If you want to test host policies, please run KubeArmor separately and use test-scenarios-in-runtime.sh"
            echo "KubeArmor does not support native policies if AppArmor is not enabled"
        elif [ "$LSM" == "apparmor" ]; then
            echo "If you want to test host policies, please run KubeArmor separately and use test-scenarios-in-runtime.sh"
            SKIP_NATIVE_POLICY=0
        else # none
            echo "KubeArmor does not support native policies if AppArmor is not enabled"
        fi
        SKIP_CONTAINER_POLICY=0
        ARMOR_OPTIONS=$@
        ;;
esac

ARMOR_MSG=/tmp/kubearmor.msg
ARMOR_LOG=/tmp/kubearmor.log
TEST_LOG=/tmp/kubearmor.test

RED='\033[0;31m'
GREEN='\033[0;32m'
ORANGE='\033[0;33m'
BLUE='\033[0;34m'
MAGENTA='\033[0;35m'
NC='\033[0m'

DBG()
{
    echo -e "[DBG] $*"
}

INFO()
{
    echo -e "${ORANGE}[INFO] $*${NC}"
}

WARN()
{
    echo -e "${MAGENTA}[WARN] $*${NC}"
}

PASS()
{
    echo -e "${BLUE}[PASS] $*${NC}"
}

FAIL()
{
    echo -e "${RED}[FAIL] $*${NC}"
}

## == Functions == ##

function start_and_wait_for_kubearmor_initialization() {
    cd $CRD_HOME

    kubectl apply -f .
    if [ $? != 0 ]; then
        FAIL "Failed to apply $1"
        exit 1
    fi

    cd $ARMOR_HOME

    if [ "$DEFAULT_POSTURE" == "allow" ]; then
        ARMOR_OPTIONS+=("-defaultFilePosture=allow")
        ARMOR_OPTIONS+=("-defaultNetworkPosture=allow")
        ARMOR_OPTIONS+=("-defaultCapabilitiesPosture=allow")
    elif [ "$DEFAULT_POSTURE" == "audit" ]; then # Current default posture is "audit" and for testing we need block based posture
        ARMOR_OPTIONS+=("-defaultFilePosture=block")
        ARMOR_OPTIONS+=("-defaultNetworkPosture=block")
        ARMOR_OPTIONS+=("-defaultCapabilitiesPosture=block")
    else # block
        ARMOR_OPTIONS+=("-defaultFilePosture=block")
        ARMOR_OPTIONS+=("-defaultNetworkPosture=block")
        ARMOR_OPTIONS+=("-defaultCapabilitiesPosture=block")
    fi

    echo "Options: -logPath=$ARMOR_LOG ${ARMOR_OPTIONS[@]}"
    if [[ ! " ${ARMOR_OPTIONS[@]} " =~ "-enableKubeArmorHostPolicy" ]]; then
        SKIP_HOST_POLICY=1
    fi

    ka_podname=`kubectl get pods -n kubearmor -l kubearmor-app=kubearmor -o custom-columns=":metadata.name" --no-headers`
    if [ "$ka_podname" != "" ]; then
        echo "Found KubeArmor from Kubernetes"

        CAT_LOG="kubectl exec -n kubearmor $ka_podname -- cat $ARMOR_LOG"
        CAT_MSG="kubectl logs -n kubearmor $ka_podname"

        sleep 10

        for count in {1..120}
        do
            $CAT_MSG | grep "Initialized KubeArmor$" &> /dev/null
            [[ $? -eq 0 ]] && break

            $CAT_MSG | grep "Terminated KubeArmor$" &> /dev/null
            [[ $? -eq 0 ]] && $CAT_MSG && exit 1

            sleep 1
        done

        $CAT_MSG
    else # start kubearmor as local process
        echo "Not found KubeArmor from Kubernetes, executing KubeArmor as a local process"

        CAT_LOG="cat $ARMOR_LOG"
        CAT_MSG="cat $ARMOR_MSG"

        PROXY=$(sudo netstat -ntlp | grep kubectl | grep 8001 | wc -l)
        if [ $PROXY != 1 ]; then
           FAIL "Proxy is not running"
           exit 1
        fi

        cd $ARMOR_HOME

        make clean; make build-test
        sudo -E ./kubearmor -test.coverprofile=.coverprofile -logPath=$ARMOR_LOG ${ARMOR_OPTIONS[@]} > $ARMOR_MSG &
        echo "Executed KubeArmor"

        sleep 10

        for count in {1..120}
        do
            $CAT_MSG | grep "Initialized KubeArmor$" &> /dev/null
            [[ $? -eq 0 ]] && break

            $CAT_MSG | grep "Terminated KubeArmor$" &> /dev/null
            [[ $? -eq 0 ]] && $CAT_MSG && exit 1

            sleep 1
        done

        $CAT_MSG
    fi
}

function stop_and_wait_for_kubearmor_termination() {
    [[ "$ka_podname" != "" ]] && echo "kubearmor not started by this script, hence not stopping" && return
    ps -e | grep kubearmor | awk '{print $1}' | xargs -I {} sudo kill {}

    for count in {1..60}
    do
        ps -e | grep kubearmor &> /dev/null
        if [ $? != 0 ]; then
            break
        fi

        sleep 1
    done
}

function apply_and_wait_for_microservice_creation() {
    cd $TEST_HOME/microservices/$1

    kubectl apply -f .
    if [ $? != 0 ]; then
        FAIL "Failed to apply $1$"
        res_microservice=1
        return
    fi

    sleep 1

    for (( ; ; ))
    do
        RAW=$(kubectl get pods -n $1 | wc -l)

        ALL=`expr $RAW - 1`
        READY=`kubectl get pods -n $1 | grep -e Running -e AppArmor | wc -l`

        [[ $ALL == $READY ]] && break

        sleep 1
    done
}

function delete_and_wait_for_microservice_deletion() {
    cd $TEST_HOME/microservices/$1

    kubectl delete -f .
    if [ $? != 0 ]; then
        FAIL "Failed to delete $1"
        res_delete=1
    fi
}

function should_not_find_any_log() {
    DBG "Finding the corresponding log"

    sleep 5

    audit_log=$($CAT_LOG | grep -E "$1.*policyName.*$2.*MatchedPolicy.*$6.*operation.*$3.*resource.*$4.*data.*action.*$5" | grep -v grep | tail -n 1 | grep -v Passed)
    if [ $? == 0 ]; then
        echo $audit_log
        FAIL "Found the log from logs"
        res_cmd=1
    else
        audit_log="<No Log>"
        DBG "Found no log from logs"
    fi
}

function should_find_passed_log() {
    DBG "Finding the corresponding log"

    sleep 5

    audit_log=$($CAT_LOG | grep -E "$1.*policyName.*$2.*MatchedPolicy.*operation.*$3.*resource.*$4.*data.*action.*$5" | grep -v grep | tail -n 1 | grep Passed)
    if [ $? != 0 ]; then
        audit_log="<No Log>"
        FAIL "Failed to find the log from logs"
        res_cmd=1
    else
        echo $audit_log
        DBG "Found the log from logs"
    fi
}

function should_find_blocked_log() {
    DBG "Finding the corresponding log"

    sleep 5

    audit_log=$($CAT_LOG | grep -E "$1.*policyName.*$2.*MatchedPolicy.*operation.*$3.*resource.*$4.*data.*action.*$5" | grep -v grep | tail -n 1 | grep -v Passed)
    if [ $? != 0 ]; then
        audit_log="<No Log>"
        FAIL "Failed to find the log from logs"
        res_cmd=1
    else
        echo $audit_log
        DBG "Found the log from logs"
    fi
}

function should_not_find_any_host_log() {
    DBG "Finding the corresponding log"

    sleep 5

    audit_log=$($CAT_LOG | grep -E "$HOST_NAME.*policyName.*$1.*MatchedHostPolicy.*$5.*operation.*$2.*resource.*$3.*data.*action.*$4" | grep -v grep | tail -n 1 | grep -v Passed)
    if [ $? == 0 ]; then
        echo $audit_log
        FAIL "Found the log from logs"
        res_cmd=1
    else
        audit_log="<No Log>"
        DBG "Found no log from logs"
    fi
}

function should_find_passed_host_log() {
    DBG "Finding the corresponding log"

    sleep 5

    audit_log=$($CAT_LOG | grep -E "$HOST_NAME.*policyName.*$1.*MatchedHostPolicy.*operation.*$2.*resource.*$3.*data.*action.*$4" | grep -v grep | tail -n 1 | grep Passed)
    if [ $? != 0 ]; then
        audit_log="<No Log>"
        FAIL "Failed to find the log from logs"
        res_cmd=1
    else
        echo $audit_log
        DBG "Found the log from logs"
    fi
}

function should_find_blocked_host_log() {
    DBG "Finding the corresponding log"

    sleep 5

    audit_log=$($CAT_LOG | grep -E "$HOST_NAME.*policyName.*$1.*MatchedHostPolicy.*operation.*$2.*resource.*$3.*data.*action.*$4" | grep -v grep | tail -n 1 | grep -v Passed)
    if [ $? != 0 ]; then
        audit_log="<No Log>"
        FAIL "Failed to find the log from logs"
        res_cmd=1
    else
        echo $audit_log
        DBG "Found the log from logs"
    fi
}

function run_test_scenario() {
    cd $1

    YAML_FILE=$(ls *.yaml)
    POLICY_TYPE=$(echo $YAML_FILE | awk '{split($0,a,"-"); print a[1]}')
    POLICY=$(grep "name:" $YAML_FILE | head -n1 | awk '{ print $2}')
    POLICY_ACTION=$(cat $YAML_FILE | grep "^action" | awk '{print $2}')
    NATIVE_POLICY=0
    HOST_POLICY=0

    if [[ $POLICY_TYPE == "ksp" ]]; then
        if [ $SKIP_CONTAINER_POLICY == 1 ]; then
            WARN "Skipped $3"
            skipped_testcases+=("$3")
            return
        fi
        if [[ "$DEFAULT_POSTURE" == "allow" ]] && [[ "$POLICY_ACTION" == "Allow" ]]; then
            WARN "Skipped $3"
            skipped_testcases+=("$3")
            return
        fi
    elif [[ $POLICY_TYPE == "nsp" ]]; then
        # skip a policy with a native profile unless AppArmor is enabled
        if [ "$LSM" != "apparmor" ]; then
            WARN "Skipped $3"
            skipped_testcases+=("$3")
            return
        elif [ $SKIP_NATIVE_POLICY == 1 ]; then
            WARN "Skipped $3"
            skipped_testcases+=("$3")
            return
        fi
        NATIVE_POLICY=1
    elif [[ $POLICY_TYPE == "hsp" ]]; then
        if [ $SKIP_HOST_POLICY == 1 ]; then
            WARN "Skipped $3"
            skipped_testcases+=("$3")
            return
        fi
        HOST_POLICY=1
    else
        WARN "Skipped unknown testcase $3"
        skipped_testcases+=("$3")
        return
    fi

    DBG "Applying $YAML_FILE into $2"
    if [[ $HOST_POLICY -eq 1 ]]; then
        kubectl apply -f $YAML_FILE
    else
        kubectl apply -n $2 -f $YAML_FILE
    fi

    if [ $? != 0 ]; then
        FAIL "Failed to apply $YAML_FILE into $2"
        res_case=1
        return
    fi
    DBG "Applied $YAML_FILE into $2"

    sleep 5
    cmd_count=0

    for cmd in $(ls cmd*)
    do
        cmd_count=$((cmd_count+1))

        SOURCE=$(cat $cmd | grep "^source" | awk '{print $2}')
        POD=""
        if [[ $HOST_POLICY -eq 0 ]]; then
            POD=$(kubectl get pods -n $2 | grep $SOURCE | awk '{print $1}')
        fi
        CMD=$(cat $cmd | grep "^cmd" | cut -d' ' -f2-)
        RESULT=$(cat $cmd | grep "^result" | awk '{print $2}')

        POLICY_NAME=$POLICY
        OP=$(cat $cmd | grep "^operation" | awk '{print $2}')
        COND=$(cat $cmd | grep "^condition" | cut -d' ' -f2-)
        ACTION=$(cat $cmd | grep "^action" | awk '{print $2}')

        if [[ $HOST_POLICY -eq 0 ]] && [[ "$RESULT" == "default" ]]; then
            if [ "$ACTION" == "default" ]; then # default posture
                if [ "$DEFAULT_POSTURE" == "block" ]; then
                    RESULT="failed"
                    POLICY_NAME="DefaultPosture"
                    ACTION="Block"
                elif [ "$DEFAULT_POSTURE" == "audit" ]; then
                    RESULT="passed"
                    POLICY_NAME="DefaultPosture"
                    ACTION="Audit"
                elif [ "$DEFAULT_POSTURE" == "allow" ]; then
                    RESULT="passed"
                    POLICY_NAME="DefaultPosture"
                    ACTION="Allow"
                fi
            elif [ "$ACTION" == "Block" ]; then # native policy
                RESULT="failed"
                POLICY_NAME="DefaultPosture"
            fi
        fi

        # if SELinux is enabled but a test policy is not for hosts
        if [[ "$LSM" == "selinux" ]] && [[ $HOST_POLICY -eq 0 ]]; then
            # replace Block with Audit
            if [ "$ACTION" == "Block" ]; then
                if [ "$RESULT" == "failed" ]; then
                    ACTION="Audit"
                    RESULT="passed"
                fi
            # replace Allow with "failed" to Audit with "passed"
            elif [ "$ACTION" == "Allow" ]; then
                if [ "$RESULT" == "failed" ]; then
                    ACTION="Audit"
                    RESULT="passed"
                fi
            fi
        fi

        # if AppArmor and SELinux are not enabled
        if [ "$LSM" == "none" ]; then
            # replace Block with Audit
            if [ "$ACTION" == "Block" ]; then
                if [ "$RESULT" == "failed" ]; then
                    ACTION="Audit"
                    RESULT="passed"
                fi
            # replace Allow with "failed" to Audit with "passed"
            elif [ "$ACTION" == "Allow" ]; then
                if [ "$RESULT" == "failed" ]; then
                    ACTION="Audit"
                    RESULT="passed"
                fi
            fi
        fi

        res_cmd=0
        audit_log=""
        actual_res="passed"

        DBG "Running \"$CMD\""
        if [[ $HOST_POLICY -eq 1 ]]; then
            bash -c ''"${CMD}"''
        else
            echo kubectl exec -n $2 $POD -- bash -c ''"${CMD}"''
            kubectl exec -n $2 $POD -- bash -c ''"${CMD}"''
        fi
        if [ $? != 0 ]; then
            actual_res="failed"
        fi

        if [[ $HOST_POLICY -eq 0 ]]; then
            if [ "$ACTION" == "Allow" ]; then
                if [ "$RESULT" == "passed" ]; then
                    DBG "$ACTION action, and the command should be passed"
                    should_not_find_any_log $POD $POLICY_NAME $OP $COND $ACTION $CMD
                else
                    DBG "$ACTION action, but the command should be failed"
                    should_find_blocked_log $POD $POLICY_NAME $OP $COND $ACTION
                fi
            elif [ "$ACTION" == "Audit" ]; then
                if [ "$RESULT" == "passed" ]; then
                    DBG "$ACTION action, and the command should be passed"
                    should_find_passed_log $POD $POLICY_NAME $OP $COND $ACTION
                else
                    DBG "$ACTION action, but the command should be failed"
                    should_find_blocked_log $POD $POLICY_NAME $OP $COND $ACTION
                fi
            elif [ "$ACTION" == "Block" ]; then
                if [ "$RESULT" == "passed" ]; then
                    DBG "$ACTION action, but the command should be passed"
                    should_not_find_any_log $POD $POLICY_NAME $OP $COND $ACTION $CMD
                else
                    DBG "$ACTION action, and the command should be failed"
                    should_find_blocked_log $POD $POLICY_NAME $OP $COND $ACTION
                fi
            fi
        else
            if [ "$ACTION" == "Allow" ]; then
                if [ "$RESULT" == "passed" ]; then
                    DBG "$ACTION action, and the command should be passed"
                    should_not_find_any_host_log $POLICY_NAME $OP $COND $ACTION $CMD
                else
                    DBG "$ACTION action, but the command should be failed"
                    should_find_blocked_host_log $POLICY_NAME $OP $COND $ACTION
                fi
            elif [ "$ACTION" == "Audit" ]; then
                if [ "$RESULT" == "passed" ]; then
                    DBG "$ACTION action, and the command should be passed"
                    should_find_passed_host_log $POLICY_NAME $OP $COND $ACTION
                else
                    DBG "$ACTION action, but the command should be failed"
                    should_find_blocked_host_log $POLICY_NAME $OP $COND $ACTION
                fi
            elif [ "$ACTION" == "Block" ]; then
                if [ "$RESULT" == "passed" ]; then
                    DBG "$ACTION action, but the command should be passed"
                    should_not_find_any_host_log $POLICY_NAME $OP $COND $ACTION $CMD
                else
                    DBG "$ACTION action, and the command should be failed"
                    should_find_blocked_host_log $POLICY_NAME $OP $COND $ACTION
                fi
            fi
        fi

        if [ $res_cmd == 0 ]; then
            echo "Testcase: $3 (command #$cmd_count)" >> $TEST_LOG
            echo "Policy: $YAML_FILE" >> $TEST_LOG
            echo "Action: $ACTION" >> $TEST_LOG
            echo "Pod: $SOURCE" >> $TEST_LOG
            echo "Command: $CMD" >> $TEST_LOG
            echo "Result: $RESULT (expected) / $actual_res (actual)" >> $TEST_LOG
            echo "Log:" >> $TEST_LOG
            echo $audit_log >> $TEST_LOG
            echo >> $TEST_LOG
        else
            echo "Testcase: $3 (command #$cmd_count)" >> $TEST_LOG
            echo "Policy: $YAML_FILE" >> $TEST_LOG
            echo "Action: $ACTION" >> $TEST_LOG
            echo "Pod: $SOURCE" >> $TEST_LOG
            echo "Command: $CMD" >> $TEST_LOG
            echo "Result: $RESULT (expected) / $actual_res (actual)" >> $TEST_LOG
            echo "Output:" >> $TEST_LOG
            if [[ $HOST_POLICY -eq 0 ]]; then 
                echo ""$(kubectl exec -n $2 $POD -- bash -c "$CMD") >> $TEST_LOG
            else
                echo ""$(bash -c "$CMD") >> $TEST_LOG
            fi
            echo "Log:" >> $TEST_LOG
            echo $audit_log >> $TEST_LOG
            echo >> $TEST_LOG
            res_case=1
        fi

        sleep 1
    done

    if [ $res_case != 0 ]; then
        FAIL "Failed $3"
        failed_testcases+=("$3")
    else
        PASS "Passed $3"
        passed_testcases+=("$3")
    fi

    DBG "Deleting $YAML_FILE from $2"
    if [[ $HOST_POLICY -eq 1 ]]; then
        kubectl delete -f $YAML_FILE
    else
        kubectl delete -n $2 -f $YAML_FILE
    fi 
    if [ $? != 0 ]; then
        FAIL "Failed to delete $YAML_FILE from $2"
        res_case=1
        return
    fi
    DBG "Deleted $YAML_FILE from $2"

    sleep 1
}

## == KubeArmor == ##

sudo rm -f $ARMOR_MSG $ARMOR_LOG $TEST_LOG

total_testcases=$(expr $(ls -l $TEST_HOME/scenarios | grep ^d | wc -l) + $(ls -ld $TEST_HOME/host_scenarios/$(hostname)_* 2> /dev/null | grep ^d | wc -l))

passed_testcases=()
failed_testcases=()
skipped_testcases=()
retried_testcases=()

echo "< KubeArmor Test Report >" > $TEST_LOG
echo >> $TEST_LOG
echo "Date:" $(date "+%Y-%m-%d %H:%M:%S %Z") >> $TEST_LOG
echo "Script: $0" >> $TEST_LOG
echo >> $TEST_LOG
echo "== Testcases ==" >> $TEST_LOG
echo >> $TEST_LOG

INFO "Starting KubeArmor"
start_and_wait_for_kubearmor_initialization
INFO "Started KubeArmor"

## == Test Scenarios == ##

res_microservice=0

is_test_ignored()
{
    IGN_FILE=$TEST_HOME/tests.ignore

    # skip tests that don't work with some runtimes
    if [ "$RUNTIME" == "crio" ]; then
        # skip tests for net_raw capability (see #697)
        echo "github_test_09" | tee -a $IGN_FILE
        echo "github_test_13" | tee -a $IGN_FILE
    fi

    [[ ! -f $IGN_FILE ]] && return 0
    for line in `grep "^[a-zA-Z].*" $IGN_FILE`; do
        echo $testcase | grep $line >/dev/null
        [[ $? -eq 0 ]] && echo "matched ignore pattern [$line]" && return 1
    done
    return 0
}

is_test_allowed()
{
    cnt=0
    ALLOW_FILE=$TEST_HOME/tests.allow
    [[ ! -f $ALLOW_FILE ]] && return 1
    for line in `grep "^[a-zA-Z].*" $ALLOW_FILE`; do
        echo $testcase | grep $line >/dev/null
        [[ $? -eq 0 ]] && echo "does not match ignore pattern [$line]" && return 1
        ((cnt++))
    done
    [[ $cnt -gt 0 ]] && echo "Testcase does not match any allowed pattern in [$ALLOW_FILE]" && return 0
    return 1
}

if [[ $SKIP_CONTAINER_POLICY -eq 0 || $SKIP_NATIVE_POLICY -eq 0 ]]; then
    INFO "Running Container Scenarios"

    microservice="github"

    ## == ##

    INFO "Applying $microservice"
    apply_and_wait_for_microservice_creation $microservice

    ## == ##

    DBG "Applied $microservice"

    DBG "Wait for initialization (20s)"
    sleep 20
    DBG "Started to run testcases"

    cd $TEST_HOME/scenarios

    for testcase in $(find -maxdepth 1 -mindepth 1 -type d  -name "${microservice}_*")
    do
        is_test_ignored
        [[ $? -eq 1 ]] && WARN "Testcase $testcase ignored" && continue

        is_test_allowed
        [[ $? -eq 0 ]] && WARN "Testcase $testcase disallowed" && continue

        res_case=0

        INFO "Testing $testcase"
        run_test_scenario $TEST_HOME/scenarios/$testcase $microservice $testcase

        if [ $res_case != 0 ]; then
            res_case=0

            INFO "Re-testing $testcase"
            total_testcases=$(expr $total_testcases + 1)
            retried_testcases+=("$testcase")
            run_test_scenario $TEST_HOME/scenarios/$testcase $microservice $testcase

            if [ $res_case != 0 ]; then
                FAIL "Failed to test $testcase"
                res_microservice=1
            else
                PASS "Successfully tested $testcase"
            fi
        else
            PASS "Successfully tested $testcase"
        fi
    done

    res_delete=0

    INFO "Deleting $microservice"
    delete_and_wait_for_microservice_deletion $microservice

    if [ $res_delete == 0 ]; then
        DBG "Deleted $microservice"
    fi

    DBG "Finished Container Scenarios"
fi

HOST_NAME=$(hostname)
res_host=0

if [[ $SKIP_HOST_POLICY -eq 0 ]]; then
    INFO "Running Host Scenarios"

    cd $TEST_HOME/host_scenarios

    host_testcases=$(ls -d "$HOST_NAME"_*)
    if [ $? -eq 0 ]; then
        for testcase in $host_testcases
        do
            res_case=0

            INFO "Testing $testcase"
            run_test_scenario $TEST_HOME/host_scenarios/$testcase $HOST_NAME $testcase

            if [ $res_case != 0 ]; then
                res_case=0

                INFO "Re-testing $testcase"
                total_testcases=$(expr $total_testcases + 1)
                retried_testcases+=("$testcase")
                run_test_scenario $TEST_HOME/host_scenarios/$testcase $HOST_NAME $testcase

                if [ $res_case != 0 ]; then
                    FAIL "Failed to test $testcase"
                    res_host=1
                else
                    PASS "Successfully tested $testcase"
                fi
            else
                PASS "Successfully tested $testcase"
            fi
        done
        DBG "Finished Host Scenarios"
    else
        WARN "No testcases found for the current host, $HOST_NAME"
    fi
else
    WARN "Skipped Host Scenarios"
fi

echo "== Summary ==" >> $TEST_LOG
echo >> $TEST_LOG
echo "Passed testcases: ${#passed_testcases[@]}/$total_testcases" >> $TEST_LOG
if [ "${#passed_testcases[@]}" != "0" ]; then
    echo >> $TEST_LOG
    for (( i=0; i<${#passed_testcases[@]}; i++ ));
    do
        echo "${passed_testcases[$i]}" >> $TEST_LOG;
    done
fi
echo >> $TEST_LOG
echo "Failed testcases: ${#failed_testcases[@]}/$total_testcases" >> $TEST_LOG
if [ "${#failed_testcases[@]}" != "0" ]; then
    echo >> $TEST_LOG
    for (( i=0; i<${#failed_testcases[@]}; i++ ));
    do
        echo "${failed_testcases[$i]}" >> $TEST_LOG;
    done
fi
echo >> $TEST_LOG
echo "Skipped testcases: ${#skipped_testcases[@]}/$total_testcases" >> $TEST_LOG
if [ "${#skipped_testcases[@]}" != "0" ]; then
    echo >> $TEST_LOG
    for (( i=0; i<${#skipped_testcases[@]}; i++ ));
    do
        echo "${skipped_testcases[$i]}" >> $TEST_LOG;
    done
fi
echo >> $TEST_LOG
echo "Retried testcases: ${#retried_testcases[@]}/$total_testcases" >> $TEST_LOG
if [ "${#retried_testcases[@]}" != "0" ]; then
    echo >> $TEST_LOG
    for (( i=0; i<${#retried_testcases[@]}; i++ ));
    do
        echo "${retried_testcases[$i]}" >> $TEST_LOG;
    done
fi
echo >> $TEST_LOG

## == KubeArmor == ##

INFO "Stopping KubeArmor"
stop_and_wait_for_kubearmor_termination
DBG "Stopped KubeArmor"

if [[ $res_microservice -eq 1 ]] || [[ $res_host -eq 1 ]]; then
    FAIL "Failed to test KubeArmor"
else
    PASS "Successfully tested KubeArmor"
fi

if [[ $res_microservice -ne 0 ]] || [[ $res_host -ne 0 ]]; then
    exit 1
fi

exit 0
