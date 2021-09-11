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

ARMOR_LOG=/tmp/kubearmor.log
TEST_LOG=/tmp/kubearmor.test

RED='\033[0;31m'
GREEN='\033[0;32m'
ORANGE='\033[0;33m'
BLUE='\033[0;34m'
MAGENTA='\033[0;35m'
NC='\033[0m'

## == Functions == ##

function apply_and_wait_for_microservice_creation() {
    cd $TEST_HOME/microservices/$1

    kubectl apply -f .
    if [ $? != 0 ]; then
        echo -e "${RED}[FAIL] Failed to apply $1${NC}"
        res_microservice=1
        return
    fi

    sleep 1

    for (( ; ; ))
    do
        RAW=$(kubectl get pods -n $1 | wc -l)

        ALL=`expr $RAW - 1`
        READY=`kubectl get pods -n $1 | grep Running | wc -l`

        if [ $ALL == $READY ]; then
            break
        fi

        sleep 1
    done

    sleep 1
}

function delete_and_wait_for_microservice_deletion() {
    cd $TEST_HOME/microservices/$1

    kubectl delete -f .
    if [ $? != 0 ]; then
        echo -e "${RED}[FAIL] Failed to delete $1${NC}"
        res_delete=1
    fi
}

function should_not_find_any_log() {
    NODE=$(kubectl get pods -A -o wide | grep $1 | awk '{print $8}')
    KUBEARMOR=$(kubectl get pods -n kube-system -l kubearmor-app=kubearmor -o wide | grep $NODE | grep kubearmor | awk '{print $1}')

    sleep 3

    echo -e "${GREEN}[INFO] Finding the corresponding log${NC}"

    if [[ $KUBEARMOR = "kubearmor"* ]]; then
        audit_log=$(kubectl -n kube-system exec -it $KUBEARMOR -- tail -n 20 $ARMOR_LOG | grep -E "$1.*MatchedPolicy.*$2.*$3.*$4" | grep -v Passed)
        if [ $? == 0 ]; then
            echo $audit_log
            echo -e "${RED}[FAIL] Found the log from logs${NC}"
            res_cmd=1
        else
            audit_log="<No Log>"
            echo "[INFO] Found no log from logs"
        fi
    else # local
        audit_log=$(tail -n 20 $ARMOR_LOG | grep -E "$1.*MatchedPolicy.*$2.*$3.*$4" | grep -v Passed)
        if [ $? == 0 ]; then
            echo $audit_log
            echo -e "${RED}[FAIL] Found the log from logs${NC}"
            res_cmd=1
        else
            audit_log="<No Log>"
            echo "[INFO] Found no log from logs"
        fi
    fi
}

function should_find_passed_log() {
    NODE=$(kubectl get pods -A -o wide | grep $1 | awk '{print $8}')
    KUBEARMOR=$(kubectl get pods -n kube-system -l kubearmor-app=kubearmor -o wide | grep $NODE | grep kubearmor | awk '{print $1}')

    sleep 3

    echo -e "${GREEN}[INFO] Finding the corresponding log${NC}"

    if [[ $KUBEARMOR = "kubearmor"* ]]; then
        audit_log=$(kubectl -n kube-system exec -it $KUBEARMOR -- tail -n 20 $ARMOR_LOG | grep -E "$1.*MatchedPolicy.*$2.*$3.*$4" | grep Passed)
        if [ $? != 0 ]; then
            audit_log="<No Log>"
            echo -e "${RED}[FAIL] Failed to find the log from logs${NC}"
            res_cmd=1
        else
            echo $audit_log
            echo "[INFO] Found the log from logs"
        fi
    else # local
        audit_log=$(tail -n 20 $ARMOR_LOG | grep -E "$1.*MatchedPolicy.*$2.*$3.*$4" | grep Passed)
        if [ $? != 0 ]; then
            audit_log="<No Log>"
            echo -e "${RED}[FAIL] Failed to find the log from logs${NC}"
            res_cmd=1
        else
            echo $audit_log
            echo "[INFO] Found the log from logs"
        fi
    fi
}

function should_find_blocked_log() {
    NODE=$(kubectl get pods -A -o wide | grep $1 | awk '{print $8}')
    KUBEARMOR=$(kubectl get pods -n kube-system -l kubearmor-app=kubearmor -o wide | grep $NODE | grep kubearmor | awk '{print $1}')

    sleep 3

    echo -e "${GREEN}[INFO] Finding the corresponding log${NC}"

    if [[ $KUBEARMOR = "kubearmor"* ]]; then
        audit_log=$(kubectl -n kube-system exec -it $KUBEARMOR -- tail -n 20 $ARMOR_LOG | grep -E "$1.*MatchedPolicy.*$2.*$3.*$4" | grep -v Passed)
        if [ $? != 0 ]; then
            audit_log="<No Log>"
            echo -e "${RED}[FAIL] Failed to find the log from logs${NC}"
            res_cmd=1
        else
            echo $audit_log
            echo "[INFO] Found the log from logs"
        fi
    else # local
        audit_log=$(tail -n 20 $ARMOR_LOG | grep -E "$1.*MatchedPolicy.*$2.*$3.*$4" | grep -v Passed)
        if [ $? != 0 ]; then
            audit_log="<No Log>"
            echo -e "${RED}[FAIL] Failed to find the log from logs${NC}"
            res_cmd=1
        else
            echo $audit_log
            echo "[INFO] Found the log from logs"
        fi
    fi
}

function run_test_scenario() {
    cd $1

    YAML_FILE=$(ls *.yaml)
    policy_type=$(echo $YAML_FILE | awk '{split($0,a,"-"); print a[1]}')

    echo -e "${GREEN}[INFO] Applying $YAML_FILE into $2${NC}"
    kubectl apply -n $2 -f $YAML_FILE
    if [ $? != 0 ]; then
        echo -e "${RED}[FAIL] Failed to apply $YAML_FILE into $2${NC}"
        res_case=1
        return
    fi
    echo "[INFO] Applied $YAML_FILE into $2"

    sleep 3
    cmd_count=0

    for cmd in $(ls cmd*)
    do
        cmd_count=$((cmd_count+1))

        SOURCE=$(cat $cmd | grep "^source" | awk '{print $2}')
        POD=$(kubectl get pods -n $2 | grep $SOURCE | awk '{print $1}')
        CMD=$(cat $cmd | grep "^cmd" | cut -d' ' -f2-)
        RESULT=$(cat $cmd | grep "^result" | awk '{print $2}')

        OP=$(cat $cmd | grep "^operation" | awk '{print $2}')
        COND=$(cat $cmd | grep "^condition" | cut -d' ' -f2-)
        ACTION=$(cat $cmd | grep "^action" | awk '{print $2}')

        res_cmd=0
        audit_log=""
        actual_res="passed"

        echo -e "${GREEN}[INFO] Running \"$CMD\"${NC}"
        kubectl exec -n $2 -it $POD -- bash -c ''"${CMD}"''
        if [ $? != 0 ]; then
            actual_res="failed"
        fi

        if [ "$ACTION" == "Allow" ]; then
            if [ "$RESULT" == "passed" ]; then
                echo "[INFO] $ACTION action, and the command should be passed"
                should_not_find_any_log $POD $OP $COND $ACTION
            else
                echo "[INFO] $ACTION action, but the command should be failed"
                should_find_blocked_log $POD $OP $COND $ACTION
            fi
        elif [ "$ACTION" == "Audit" ]; then
            if [ "$RESULT" == "passed" ]; then
                echo "[INFO] $ACTION action, and the command should be passed"
                should_find_passed_log $POD $OP $COND $ACTION
            else
                echo "[INFO] $ACTION action, but the command should be failed"
                should_find_blocked_log $POD $OP $COND $ACTION
            fi
        elif [ "$ACTION" == "Block" ]; then
            if [ "$RESULT" == "passed" ]; then
                echo "[INFO] $ACTION action, but the command should be passed"
                should_not_find_any_log $POD $OP $COND $ACTION
            else
                echo "[INFO] $ACTION action, and the command should be failed"
                should_find_blocked_log $POD $OP $COND $ACTION
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
            echo ""$(kubectl exec -n $2 -it $POD -- bash -c \""$CMD\"") >> $TEST_LOG
            echo "Log:" >> $TEST_LOG
            echo $audit_log >> $TEST_LOG
            echo >> $TEST_LOG
            res_case=1
        fi

        sleep 1
    done

    if [ $res_case != 0 ]; then
        echo -e "${RED}[FAIL] Failed $3${NC}"
        failed_testcases+=("$3")
    else
        echo -e "${BLUE}[PASS] Passed $3${NC}"
        passed_testcases+=("$3")
    fi

    echo -e "${GREEN}[INFO] Deleting $YAML_FILE from $2${NC}"
    kubectl delete -n $2 -f $YAML_FILE
    if [ $? != 0 ]; then
        echo -e "${RED}[FAIL] Failed to delete $YAML_FILE from $2${NC}"
        res_case=1
        return
    fi
    echo "[INFO] Deleted $YAML_FILE from $2"

    sleep 1
}

## == KubeArmor == ##

total_testcases=$(ls -l $TEST_HOME/scenarios | grep ^d | wc -l)

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

## == Test Scenarios == ##

res_microservice=0

echo -e "${ORANGE}[INFO] Running Container Scenarios${NC}"
for microservice in $(ls $TEST_HOME/microservices)
do
    ## == ##

    echo -e "${ORANGE}[INFO] Applying $microservice${NC}"
    apply_and_wait_for_microservice_creation $microservice

    ## == ##

    if [ $res_microservice == 0 ]; then
        echo "[INFO] Applied $microservice"

        echo "[INFO] Wait for initialization (30 secs)"
        sleep 30
        echo "[INFO] Started to run testcases"

        cd $TEST_HOME/scenarios

        for testcase in $(ls -d "$microservice"_*)
        do
            res_case=0

            echo -e "${ORANGE}[INFO] Testing $testcase${NC}"
            run_test_scenario $TEST_HOME/scenarios/$testcase $microservice $testcase

            if [ $res_case != 0 ]; then
                res_case=0

                echo -e "${ORANGE}[INFO] Re-testing $testcase${NC}"
                total_testcases=$(expr $total_testcases + 1)
                retried_testcases+=("$testcase")
                run_test_scenario $TEST_HOME/scenarios/$testcase $microservice $testcase

                if [ $res_case != 0 ]; then
                    echo -e "${RED}[FAIL] Failed to test $testcase${NC}"
                    res_microservice=1
                else
                    echo -e "${BLUE}[PASS] Successfully tested $testcase${NC}"
                fi
            else
                echo -e "${BLUE}[PASS] Successfully tested $testcase${NC}"
            fi
        done

        res_delete=0

        echo -e "${ORANGE}[INFO] Deleting $microservice${NC}"
        delete_and_wait_for_microservice_deletion $microservice

        if [ $res_delete == 0 ]; then
            echo "[INFO] Deleted $microservice"
        fi
    fi
done    
echo "[INFO] Finished Container Scenarios"

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

if [[ $res_microservice -eq 1 ]]; then
    echo -e "${RED}[FAIL] Failed to test KubeArmor${NC}"
    exit 1
else
    echo -e "${BLUE}[PASS] Successfully tested KubeArmor${NC}"
    exit 0
fi
