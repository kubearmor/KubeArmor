#!/bin/bash

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

ARMOR_LOG="/tmp/kubearmor.log"

RED='\033[0;31m'
GREEN='\033[0;32m'
ORANGE='\033[0;33m'
BLUE='\033[0;34m'
MAGENTA='\033[0;35m'
NC='\033[0m'

## == Functions == ##

function wait_for_kubearmor_initialization() {
    cd $CRD_HOME

    kubectl apply -f .
    if [ $? != 0 ]; then
        echo -e "${RED}[FAIL] Failed to apply $1${NC}"
        exit 1
    fi

    KUBEARMOR=$(kubectl get pods -n kube-system | grep kubearmor | grep -v cos | awk '{print $1}')

    for ARMOR in $KUBEARMOR
    do
        for (( ; ; ))
        do
            kubectl -n kube-system logs $ARMOR | grep "Initialized KubeArmor" &> /dev/null
            if [ $? == 0 ]; then
                break
            fi

            sleep 1
        done
    done

    sleep 1
}

function apply_and_wait_for_microservice_creation() {
    cd $TEST_HOME/microservices/$1

    kubectl apply -f .
    if [ $? != 0 ]; then
        echo -e "${RED}[FAIL] Failed to apply $1${NC}"
        res_microservice=1
        return
    fi

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

function delete_and_wait_for_microserivce_deletion() {
    cd $TEST_HOME/microservices/$1

    kubectl delete -f .
    if [ $? != 0 ]; then
        echo -e "${RED}[FAIL] Failed to delete $1${NC}"
        res_delete=1
    fi
}

function find_allow_logs() {
    NODE=$(kubectl get pods -A -o wide | grep $1 | awk '{print $8}')
    KUBEARMOR=$(kubectl get pods -n kube-system -o wide | grep $NODE | grep kubearmor | grep -v cos | awk '{print $1}')

    sleep 1

    echo -e "${GREEN}[INFO] Finding the corresponding log${NC}"

    kubectl -n kube-system exec -it $KUBEARMOR -- bash -c "grep PolicyMatched $ARMOR_LOG | tail -n 10 | grep $1 | grep $2 | grep $3 | grep $4 | grep Passed"
    if [ $? == 0 ]; then
        echo -e "${RED}[FAIL] Found the log from logs${NC}"
        res_cmd=1
    else
        echo "[INFO] Found no log from logs"
    fi
}

function find_audit_logs() {
    NODE=$(kubectl get pods -A -o wide | grep $1 | awk '{print $8}')
    KUBEARMOR=$(kubectl get pods -n kube-system -o wide | grep $NODE | grep kubearmor | grep -v cos | awk '{print $1}')

    sleep 1

    echo -e "${GREEN}[INFO] Finding the corresponding log${NC}"

    if [ "$KUBEARMOR" != "" ]; then
        kubectl -n kube-system exec -it $KUBEARMOR -- bash -c "grep PolicyMatched $ARMOR_LOG | tail -n 10 | grep $1 | grep $2 | grep $3 | grep $4 | grep Passed"
        if [ $? != 0 ]; then
            echo -e "${RED}[FAIL] Failed to find the log from logs${NC}"
            res_cmd=1
        else
            echo "[INFO] Found the log from logs"
        fi
    else
        grep PolicyMatched $ARMOR_LOG | tail -n 10 | grep $1 | grep $2 | grep $3 | grep $4 | grep Passed
        if [ $? != 0 ]; then
            echo -e "${RED}[FAIL] Failed to find the log from logs${NC}"
            res_cmd=1
        else
            echo "[INFO] Found the log from logs"
        fi
    fi
}

function find_block_logs() {
    NODE=$(kubectl get pods -A -o wide | grep $1 | awk '{print $8}')
    KUBEARMOR=$(kubectl get pods -n kube-system -o wide | grep $NODE | grep kubearmor | grep -v cos | awk '{print $1}')

    sleep 1

    echo -e "${GREEN}[INFO] Finding the corresponding log${NC}"

    if [ "$KUBEARMOR" != "" ]; then
        kubectl -n kube-system exec -it $KUBEARMOR -- bash -c "grep PolicyMatched $ARMOR_LOG | tail -n 10 | grep $1 | grep $2 | grep $3 | grep $4 | grep -v Passed"
        if [ $? != 0 ]; then
            echo -e "${RED}[FAIL] Failed to find the log from logs${NC}"
            res_cmd=1
        else
            echo "[INFO] Found the log from logs"
        fi
    else
        grep PolicyMatched $ARMOR_LOG | tail -n 10 | grep $1 | grep $2 | grep $3 | grep $4 | grep -v Passed
        if [ $? != 0 ]; then
            echo -e "${RED}[FAIL] Failed to find the log from logs${NC}"
            res_cmd=1
        else
            echo "[INFO] Found the log from logs"
        fi
    fi
}

function run_test_scenario() {
    cd $1

    YAML_FILE=$(ls *.yaml)

    echo -e "${GREEN}[INFO] Applying $YAML_FILE into $2${NC}"
    kubectl apply -n $2 -f $YAML_FILE
    if [ $? != 0 ]; then
        echo -e "${RED}[FAIL] Failed to apply $YAML_FILE into $2${NC}"
        res_case=1
        return
    fi
    echo "[INFO] Applied $YAML_FILE into $2"

    sleep 2

    for cmd in $(ls cmd*)
    do
        SOURCE=$(cat $cmd | grep source | awk '{print $2}')
        POD=$(kubectl get pods -n $2 | grep $SOURCE | awk '{print $1}')

        CMD=$(cat $cmd | grep cmd | cut -d' ' -f2-)
        RESULT=$(cat $cmd | grep result | awk '{print $2}')

        OP=$(cat $cmd | grep operation | awk '{print $2}')
        COND=$(cat $cmd | grep condition | cut -d' ' -f2-)
        ACTION=$(cat $cmd | grep action | awk '{print $2}')

        res_cmd=0

        echo -e "${GREEN}[INFO] Running \"$CMD\"${NC}"
        kubectl exec -n $2 -it $POD -- bash -c "$CMD"
        if [ $? == 0 ]; then
            if [ "$ACTION" == "Allow" ] && [ "$RESULT" == "passed" ]; then
                find_allow_logs $POD $OP $COND $ACTION
            elif [ "$ACTION" == "AllowWithAudit" ] && [ "$RESULT" == "passed" ]; then
                find_audit_logs $POD $OP $COND $ACTION
            elif [ "$ACTION" == "Audit" ] && [ "$RESULT" == "audited" ]; then
                find_audit_logs $POD $OP $COND $ACTION
            elif [ "$RESULT" == "failed" ]; then
                echo -e "${MAGENTA}[WARN] Expected failure, but got success${NC}"
            fi
        else
            if [ "$RESULT" == "failed" ]; then
                find_block_logs $POD $OP $COND $ACTION
            else
                echo -e "${MAGENTA}[WARN] Expected success, but got failure${NC}"
            fi
        fi

        if [ $res_cmd != 0 ]; then
            break
        fi

        sleep 1
    done

    if [ $res_cmd != 0 ]; then
        echo -e "${RED}[FAIL] Failed $3${NC}"
        res_case=1
    else
        echo -e "${BLUE}[PASS] Passed $3${NC}"
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

echo -e "${ORANGE}[INFO] Checking KubeArmor${NC}"
wait_for_kubearmor_initialization
echo "[INFO] Checked KubeArmor"

## == Test Scenarios == ##

cd $TEST_HOME

res_microservice=0

for microservice in $(ls microservices)
do
    ## == ##

    echo -e "${ORANGE}[INFO] Applying $microservice${NC}"
    apply_and_wait_for_microservice_creation $microservice

    ## == ##

    if [ $res_microservice == 0 ]; then
        echo "[INFO] Applied $microservice"

        echo "[INFO] Wait for initialization"
        sleep 30
        echo "[INFO] Started to run testcases"

        cd $TEST_HOME/scenarios

        for testcase in $(ls -d $microservice_*)
        do
            res_case=0

            echo -e "${ORANGE}[INFO] Testing $testcase${NC}"
            run_test_scenario $TEST_HOME/scenarios/$testcase $microservice $testcase

            if [ $res_case != 0 ]; then
                res_microservice=1
                break
            fi

            echo "[INFO] Tested $testcase"
        done

        res_delete=0

        echo -e "${ORANGE}[INFO] Deleting $microservice${NC}"
        delete_and_wait_for_microserivce_deletion $microservice

        if [ $res_delete == 0 ]; then
            echo "[INFO] Deleted $microservice"
        fi
    fi

    ## == ##

    if [ $res_microservice != 0 ]; then
        break
    fi

    ## == ##
done

## == KubeArmor == ##

if [ $res_microservice != 0 ]; then
    echo -e "${RED}[FAIL] Failed to test KubeArmor${NC}"
    exit 1
else
    echo -e "${BLUE}[PASS] Successfully tested KubeArmor${NC}"
    exit 0
fi
