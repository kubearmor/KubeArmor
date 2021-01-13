#!/bin/bash

TEST_HOME=`dirname $(realpath "$0")`
CRD_HOME=`dirname $(realpath "$0")`/../deployments/CRD
ARMOR_HOME=`dirname $(realpath "$0")`/../deployments/test-microk8s

AUDIT_LOG="/KubeArmor/audit.log"
SYSTEM_LOG="/KubeArmor/system.log"

RED='\033[0;31m'
GREEN='\033[0;32m'
ORANGE='\033[0;33m'
BLUE='\033[0;34m'
NC='\033[0m'

## == Functions == ##

function start_and_wait_for_kubearmor_initialization() {
    cd $CRD_HOME

    kubectl apply -f .
    if [ $? != 0 ]; then
        echo -e "${RED}[FAIL] Failed to apply $1${NC}"
        exit 1
    fi

    if [ ! -f /sbin/auditd ]; then
        sudo apt-get install -y auditd
        sudo service auditd start
    fi

    cd $ARMOR_HOME

    kubectl apply -f .
    if [ $? != 0 ]; then
        echo -e "${RED}[FAIL] Failed to apply $1${NC}"
        exit 1
    fi

    for (( ; ; ))
    do
        RAW=$(kubectl get pods -n kube-system | wc -l)

        ALL=`expr $RAW - 1`
        READY=`kubectl get pods -n kube-system | grep Running | wc -l`

        if [ $ALL == $READY ]; then
            break
        fi

        sleep 1
    done

    KUBEARMOR=$(kubectl get pods -n kube-system | grep kubearmor | grep -v kubearmor-logserver | awk '{print $1}')

    for (( ; ; ))
    do
        kubectl -n kube-system logs $KUBEARMOR | grep "Initialized KubeArmor" &> /dev/null
        if [ $? == 0 ]; then
            break
        fi

        sleep 1
    done

    sleep 1
}

function stop_and_wait_for_kubearmor_termination() {
    cd $ARMOR_HOME

    kubectl delete -f .
    if [ $? != 0 ]; then
        echo -e "${RED}[FAIL] Failed to delete $1${NC}"
        exit 1
    fi

    for (( ; ; ))
    do
        kubectl get pods -n kube-system | grep kubearmor &> /dev/null
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
        echo -e "${RED}[FAIL] Failed to apply $1${NC}"
        exit 1
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
        exit 1
    fi
}

function find_no_logs() {
    KUBEARMOR=$(kubectl get pods -n kube-system | grep kubearmor | grep -v kubearmor-logserver | awk '{print $1}')

    sleep 1

    echo -e "${GREEN}[INFO] Finding the corresponding log${NC}"

    kubectl -n kube-system exec -it $KUBEARMOR -- bash -c "tail -n 10 $AUDIT_LOG" | grep $1 | grep $2
    if [ $? != 0 ]; then
        kubectl -n kube-system exec -it $KUBEARMOR -- bash -c "tail -n 10 $SYSTEM_LOG" | grep $1 | grep $2 | grep 'Operation not permitted\|Permission denied'
        if [ $? != 0 ]; then
            echo "[INFO] Found no log from both audit logs and system logs"
        else
            echo -e "${RED}[FAIL] Found the log from system logs${NC}"
        fi
    else
        echo -e "${RED}[FAIL] Found the log from audit logs${NC}"
    fi
}

function find_logs() {
    KUBEARMOR=$(kubectl get pods -n kube-system | grep kubearmor | grep -v kubearmor-logserver | awk '{print $1}')

    sleep 1

    echo -e "${GREEN}[INFO] Finding the corresponding log${NC}"

    kubectl -n kube-system exec -it $KUBEARMOR -- bash -c "tail -n 10 $AUDIT_LOG" | grep $1 | grep $2
    if [ $? != 0 ]; then
        kubectl -n kube-system exec -it $KUBEARMOR -- bash -c "tail -n 10 $SYSTEM_LOG" | grep $1 | grep $2 | grep 'Operation not permitted\|Permission denied'
        if [ $? != 0 ]; then
            echo -e "${RED}[FAIL] Failed to find the log from both audit logs and system logs${NC}"
        else
            echo "[INFO] Found the log from system logs"
        fi
    else
        echo "[INFO] Found the log from audit logs"
    fi
}

function run_test_scenario() {
    cd $1

    YAML_FILE=$(ls *.yaml)

    echo -e "${GREEN}[INFO] Applying $YAML_FILE into $2${NC}"
    kubectl apply -n $2 -f $YAML_FILE
    echo "[INFO] Applied $YAML_FILE into $2"

    sleep 1

    for cmd in $(ls cmd*)
    do
        SOURCE=$(cat $cmd | grep source | awk '{print $2}')
        POD=$(kubectl get pods -n $2 | grep $SOURCE | awk '{print $1}')

        CMD=$(cat $cmd | grep cmd | cut -d' ' -f2-)
        COND=$(cat $cmd | grep cmd | awk '{print $2}')
        RESULT=$(cat $cmd | grep result | awk '{print $2}')

        FINAL=1

        echo -e "${GREEN}[INFO] Running \"$CMD\"${NC}"
        kubectl exec -n $2 -it $POD -- bash -c "$CMD"
        if [ $? == 0 ]; then
            if [ "$RESULT" == "passed" ]; then
                find_no_logs $POD $COND
            elif [ "$RESULT" == "audited" ]; then
                find_logs $POD $COND
            else
                FINAL=0
            fi
        else
            if [ "$RESULT" == "failed" ]; then
                find_logs $POD $COND
            else
                FINAL=0
            fi
        fi

        sleep 1
    done

    if [ $FINAL == 1 ]; then
        echo -e "${BLUE}[PASS] Passed $3${NC}"
    else
        echo -e "${RED}[FAIL] Failed $3${NC}"
    fi

    echo -e "${GREEN}[INFO] Deleting $YAML_FILE from $2${NC}"
    kubectl delete -n $2 -f $YAML_FILE
    echo "[INFO] Deleted $YAML_FILE from $2"

    sleep 1
}

## == KubeArmor == ##

echo -e "${ORANGE}[INFO] Starting KubeArmor${NC}"
start_and_wait_for_kubearmor_initialization
echo "[INFO] Started KubeArmor"

## == Test Scenarios == ##

cd $TEST_HOME

for microservice in $(ls microservices)
do
    ## == ##

    echo -e "${ORANGE}[INFO] Applying $microservice${NC}"
    apply_and_wait_for_microservice_creation $microservice
    echo "[INFO] Applied $microservice"

    ## == ##

    cd $TEST_HOME/scenarios

    for testcase in $(ls -d $microservice_*)
    do
        echo -e "${ORANGE}[INFO] Testing $testcase${NC}"
        run_test_scenario $TEST_HOME/scenarios/$testcase $microservice $testcase
        echo "[INFO] Tested $testcase"
    done

    ## == ##

    echo -e "${ORANGE}[INFO] Deleting $microservice${NC}"
    delete_and_wait_for_microserivce_deletion $microservice
    echo "[INFO] Deleted $microservice"

    ## == ##
done

## == KubeArmor == ##

echo -e "${ORANGE}[INFO] Stopping KubeArmor${NC}"
stop_and_wait_for_kubearmor_termination
echo "[INFO] Stopped KubeArmor"
