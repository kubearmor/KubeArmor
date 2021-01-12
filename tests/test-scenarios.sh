#!/bin/bash

TEST_HOME=`dirname $(realpath "$0")`
ARMOR_HOME=`dirname $(realpath "$0")`/../KubeArmor

ARMOR_LOG=$TEST_HOME/kubearmor.log
AUDIT_LOG=$TEST_HOME/audit.log
SYSTEM_LOG=$TEST_HOME/system.log

RED='\033[0;31m'
GREEN='\033[0;32m'
ORANGE='\033[0;33m'
BLUE='\033[0;34m'
NC='\033[0m'

## == Functions == ##

function start_and_wait_for_kubearmor_initialization() {
    cd $ARMOR_HOME

    sudo -E ./kubearmor -audit=file:$AUDIT_LOG -system=file:$SYSTEM_LOG > $ARMOR_LOG &

    for (( ; ; ))
    do
        grep "Initialized KubeArmor" $TEST_HOME/kubearmor.log &> /dev/null
        if [ $? == 0 ]; then
            break
        fi

        sleep 1
    done
}

function stop_and_wait_for_kubearmor_termination() {
    ps -e | grep kubearmor | awk '{print $1}' | xargs -I {} sudo kill {}

    for (( ; ; ))
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
}

function delete_and_wait_for_microserivce_deletion() {
    cd $TEST_HOME/microservices/$1

    kubectl delete -f .
    if [ $? != 0 ]; then
        echo -e "${RED}[FAIL] Failed to delete $1${NC}"
        exit 1
    fi
}

function find_logs() {
    echo -e "${GREEN}[INFO] Finding the corresponding log${NC}"

    tail -n 10 $AUDIT_LOG | grep $1 | grep $2
    if [ $? != 0 ]; then
        tail -n 10 $SYSTEM_LOG | grep $1 | grep $2
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

    SOURCE=$(cat source | grep source | awk '{print $2}')
    POD=$(kubectl get pods -n $2 | grep $SOURCE | awk '{print $1}')

    echo -e "${GREEN}[INFO] Applying $YAML_FILE into $2${NC}"
    kubectl apply -n $2 -f $YAML_FILE
    echo "[INFO] Applied $YAML_FILE into $2"

    sleep 1

    for cmd in $(ls cmd*)
    do
        CMD=$(cat $cmd | grep cmd | cut -d' ' -f2-)
        COND=$(cat $cmd | grep cmd | awk '{print $2}')
        RESULT=$(cat $cmd | grep result | awk '{print $2}')

        FINAL=1

        echo -e "${GREEN}[INFO] Running \"$CMD\"${NC}"
        kubectl exec -n $2 -it $POD -- bash -c "$CMD"
        if [ $? == 0 ]; then
            if [ "$RESULT" == "passed" ]; then
                echo "[INFO] Ran \"$CMD\""
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

cd $ARMOR_HOME

if [ ! -f kubearmor ]; then
    echo -e "${ORANGE}[INFO] Building KubeArmor${NC}"
    make clean; make
    echo "[INFO] Built KubeArmor"
fi

echo -e "${ORANGE}[INFO] Starting KubeArmor${NC}"
start_and_wait_for_kubearmor_initialization
echo "[INFO] Started KubeArmor"

## == Test Scenarios == ##

cd $TEST_HOME

sudo rm -f $ARMOR_LOG $AUDIT_LOG $SYSTEM_LOG

sleep 1

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

while true;
do
    read -p "Do you want to delete log files (Yn)?" yn
    case $yn in
        [Nn]*) break;;
        *) sudo rm -f $ARMOR_LOG $AUDIT_LOG $SYSTEM_LOG; break;;
    esac
done