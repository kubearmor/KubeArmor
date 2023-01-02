#!/bin/bash -e

BASEDIR=$(dirname "${0}") ; cd ${BASEDIR}/../ ; BASEDIR=$(pwd) ; cd ${BASEDIR}

MONITOR_BPF_OBJECT="${BASEDIR}/KubeArmor/monitor/embedded_system_monitor.bpf.o"
MONITOR_CONTAINER_BPF_OBJECT="${BASEDIR}/KubeArmor/monitor/embedded_system_monitor.container.bpf.o"
MONITOR_HOST_BPF_OBJECT="${BASEDIR}/KubeArmor/monitor/embedded_system_monitor.host.bpf.o"
BTFHUB_REPO="https://github.com/aquasecurity/btfhub.git"
BTFHUB_ARCHIVE_REPO="https://github.com/aquasecurity/btfhub-archive.git"
BPFTOOL_REPO="https://github.com/libbpf/bpftool.git"
BTFHUB_DIR="${BASEDIR}/btf-utils/btfhub"
BTFHUB_ARCHIVE_DIR="${BASEDIR}/btf-utils/btfhub-archive"
BPFTOOL_DIR="${BASEDIR}/btf-utils/bpftool"
# BTFHUB_DIR="/var/tmp/btf/btfhub"
# BTFHUB_ARCHIVE_DIR="/var/tmp/btfhub-archive"
ARCH=$(uname -m)
DISTRO_LIST="${BASEDIR}/btf-utils/dirlist"


[ ! -f ${MONITOR_BPF_OBJECT} ] && die "Kubearmor embedded_system_monitor obj not found"
[ ! -f ${MONITOR_CONTAINER_BPF_OBJECT} ] && die "Kubearmor embedded_system_monitor_container obj not found"
[ ! -f ${MONITOR_HOST_BPF_OBJECT} ] && die "Kubearmor embedded_system_monitor_container obj not found"
# [ ! -d ${BASEDIR}/dist/btfhub ] && mkdir ${BASEDIR}/btf-utils/btf/btfhub

[ ! -d ${BPFTOOL_DIR} ] && git clone --recurse-submodules ${BPFTOOL_REPO} ${BPFTOOL_DIR}

cd "${BPFTOOL_DIR}/src"
make install


[ ! -d ${BTFHUB_DIR} ] && git clone "${BTFHUB_REPO}" ${BTFHUB_DIR}
[ ! -d ${BTFHUB_ARCHIVE_DIR} ] && git clone "${BTFHUB_ARCHIVE_REPO}" ${BTFHUB_ARCHIVE_DIR}
# cd ${BTFHUB_DIR}

# [ ! -f ./tools/btfgen.sh ] && die "could not find btfgen.sh"
# ./tools/btfgen.sh -a $ARCH -o $MONITOR_BPF_OBJECT -o $MONITOR_CONTAINER_BPF_OBJECT -o $MONITOR_HOST_BPF_OBJECT 



input="${BASEDIR}/btf-utils/dirlist"

while IFS= read -r line
do
    extracted_line="$BASEDIR/btf-utils/$line"
    echo "reading from $extracted_line"
    cd "$extracted_line"
    for f in *.tar.xz;
    do 
        # echo "Extracting $f"
        # tar -xf  "$f";
        filename="$extracted_line/$(basename $f .tar.xz)"
        if [ ! -f $filename ];
        then 
        echo "Extracting $f"
        tar -xf  "$f";
        fi
    done
    reduced_dir="${BASEDIR}/KubeArmor/monitor/reduced-btfs/${line:15}" 
    [ ! -d $reduced_dir ] && mkdir "$reduced_dir" -p
    for f in *.btf;
    do 
        echo "Generating reduced file for $f"
        bpftool gen min_core_btf "$f" "$reduced_dir/$(basename $f)" \
        $MONITOR_BPF_OBJECT \
        $MONITOR_CONTAINER_BPF_OBJECT \
        $MONITOR_HOST_BPF_OBJECT;
        # rm $f
    done
    cd $reduced_dir
    find . -name "*.btf" | xargs du -ch | tail -n 1
    echo "================="
done < "$input"

die() {
    echo ${@}
    exit 1
}
