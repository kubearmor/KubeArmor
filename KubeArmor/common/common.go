// SPDX-License-Identifier: Apache-2.0
// Copyright 2021 Authors of KubeArmor

// Package common contains utility functions which are commonly used across packages and modules
package common

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"time"

	kc "github.com/kubearmor/KubeArmor/KubeArmor/config"
	kg "github.com/kubearmor/KubeArmor/KubeArmor/log"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// ============ //
// == Common == //
// ============ //

// Clone Function
func Clone(src, dst interface{}) error {
	arr, _ := json.Marshal(src)
	return json.Unmarshal(arr, dst)
}

// RemoveStringElement function
func RemoveStringElement(slice []string, size int) []string {
	return append(slice[:size], slice[size+1:]...)
}

// ContainsElement Function
func ContainsElement(slice interface{}, element interface{}) bool {
	switch reflect.TypeOf(slice).Kind() {
	case reflect.Slice:
		s := reflect.ValueOf(slice)

		for i := 0; i < s.Len(); i++ {
			val := s.Index(i).Interface()
			if reflect.DeepEqual(val, element) {
				return true
			}
		}
	}
	return false
}

// ObjCommaCanBeExpanded Function
func ObjCommaCanBeExpanded(objptr interface{}) bool {
	ovptr := reflect.ValueOf(objptr)
	if ovptr.Kind() != reflect.Ptr {
		return false
	}

	ov := ovptr.Elem()
	if ov.Kind() != reflect.Slice {
		return false
	}

	if ov.Len() == 0 {
		return false
	}

	ovelm := ov.Index(0)
	if ovelm.Kind() != reflect.Struct {
		return false
	}

	field0 := ovelm.Field(0)
	if field0.Kind() != reflect.String {
		return false
	}

	value := field0.Interface().(string)
	return strings.Split(value, ",")[0] != value
}

// ObjCommaExpand Function
func ObjCommaExpand(v reflect.Value) []string {
	return strings.Split(v.Field(0).Interface().(string), ",")
}

// ObjCommaExpandFirstDupOthers Function
func ObjCommaExpandFirstDupOthers(objptr interface{}) {
	if ObjCommaCanBeExpanded(objptr) {
		old := reflect.ValueOf(objptr).Elem()
		new := reflect.New(reflect.TypeOf(objptr).Elem()).Elem()

		for i := 0; i < old.Len(); i++ {
			for _, f := range ObjCommaExpand(old.Index(i)) {
				field := strings.ReplaceAll(f, " ", "")
				new.Set(reflect.Append(new, old.Index(i)))
				new.Index(new.Len() - 1).Field(0).SetString(field)
			}
		}

		reflect.ValueOf(objptr).Elem().Set(new)
	}
}

// CopyFile Function
func CopyFile(src, dst string) error {
	in, err := os.Open(filepath.Clean(src))
	if err != nil {
		return err
	}
	defer func() {
		cerr := in.Close()
		if err == nil {
			err = cerr
		}
	}()

	out, err := os.Create(filepath.Clean(dst))
	if err != nil {
		return err
	}
	defer func() {
		cerr := out.Close()
		if err == nil {
			err = cerr
		}
	}()

	if _, err = io.Copy(out, in); err != nil {
		return err
	}

	err = out.Sync()
	if err != nil {
		return err
	}

	return nil
}

// ========== //
// == Time == //
// ========== //

// Time Format
const (
	TimeFormUTC string = "2006-01-02T15:04:05.000000Z"
)

// GetDateTimeNow Function
func GetDateTimeNow() (int64, string) {
	utc := time.Now().UTC()
	ret := utc.Format(TimeFormUTC)
	return utc.Unix(), ret
}

// GetUptimeTimestamp Function
func GetUptimeTimestamp() float64 {
	now := time.Now().UTC()

	res := GetCommandOutputWithoutErr("cat", []string{"/proc/uptime"})

	uptimeDiff := strings.Split(res, " ")[0]

	uptimeDiffSec, err := strconv.ParseInt(strings.Split(uptimeDiff, ".")[0], 10, 64) // second
	if err != nil {
		kg.Err(err.Error())
	}
	uptimeDiffMil, err := strconv.ParseInt(strings.Split(uptimeDiff, ".")[1], 10, 64) // milli second
	if err != nil {
		kg.Err(err.Error())
	}

	uptime := now.Add(-time.Second * time.Duration(uptimeDiffSec))
	uptime = uptime.Add(-time.Millisecond * time.Duration(uptimeDiffMil))

	micro := uptime.UnixNano() / 1000
	up := float64(micro) / 1000000.0

	return up
}

// GetDateTimeFromTimestamp Function
func GetDateTimeFromTimestamp(timestamp float64) string {
	strTS := fmt.Sprintf("%.6f", timestamp)

	secTS := strings.Split(strTS, ".")[0]
	nanoTS := strings.Split(strTS, ".")[1] + "000"

	sec64, err := strconv.ParseInt(secTS, 10, 64)
	if err != nil {
		kg.Err(err.Error())
	}

	nano64, err := strconv.ParseInt(nanoTS, 10, 64)
	if err != nil {
		kg.Err(err.Error())
	}

	tm := time.Unix(sec64, nano64)
	tm = tm.UTC()

	return tm.Format(TimeFormUTC)
}

// ======================= //
// == Command Execution == //
// ======================= //

// GetCommandOutputWithErr Function
func GetCommandOutputWithErr(cmd string, args []string) (string, error) {
	// #nosec
	res := exec.Command(cmd, args...)
	stdin, err := res.StdinPipe()
	if err != nil {
		return "", err
	}

	go func() {
		defer func() {
			if err = stdin.Close(); err != nil {
				kg.Warnf("Error closing stdin %s\n", err)
			}
		}()
		_, err = io.WriteString(stdin, "values written to stdin are passed to cmd's standard input")
	}()

	out, err := res.CombinedOutput()
	if err != nil {
		return string(out), err
	}

	return string(out), nil
}

// GetSHA256ofImage of the image
func GetSHA256ofImage(s string) string {
	if idx := strings.Index(s, "@"); idx != -1 {
		return s[idx:]
	}
	return s
}

// GetCommandOutputWithoutErr Function
func GetCommandOutputWithoutErr(cmd string, args []string) string {
	// #nosec
	res := exec.Command(cmd, args...)
	stdin, err := res.StdinPipe()
	if err != nil {
		return ""
	}

	go func() {
		defer func() {
			if err = stdin.Close(); err != nil {
				kg.Warnf("Error closing stdin %s\n", err)
			}
		}()
		_, _ = io.WriteString(stdin, "values written to stdin are passed to cmd's standard input")
	}()

	out, err := res.CombinedOutput()
	if err != nil {
		return ""
	}

	return string(out)
}

// RunCommandAndWaitWithErr Function
func RunCommandAndWaitWithErr(cmd string, args []string) error {
	// #nosec
	res := exec.Command(cmd, args...)
	if err := res.Start(); err != nil {
		return err
	}
	if err := res.Wait(); err != nil {
		return err
	}
	return nil
}

// ============= //
// == Network == //
// ============= //

// GetExternalInterface Function
func GetExternalInterface() string {
	route := GetCommandOutputWithoutErr("ip", []string{"route"})
	routeData := strings.Split(strings.Split(route, "\n")[0], " ")
	for idx, word := range routeData {
		if word == "dev" {
			return routeData[idx+1]
		}
	}
	return ""
}

// GetIPAddr Function
func GetIPAddr(ifname string) string {
	if interfaces, err := net.Interfaces(); err == nil {
		for _, iface := range interfaces {
			if iface.Name == ifname {
				if addrs, err := iface.Addrs(); err == nil {
					ipaddr := strings.Split(addrs[0].String(), "/")[0]
					return ipaddr
				}
				return ""
			}
		}
	}
	return ""
}

// GetExternalIPAddr Function
func GetExternalIPAddr() string {
	iface := GetExternalInterface()
	return GetIPAddr(iface)
}

// ================ //
// == Kubernetes == //
// ================ //

// IsK8sLocal Function
func IsK8sLocal() bool {
	if !kc.GlobalCfg.K8sEnv {
		return false
	}

	k8sConfig := os.Getenv("KUBECONFIG")
	if k8sConfig != "" {
		if _, err := os.Stat(filepath.Clean(k8sConfig)); err == nil {
			return true
		}
	}

	home := os.Getenv("HOME")
	if _, err := os.Stat(filepath.Clean(home + "/.kube/config")); err == nil {
		return true
	}

	return false
}

// IsInK8sCluster Function
func IsInK8sCluster() bool {
	if _, ok := os.LookupEnv("KUBERNETES_SERVICE_HOST"); ok {
		return true
	}

	if _, err := os.Stat(filepath.Clean("/run/secrets/kubernetes.io")); err == nil {
		return true
	}

	return false
}

// IsK8sEnv Function
func IsK8sEnv() bool {
	// local
	if IsK8sLocal() {
		return true
	}

	// in-cluster
	if IsInK8sCluster() {
		return true
	}

	return false
}

// ContainerRuntimeSocketMap Structure
var ContainerRuntimeSocketMap = map[string][]string{
	"docker": {
		"/var/run/docker.sock",
		"/run/docker.sock",
	},
	"containerd": {
		"/var/snap/microk8s/common/run/containerd.sock",
		"/run/k3s/containerd/containerd.sock",
		"/run/containerd/containerd.sock",
		"/var/run/containerd/containerd.sock",
		"/run/dockershim.sock",
	},
	"cri-o": {
		"/var/run/crio/crio.sock",
		"/run/crio/crio.sock",
	},
}

// GetCRISocket Function
func GetCRISocket(ContainerRuntime string) string {
	for k := range ContainerRuntimeSocketMap {
		if ContainerRuntime != "" && k != ContainerRuntime {
			continue
		}
		for _, candidate := range ContainerRuntimeSocketMap[k] {
			if _, err := os.Stat(candidate); err == nil {
				return candidate
			}
		}
	}
	return ""
}

// GetControllingPodOwner Function returns the pod's Controlling OnwerReference
func GetControllingPodOwner(ownerRefs []metav1.OwnerReference) *metav1.OwnerReference {
	for _, ownerRef := range ownerRefs {
		if ownerRef.Controller != nil && *ownerRef.Controller {
			return &ownerRef
		}
	}
	return nil
}

// ==================== //
// == Identity Match == //
// ==================== //

// MatchIdentities Function
func MatchIdentities(identities []string, superIdentities []string) bool {
	matched := true

	// if nothing in identities, skip it
	if len(identities) == 0 {
		return false
	}

	// if super identities not include identity, return false
	for _, identity := range identities {
		if !ContainsElement(superIdentities, identity) {
			matched = false
			break
		}
	}

	// otherwise, return true
	return matched
}

// WriteToFile writes given string to file as JSON
func WriteToFile(val interface{}, destFile string) error {
	j, err := json.Marshal(val)
	if err != nil {
		return err
	}
	err = os.WriteFile(destFile, j, 0600)
	if err != nil {
		return err
	}
	return nil
}
