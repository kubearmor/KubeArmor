// SPDX-License-Identifier: Apache-2.0
// Copyright 2021 Authors of KubeArmor

// Package common contains utility functions which are commonly used across packages and modules
package common

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	kc "github.com/kubearmor/KubeArmor/KubeArmor/config"
	kg "github.com/kubearmor/KubeArmor/KubeArmor/log"
	tp "github.com/kubearmor/KubeArmor/KubeArmor/types"
	"golang.org/x/sys/unix"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// OuterKey struct
type OuterKey struct {
	PidNs uint32
	MntNs uint32
}

// ============ //
// == Common == //
// ============ //

const (
	// grpc default is 4MB
	// CRI i.e. containerd service can send msg extended upto 16MB
	// https://github.com/containerd/containerd/blob/main/defaults/defaults.go#L22-L25
	DefaultMaxRecvMaxSize = 16 << 20
)

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

// MatchesRegex function
func MatchesRegex(key, element string, array []string) bool {
	for _, item := range array {
		if strings.Contains(item, key) {
			expr, err := regexp.CompilePOSIX(element)
			if err != nil {
				kg.Warnf("Failed to compile regex: %s", element)
				return false
			}

			return expr.MatchString(item)
		}
	}

	// key not found in array
	return true
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

	var wg sync.WaitGroup
	wg.Add(1)

	go func() {
		defer wg.Done()
		defer func() {
			if err = stdin.Close(); err != nil {
				kg.Warnf("Error closing stdin %s\n", err)
			}
		}()
		_, _ = io.WriteString(stdin, "values written to stdin are passed to cmd's standard input")
	}()

	// Wait for the stdin writing to complete
	wg.Wait()

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

// ContainerRuntimeSocketKeys contains FIFO ordered keys of container runtimes
var ContainerRuntimeSocketKeys = []string{"docker", "containerd", "cri-o"}

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

// NRISocketMap Structure
var NRISocketMap = map[string][]string{
	"nri": {
		"/var/run/nri/nri.sock",
		"/run/nri/nri.sock",
	},
}

// GetNRISocket Function
func GetNRISocket(ContainerRuntime string) string {
	for _, candidate := range NRISocketMap["nri"] {
		if _, err := os.Stat(candidate); err == nil {
			return candidate
		}
	}
	return ""
}

// GetCRISocket Function
func GetCRISocket(ContainerRuntime string) string {
	for _, k := range ContainerRuntimeSocketKeys {
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
func MatchIdentities(identities, superIdentities []string) bool {
	matched := true

	// if nothing in identities, skip it
	if len(identities) == 0 {
		return false
	}

	// if super identities not include identity, return false
	for _, identity := range identities {

		// match regex if container name or host name label present
		if strings.Contains(identity, "kubearmor.io/container.name") {
			if !MatchesRegex("kubearmor.io/container.name", identity, superIdentities) {
				matched = false
				break
			}

			continue
		}

		if strings.Contains(identity, "kubearmor.io/hostname") {
			if !MatchesRegex("kubearmor.io/hostname", identity, superIdentities) {
				matched = false
				break
			}

			continue
		}

		if !ContainsElement(superIdentities, identity) {
			matched = false
			break
		}
	}

	// otherwise, return true
	return matched
}

// MatchExpIdentities Function
func MatchExpIdentities(selector tp.SelectorType, superIdentities []string) bool {
	matched := false

	identities := selector.MatchExpIdentities
	nonIdentities := selector.NonIdentities

	// no matchExp with key as label defined
	if len(identities) == 0 && len(nonIdentities) == 0 {
		return true
	}

	for _, identity := range identities {
		if ContainsElement(superIdentities, identity) {
			matched = true
			break
		}
	}

	for i, nonIdentity := range nonIdentities {
		if ContainsElement(superIdentities, nonIdentity) {
			matched = false
			break
		}
		if i == len(nonIdentities)-1 {
			// if nonIdentities are not matched, then return true
			matched = true
		}
	}

	// otherwise, return false
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

// ParseURL with/without scheme and return host, port or error
func ParseURL(address string) (string, string, error) {
	var host string
	port := "80"

	addr, err := url.Parse(address)
	if err != nil || addr.Host == "" {
		// URL without scheme
		u, repErr := url.ParseRequestURI("http://" + address)
		if repErr != nil {
			return "", "", fmt.Errorf("Error while parsing URL: %s", err)
		}

		addr = u
	}

	host = addr.Hostname()
	if addr.Port() != "" {
		port = addr.Port()
	}

	return host, port, nil
}

// handle gRPC errors
func HandleGRPCErrors(err error) error {
	if err == nil {
		return nil
	}

	if status, ok := status.FromError(err); ok {
		switch status.Code() {
		case codes.OK:
			// noop
			return nil
		//case codes.Unavailable, codes.Canceled, codes.DeadlineExceeded:
		//	return status.Err()
		default:
			return status.Err()
		}
	}

	return nil
}

// get boot time
// credits: https://github.com/kubernetes/kubernetes/blob/master/pkg/kubelet/util/boottime_util_linux.go
func GetBootTime() string {
	currentTime := time.Now()

	var info unix.Sysinfo_t
	if err := unix.Sysinfo(&info); err != nil {
		return ""
	}

	return currentTime.Add(-time.Duration(info.Uptime) * time.Second).Truncate(time.Second).UTC().String()
}

func GetLabelsFromString(labelString string) (map[string]string, []string) {
	labelsMap := make(map[string]string)

	labelsSlice := strings.Split(labelString, ",")
	for _, label := range labelsSlice {
		key, value, ok := strings.Cut(label, "=")
		if !ok {
			continue
		}

		labelsMap[key] = value
	}

	sort.Slice(labelsSlice, func(i, j int) bool {
		return labelsSlice[i] < labelsSlice[j]
	})

	return labelsMap, labelsSlice
}

// provide current timestamp
func GetCurrentTimeStamp() uint64 {
	return uint64(time.Now().UnixNano())
}

// ============
// == Feeder ==
// ============

// IsPresetEnforcer returns true if log is generated by any of preset enforcer
func IsPresetEnforcer(enforcer string) bool {
	return strings.Contains(enforcer, "PRESET")
}
