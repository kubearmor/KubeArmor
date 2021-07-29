package common

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"reflect"
	"strconv"
	"strings"
	"time"

	kg "github.com/kubearmor/KubeArmor/KubeArmor/log"

	"golang.org/x/sys/unix"
)

// ============ //
// == Common == //
// ============ //

// Clone Function
func Clone(src, dst interface{}) error {
	arr, _ := json.Marshal(src)
	return json.Unmarshal(arr, dst)
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
	uptimeDiffSec, _ := strconv.Atoi(strings.Split(uptimeDiff, ".")[0]) // second
	uptimeDiffMil, _ := strconv.Atoi(strings.Split(uptimeDiff, ".")[1]) // milli sec.

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
	res := exec.Command(cmd, args...)
	out, err := res.Output()
	if err != nil {
		return string(out), err
	}
	return string(out), nil
}

// GetCommandOutputWithoutErr Function
func GetCommandOutputWithoutErr(cmd string, args []string) string {
	res := exec.Command(cmd, args...)
	out, err := res.Output()
	if err != nil {
		return ""
	}
	return string(out)
}

// GetCommandWaitOutputWithErr Function
func GetCommandWaitOutputWithErr(cmd string, args []string) error {
	command := exec.Command(cmd, args...)
	if err := command.Start(); err != nil {
		return err
	}

	if err := command.Wait(); err != nil {
		return err
	}

	return nil
}

// ========== //
// == Host == //
// ========== //

// GetHostName Function
func GetHostName() string {
	if res, err := os.Hostname(); err == nil {
		return res
	}
	return ""
}

// ================= //
// == File Output == //
// ================= //

// StrToFile Function
func StrToFile(str, destFile string) {
	// if destFile doesn't exist, create it
	if _, err := os.Stat(destFile); err != nil {
		newFile, err := os.Create(destFile)
		if err != nil {
			kg.Err(err.Error())
			return
		}
		newFile.Close()
	}

	// open the file with the append mode
	file, err := os.OpenFile(destFile, os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		kg.Err(err.Error())
		return
	}
	defer file.Close()

	// add the newline at the end of the string
	str = str + "\n"

	// write the string into the file
	_, err = file.WriteString(str)
	if err != nil {
		kg.Err(err.Error())
	}

	// sync the file
	err = file.Sync()
	if err != nil {
		kg.Err(err.Error())
	}
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
	// local
	k8sConfig := os.Getenv("HOME") + "/.kube"
	if _, err := os.Stat(k8sConfig); err == nil {
		return true
	}

	return false
}

// IsInK8sCluster Function
func IsInK8sCluster() bool {
	if _, ok := os.LookupEnv("KUBERNETES_PORT"); ok {
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

	// if super identities not include indentity, return false
	for _, identity := range identities {
		if !ContainsElement(superIdentities, identity) {
			matched = false
			break
		}
	}

	// otherwise, return true
	return matched
}

// ============= //
// == SELinux == //
// ============= //

// DoLgetxattr is a wrapper that retries on EINTR
func DoLgetxattr(path, attr string, dest []byte) (int, error) {
	for { // TODO: NEED THE TERMINATION CONDITION FOR THE WORST CASE
		if sz, err := unix.Lgetxattr(path, attr, dest); err != unix.EINTR {
			return sz, err
		}
	}
}

// Lgetxattr returns a []byte slice containing the value of an extended attribute attr set for path.
func Lgetxattr(path, attr string) ([]byte, error) {
	dest := make([]byte, 128)

	sz, errno := DoLgetxattr(path, attr, dest)
	for errno == unix.ERANGE {
		// if buffer is too small, use zero-sized buffer to get the actual size
		sz, errno = DoLgetxattr(path, attr, []byte{})
		if errno != nil {
			return nil, errno
		}

		dest = make([]byte, sz)
		sz, errno = DoLgetxattr(path, attr, dest)
	}
	if errno != nil {
		return nil, errno
	}

	return dest[:sz], nil
}

func GetSELinuxType(path string) (string, error) {
	xattrNameSelinux := "security.selinux"

	label, err := Lgetxattr(path, xattrNameSelinux)
	if err != nil {
		return "", err
	}

	// Trim the NUL byte at the end of the byte buffer, if present.
	if len(label) > 0 && label[len(label)-1] == '\x00' {
		label = label[:len(label)-1]
	}

	return strings.Split(string(label), ":")[2], nil
}
