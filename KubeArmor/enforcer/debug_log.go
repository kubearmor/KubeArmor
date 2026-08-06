package enforcer

import (
	"os"
	"time"
	"fmt"
)

func debugLog(format string, args ...interface{}) {
	f, _ := os.OpenFile(`C:\kubearmor_debug.log`, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0666)
	if f != nil {
		msg := fmt.Sprintf(format, args...)
		f.WriteString(time.Now().Format(time.RFC3339) + " " + msg + "\n")
		f.Close()
	}
}
