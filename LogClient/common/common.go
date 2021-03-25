package common

import (
	"fmt"
	"os"
)

// StrToFile Function
func StrToFile(str, destFile string) {
	file, err := os.OpenFile(destFile, os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		fmt.Errorf("Failed to open a file (%s, %s)", destFile, err.Error())
	}
	defer file.Close()

	_, err = file.WriteString(str)
	if err != nil {
		fmt.Errorf("Failed to write a string into the file (%s, %s)", destFile, err.Error())
	}
}
