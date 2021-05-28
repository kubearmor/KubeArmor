package common

import (
	"fmt"
	"os"
)

// StrToFile Function
func StrToFile(str, destFile string) {
	if _, err := os.Stat(destFile); err != nil {
		newFile, err := os.Create(destFile)
		if err != nil {
			fmt.Printf("Failed to create a file (%s, %s)\n", destFile, err.Error())
			return
		}
		newFile.Close()
	}

	file, err := os.OpenFile(destFile, os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		fmt.Printf("Failed to open a file (%s, %s)\n", destFile, err.Error())
	}
	defer file.Close()

	_, err = file.WriteString(str)
	if err != nil {
		fmt.Printf("Failed to write a string into the file (%s, %s)\n", destFile, err.Error())
	}
}
