// Copyright 2021 Authors of KubeArmor
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"errors"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	ea "github.com/kubearmor/KubeArmor/KubeArmor/eventAuditor"
	fd "github.com/kubearmor/KubeArmor/KubeArmor/feeder"
)

// Exit if err is not nil
// Don't use this in production
func exitIfError(err error) {
	if err != nil {
		fmt.Printf("\n%v\n", err)
		os.Exit(-1)
	}
}

func main() {
	var err error
	var eAuditor ea.EventAuditor

	eAuditor.Logger = fd.NewFeeder("", "1337", "stdout", "", false)

	// First set the right path to load the ebpf object files
	eAuditor.SetBPFObjPath("../" + ea.BPFObjRelPath)

	// Init the shared maps
	err = eAuditor.InitSharedMaps()
	exitIfError(err)
	defer eAuditor.StopSharedMaps()

	// Manage maps elements (PatternMap in this case)
	var pattMapElem ea.PatternMapElement
	pattMapElem.SetKey("/bin/*sh")
	pattMapElem.SetValue(1337)

	// Update the map with an element
	err = eAuditor.BPFMapUpdateElement(&pattMapElem)
	exitIfError(err)

	// Update the map with other element
	pattMapElem.SetKey("/bin/*do")
	pattMapElem.SetValue(1949315186)
	err = eAuditor.BPFMapUpdateElement(&pattMapElem)
	exitIfError(err)

	var retPME ea.PatternMapElement
	retPME.SetKey("/bin/*sh")

	// Retrieve an element from the map
	_, err = eAuditor.BPFMapLookupElement(&retPME)
	exitIfError(err)
	if retPME.Value.PatternId != 1337 {
		exitIfError(errors.New("The retrieved element value is not equal to inserted one"))
	}

	done := make(chan bool)
	c := make(chan os.Signal)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-c
		done <- true
	}()

	fmt.Printf(`Check me in other terminal with:
sudo bpftool map show -f
sudo bpftool map dump name ka_ea_pattern_m

Terminate me with: Ctrl+C
`)

	<-done

	// Delete a map element
	err = eAuditor.BPFMapDeleteElement(&retPME)
	exitIfError(err)
}
