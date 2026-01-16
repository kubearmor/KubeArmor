// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Authors of KubeArmor

package bpflsm

import (
	"strings"

	tp "github.com/kubearmor/KubeArmor/KubeArmor/types"
)

func handleAllNetworkRule(protocols *[]tp.NetworkProtocolType) {
	allProtocols := []tp.NetworkProtocolType{}

	allWithNoFromSourceAllow := false
	allWithNoFromSourceBlock := false

	sourcesBlock := map[string]string{}
	sourcesAllow := map[string]string{}

	for _, net := range *protocols {
		if strings.ToUpper(net.Protocol) == "ALL" {
			if len(net.FromSource) == 0 {
				if net.Action == "Allow" && !allWithNoFromSourceAllow {
					for r := range netType {
						allProtocols = append(allProtocols, tp.NetworkProtocolType{
							Protocol: r,
							Action:   net.Action,
						})
					}
					allWithNoFromSourceAllow = true
				} else if net.Action == "Block" && !allWithNoFromSourceBlock {
					for r := range netType {
						allProtocols = append(allProtocols, tp.NetworkProtocolType{
							Protocol: r,
							Action:   net.Action,
						})
					}
					allWithNoFromSourceBlock = true
				}
			} else {
				for _, src := range net.FromSource {
					if _, ok := sourcesAllow[src.Path]; !ok && net.Action == "Allow" {
						sourcesAllow[src.Path] = net.Action
					}
					if _, ok := sourcesBlock[src.Path]; !ok && net.Action == "Block" {
						sourcesBlock[src.Path] = net.Action
					}
				}
			}
		}
	}

	// add all with fromsource rules

	if len(sourcesAllow) > 0 {
		sources := []tp.MatchSourceType{}
		for src := range sourcesAllow {
			sources = append(sources, tp.MatchSourceType{
				Path: src,
			})
		}
		for r := range netType {
			allProtocols = append(allProtocols, tp.NetworkProtocolType{
				Protocol:   r,
				Action:     "Allow",
				FromSource: sources,
			})
		}
	}

	if len(sourcesBlock) > 0 {
		sources := []tp.MatchSourceType{}
		for src := range sourcesBlock {
			sources = append(sources, tp.MatchSourceType{
				Path: src,
			})
		}
		for r := range netType {
			allProtocols = append(allProtocols, tp.NetworkProtocolType{
				Protocol:   r,
				Action:     "Block",
				FromSource: sources,
			})
		}
	}

	*protocols = append(*protocols, allProtocols...)

}
