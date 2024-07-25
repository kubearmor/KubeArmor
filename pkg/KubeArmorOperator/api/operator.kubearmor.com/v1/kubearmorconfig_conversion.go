// SPDX-License-Identifier: Apache-2.0
// Copyright 2022 Authors of KubeArmor

package v1

import (
	"strconv"
	"strings"

	"sigs.k8s.io/controller-runtime/pkg/conversion"

	v2 "github.com/kubearmor/KubeArmor/pkg/KubeArmorOperator/api/operator.kubearmor.com/v2"
)

// ConvertTo converts this KubeArmorConfig to the Hub version (v2).
func (src *KubeArmorConfig) ConvertTo(dstRaw conversion.Hub) error {

	dst := dstRaw.(*v2.KubeArmorConfig)

	// ======
	// images
	// ======

	// kubearmor image
	if imageAndTag := src.Spec.KubeArmorImage.Image; imageAndTag != "" {
		reg, repo, tag := parseImage(imageAndTag)
		dst.Spec.KubeArmor.Image.Registry = reg
		dst.Spec.KubeArmor.Image.Repository = repo
		dst.Spec.KubeArmor.Image.Tag = tag
	}
	dst.Spec.KubeArmor.ImagePullPolicy = v2.ImagePullPolicy(src.Spec.KubeArmorImage.ImagePullPolicy)
	// kubearmor init image
	if imageAndTag := src.Spec.KubeArmorInitImage.Image; imageAndTag != "" {
		reg, repo, tag := parseImage(imageAndTag)
		dst.Spec.KubeArmorInit.Image.Registry = reg
		dst.Spec.KubeArmorInit.Image.Repository = repo
		dst.Spec.KubeArmorInit.Image.Tag = tag
	}
	dst.Spec.KubeArmorInit.ImagePullPolicy = v2.ImagePullPolicy(src.Spec.KubeArmorInitImage.ImagePullPolicy)
	// kubearmor relay image
	if imageAndTag := src.Spec.KubeArmorRelayImage.Image; imageAndTag != "" {
		reg, repo, tag := parseImage(imageAndTag)
		dst.Spec.KubeArmorRelay.Image.Registry = reg
		dst.Spec.KubeArmorRelay.Image.Repository = repo
		dst.Spec.KubeArmorRelay.Image.Tag = tag
	}
	dst.Spec.KubeArmorRelay.ImagePullPolicy = v2.ImagePullPolicy(src.Spec.KubeArmorRelayImage.ImagePullPolicy)
	// kubearmor controller image
	if imageAndTag := src.Spec.KubeArmorControllerImage.Image; imageAndTag != "" {
		reg, repo, tag := parseImage(imageAndTag)
		dst.Spec.KubeArmorController.Image.Registry = reg
		dst.Spec.KubeArmorController.Image.Repository = repo
		dst.Spec.KubeArmorController.Image.Tag = tag
	}
	dst.Spec.KubeArmorController.ImagePullPolicy = v2.ImagePullPolicy(src.Spec.KubeArmorControllerImage.ImagePullPolicy)
	// kube rbac proxy image
	if imageAndTag := src.Spec.KubeRbacProxyImage.Image; imageAndTag != "" {
		reg, repo, tag := parseImage(imageAndTag)
		dst.Spec.KubeRbacProxy.Image.Registry = reg
		dst.Spec.KubeRbacProxy.Image.Repository = repo
		dst.Spec.KubeRbacProxy.Image.Tag = tag
	}
	dst.Spec.KubeRbacProxy.ImagePullPolicy = v2.ImagePullPolicy(src.Spec.KubeRbacProxyImage.ImagePullPolicy)

	// ===================
	// kubearmor configmap
	// ===================

	// file posture
	dst.Spec.KubeArmorConfigMap.DefaultFilePosture = v2.DefaultPosture(src.Spec.DefaultFilePosture)

	// capability posture
	dst.Spec.KubeArmorConfigMap.DefaultCapabilitiesPosture = v2.DefaultPosture(src.Spec.DefaultCapabilitiesPosture)

	// capability posture
	dst.Spec.KubeArmorConfigMap.DefaultNetworkPosture = v2.DefaultPosture(src.Spec.DefaultNetworkPosture)

	// visibility
	dst.Spec.KubeArmorConfigMap.Visibility = src.Spec.DefaultVisibility

	// alert throttling
	dst.Spec.KubeArmorConfigMap.AlertThrottling = src.Spec.AlertThrottling
	// max alerts/sec
	dst.Spec.KubeArmorConfigMap.MaxAlertPerSec = src.Spec.MaxAlertPerSec
	// throttle sec
	dst.Spec.KubeArmorConfigMap.ThrottleSec = src.Spec.ThrottleSec

	// ==================
	// tls configurations
	// ==================
	dst.Spec.TLS.Enabled = src.Spec.Tls.Enable
	dst.Spec.KubeArmorRelay.TLS.ExtraDNSNames = src.Spec.Tls.RelayExtraDnsNames
	dst.Spec.KubeArmorRelay.TLS.ExtraIPAddresses = src.Spec.Tls.RelayExtraIpAddresses

	// =============
	// relay env var
	// =============
	dst.Spec.KubeArmorRelay.EnableStdOutLogs = strconv.FormatBool(src.Spec.EnableStdOutLogs)
	dst.Spec.KubeArmorRelay.EnableStdOutAlerts = strconv.FormatBool(src.Spec.EnableStdOutAlerts)
	dst.Spec.KubeArmorRelay.EnableStdOutMsg = strconv.FormatBool(src.Spec.EnableStdOutMsgs)
	dst.ObjectMeta = src.ObjectMeta

	// remove global registry configs
	dst.Spec.GlobalRegistry = ""
	dst.Spec.UseGlobalRegistryForVendorImages = false
	return nil
}

// ConvertFrom converts from the Hub version (v2) to this version.
func (dst *KubeArmorConfig) ConvertFrom(srcRaw conversion.Hub) error {
	src := srcRaw.(*v2.KubeArmorConfig)

	// ======
	// images
	// ======
	globalRegistry := src.Spec.GlobalRegistry
	// kubearmor image
	if img := src.Spec.KubeArmor.Image.Repository; img != "" {
		tag := src.Spec.KubeArmor.Image.Tag
		if reg := src.Spec.KubeArmor.Image.Registry; reg != "" {
			dst.Spec.KubeArmorImage.Image = createImage(reg, img, tag)
		} else {
			dst.Spec.KubeArmorImage.Image = createImage(globalRegistry, img, tag)
		}
	}
	dst.Spec.KubeArmorImage.ImagePullPolicy = string(src.Spec.KubeArmor.ImagePullPolicy)
	// kubearmor init image
	if img := src.Spec.KubeArmorInit.Image.Repository; img != "" {
		tag := src.Spec.KubeArmorInit.Image.Tag
		if reg := src.Spec.KubeArmorInit.Image.Registry; reg != "" {
			dst.Spec.KubeArmorInitImage.Image = createImage(reg, img, tag)
		} else {
			dst.Spec.KubeArmorInitImage.Image = createImage(globalRegistry, img, tag)
		}
	}
	dst.Spec.KubeArmorInitImage.ImagePullPolicy = string(src.Spec.KubeArmorInit.ImagePullPolicy)
	// kubearmor relay image
	if img := src.Spec.KubeArmorRelay.Image.Repository; img != "" {
		tag := src.Spec.KubeArmorRelay.Image.Tag
		if reg := src.Spec.KubeArmorRelay.Image.Registry; reg != "" {
			dst.Spec.KubeArmorRelayImage.Image = createImage(reg, img, tag)
		} else {
			dst.Spec.KubeArmorRelayImage.Image = createImage(globalRegistry, img, tag)
		}
	}
	dst.Spec.KubeArmorRelayImage.ImagePullPolicy = string(src.Spec.KubeArmorRelay.ImagePullPolicy)
	// kubearmor controller image
	if img := src.Spec.KubeArmorController.Image.Repository; img != "" {
		tag := src.Spec.KubeArmorController.Image.Tag
		if reg := src.Spec.KubeArmorController.Image.Registry; reg != "" {
			dst.Spec.KubeArmorControllerImage.Image = createImage(reg, img, tag)
		} else {
			dst.Spec.KubeArmorControllerImage.Image = createImage(globalRegistry, img, tag)
		}
	}
	dst.Spec.KubeArmorControllerImage.ImagePullPolicy = string(src.Spec.KubeArmorController.ImagePullPolicy)
	// kube rbac proxy image
	if img := src.Spec.KubeRbacProxy.Image.Repository; img != "" {
		tag := src.Spec.KubeRbacProxy.Image.Tag
		if reg := src.Spec.KubeRbacProxy.Image.Registry; reg != "" && !src.Spec.UseGlobalRegistryForVendorImages {
			dst.Spec.KubeRbacProxyImage.Image = createImage(reg, img, tag)
		} else {
			dst.Spec.KubeRbacProxyImage.Image = createImage(globalRegistry, img, tag)
		}
	}
	dst.Spec.KubeRbacProxyImage.ImagePullPolicy = string(src.Spec.KubeRbacProxy.ImagePullPolicy)

	// ===================
	// kubearmor configmap
	// ===================

	// file posture
	dst.Spec.DefaultFilePosture = PostureType(src.Spec.KubeArmorConfigMap.DefaultFilePosture)

	// capability posture
	dst.Spec.DefaultCapabilitiesPosture = PostureType(src.Spec.KubeArmorConfigMap.DefaultCapabilitiesPosture)

	// capability posture
	dst.Spec.DefaultNetworkPosture = PostureType(src.Spec.KubeArmorConfigMap.DefaultNetworkPosture)

	// visibility
	dst.Spec.DefaultVisibility = src.Spec.KubeArmorConfigMap.Visibility

	// alert throttling
	dst.Spec.AlertThrottling = src.Spec.KubeArmorConfigMap.AlertThrottling
	// max alerts/sec
	dst.Spec.MaxAlertPerSec = src.Spec.KubeArmorConfigMap.MaxAlertPerSec
	// throttle sec
	dst.Spec.ThrottleSec = src.Spec.KubeArmorConfigMap.ThrottleSec

	// ==================
	// tls configurations
	// ==================
	dst.Spec.Tls.Enable = src.Spec.TLS.Enabled
	dst.Spec.Tls.RelayExtraDnsNames = src.Spec.KubeArmorRelay.TLS.ExtraDNSNames
	dst.Spec.Tls.RelayExtraIpAddresses = src.Spec.KubeArmorRelay.TLS.ExtraIPAddresses

	// =============
	// relay env var
	// =============
	dst.Spec.EnableStdOutLogs, _ = strconv.ParseBool(src.Spec.KubeArmorRelay.EnableStdOutLogs)
	dst.Spec.EnableStdOutAlerts, _ = strconv.ParseBool(src.Spec.KubeArmorRelay.EnableStdOutAlerts)
	dst.Spec.EnableStdOutMsgs, _ = strconv.ParseBool(src.Spec.KubeArmorRelay.EnableStdOutMsg)
	dst.ObjectMeta = src.ObjectMeta
	return nil
}

// parseImage parses a image string into registry, repository, and tag.
func parseImage(image string) (string, string, string) {
	// Split the image string into parts
	var registry, repo, tag string

	// Split image by ':'
	parts := strings.Split(image, ":")
	if len(parts) > 2 {
		// Invalid format if there are more than two parts
		return "", "", ""
	}

	// Extract tag if present
	if len(parts) == 2 {
		tag = parts[1]
		image = parts[0]
	} else {
		tag = ""
	}

	// Split image by '/'
	imageParts := strings.Split(image, "/")

	// Handle cases with multiple slashes
	if len(imageParts) > 1 {
		// The last part is the repository
		repo = imageParts[len(imageParts)-1]

		// The registry is everything before the last part
		registry = strings.Join(imageParts[:len(imageParts)-1], "/")
	} else {
		// Handle case with no slashes (assume it is just a repository)
		repo = imageParts[0]
		registry = ""
	}

	// Return results
	return registry, repo, tag
}

// createImage generates image string from registry, repository, and tag.
func createImage(registry, repo, tag string) string {
	// Construct the image string
	var imageBuilder strings.Builder

	if registry != "" {
		imageBuilder.WriteString(registry)
		imageBuilder.WriteString("/")
	}
	imageBuilder.WriteString(repo)
	if tag != "" {
		imageBuilder.WriteString(":")
		imageBuilder.WriteString(tag)
	}

	return imageBuilder.String()
}
