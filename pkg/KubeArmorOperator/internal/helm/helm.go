// SPDX-License-Identifier: Apache-2.0
// Copyright 2022 Authors of KubeArmor

// Package helm ...
package helm

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path"
	"strings"
	"sync"
	"time"

	"go.uber.org/zap"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/discovery/cached/memory"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/restmapper"
	"sigs.k8s.io/yaml"

	semver "github.com/Masterminds/semver/v3"
	operatorv2 "github.com/kubearmor/KubeArmor/pkg/KubeArmorOperator/api/operator.kubearmor.com/v2"
	"github.com/kubearmor/KubeArmor/pkg/KubeArmorOperator/common"
	embedFs "github.com/kubearmor/KubeArmor/pkg/KubeArmorOperator/embed"
	"helm.sh/helm/v3/pkg/action"
	"helm.sh/helm/v3/pkg/chart"
	"helm.sh/helm/v3/pkg/chart/loader"
	"helm.sh/helm/v3/pkg/cli"
	"helm.sh/helm/v3/pkg/registry"
	"helm.sh/helm/v3/pkg/release"
	"helm.sh/helm/v3/pkg/releaseutil"
	"helm.sh/helm/v3/pkg/storage/driver"
)

var (
	settings  = cli.New()
	logger, _ = zap.NewProduction()
	log       = logger.With(zap.String("component", "helmController")).Sugar()
)

// Config provides configurations to initialize a helm controller instance
type Config struct {
	// chartRef or chart name
	ChartName string
	// namespace to deploy chart
	Namespace string
	// chart version to install
	Version string
	// chart repository
	Repository string
	// chart directory if local chart
	Directory string
	// rollaback in case of install/upgrade failure
	RollbackOnFailure bool
}

// Controller contains helm chart configurations
type Controller struct {
	// configuration for helm clients i.e. install,upgrade,list, etc.
	actionConfig *action.Configuration
	// mutex to avoid race conditions
	mutex sync.Mutex
	// Helm release chartName
	chartName string
	// Helm release namespace
	namespace string
	// rollaback in case of install/upgrade failure
	rollbackOnFailure bool
	// Helm chart
	chart *chart.Chart
	// Helm values generated using kubearmorconfig instance
	kaConfigValues map[string]interface{}
	// Helm values generated using node configuration
	nodeConfigValues map[string]interface{}
}

// NewHelmController creates an instance of helm controller using provided configurations
// and return it on successful initialization otherwise returns an error
func NewHelmController(cfg Config) (*Controller, error) {
	actionConfig := new(action.Configuration)
	err := actionConfig.Init(settings.RESTClientGetter(), cfg.Namespace, os.Getenv("HELM_DRIVER"), log.Infof)
	if err != nil {
		return nil, fmt.Errorf("error initializing helm action config: %s", err.Error())
	}
	chart, err := getHelmChart(actionConfig, cfg.Repository, cfg.Version, cfg.Directory, cfg.ChartName)
	if err != nil {
		return nil, fmt.Errorf("error pulling helm chart: %s", err.Error())
	}

	log.Infof("helm controller has configured: %+v", cfg)

	return &Controller{
		actionConfig:      actionConfig,
		mutex:             sync.Mutex{},
		chartName:         cfg.ChartName,
		namespace:         cfg.Namespace,
		chart:             chart,
		rollbackOnFailure: cfg.RollbackOnFailure,
		kaConfigValues:    map[string]interface{}{},
		nodeConfigValues:  map[string]interface{}{},
	}, nil
}

type resource struct {
	kind  string
	name  string
	group string
}

// UpdateHelmValuesFromKubeArmorConfig function merge helm values with new values
// defined with kubearmorconfig instance
func (ctrl *Controller) UpdateHelmValuesFromKubeArmorConfig(kaConfig *operatorv2.KubeArmorConfig) error {
	kaConfigHelmValues := map[string]interface{}{}

	jsonBytes, err := json.Marshal(kaConfig.Spec)
	if err != nil {
		return err
	}

	err = json.Unmarshal(jsonBytes, &kaConfigHelmValues)
	if err != nil {
		return err
	}

	ctrl.kaConfigValues = kaConfigHelmValues
	return nil
}

func (ctrl *Controller) UpdateNodeConfigHelmValues(nodeConfig []map[string]interface{}) {
	ctrl.nodeConfigValues = map[string]interface{}{
		"nodes": nodeConfig,
	}
}

func pullHelmChartFromOCIRegistry(actionConfig *action.Configuration, repository, version, chart, targetDir string) (*chart.Chart, error) {
	// create a temp subdirectory to pull helm chart
	file := path.Join(targetDir, fmt.Sprintf("%s-%s.tgz", chart, version))
	actionCfg := &action.Configuration{}
	pull := action.NewPullWithOpts(action.WithConfig(actionConfig))
	pull.Settings = settings
	pull.Version = version
	pull.DestDir = targetDir
	// in case of private registries ??
	client, err := registry.NewClient()
	if err != nil {
		return nil, err
	}
	actionCfg.RegistryClient = client
	_, err = pull.Run(repository)
	if err != nil {
		return nil, err
	}
	// load pulled helm chart from archieve file
	return loader.Load(file)
}

// getHelmChart pull helm chart from given helm parameters
func getHelmChart(actionConfig *action.Configuration, repository, version, directory, chartName string) (*chart.Chart, error) {
	// TODO: validate chart version ^v1.3.8
	// check if local helm chart is to be used
	if directory != "" {
		chart, err := loader.Load(directory)
		if err != nil {
			return nil, err
		}
		return chart, nil
	}

	if repository == "embed" {
		chartArchieve, err := embedFs.EmbedFs.ReadFile(fmt.Sprintf("%s-%s.tgz", chartName, version))
		if err != nil {
			return nil, err
		}
		return loader.LoadArchive(bytes.NewReader(chartArchieve))
	}

	// create a cache directory to store pulled helm chart
	targetDir := path.Join(os.TempDir(), "kubearmor", ".cache")
	err := os.MkdirAll(targetDir, 0755)
	if err != nil && !os.IsExist(err) {
		targetDir = "./"
	}

	if registry.IsOCI(repository) {
		return pullHelmChartFromOCIRegistry(actionConfig, repository, version, chartName, targetDir)
	}

	file := path.Join(targetDir, fmt.Sprintf("%s-%s.tgz", chartName, version))
	pull := action.NewPullWithOpts(action.WithConfig(actionConfig))
	pull.Settings = settings
	pull.Version = version
	pull.RepoURL = repository
	pull.DestDir = targetDir
	// pull chart
	_, err = pull.Run(chartName)
	if err != nil {
		log.Infof("error pulling helm chart: %s", err.Error())
		return nil, err
	}
	// load pulled helm chart from archieve file
	return loader.Load(file)
}

// checkIfCleanUpRequired check for recent two revisions of (if any) existing
// kubearmor-operator release and check if last installed version is <v1.3.8
func checkIfCleanUpRequired(actionConfig *action.Configuration) bool {
	v138, _ := semver.NewVersion("v1.3.8")
	histClient := action.NewHistory(actionConfig)
	release, err := histClient.Run("kubearmor-operator")
	if err != nil && err == driver.ErrReleaseNotFound {
		return false
	}
	releaseutil.SortByRevision(release)
	for _, rel := range release {
		ver, _ := semver.NewVersion(rel.Chart.Metadata.Version)
		if ver.Equal(v138) {
			continue
		} else if ver.LessThan(v138) {
			return true
		} else if ver.GreaterThan(v138) {
			return false
		}
	}
	return false
}

func (ctrl *Controller) UninstallRelease() error {
	uninstallClient := action.NewUninstall(ctrl.actionConfig)
	_, err := uninstallClient.Run(ctrl.chartName)
	if err != nil && err != driver.ErrReleaseNotFound {
		return err
	}
	return nil
}

func removeManifestHeader(manifest string) string {
	var cleanedLines []string
	lines := strings.Split(manifest, "\n")
	for _, line := range lines {
		trimmedLine := strings.TrimSpace(line)
		if trimmedLine == "" || strings.HasPrefix(trimmedLine, "#") {
			continue
		}
		cleanedLines = append(cleanedLines, line)
	}
	// log.Infof("resource after header removed: \n%s\n", strings.Join(cleanedLines, "\n"))
	return strings.Join(cleanedLines, "\n")
}

func (ctrl *Controller) cleanUpResources(ctx context.Context, actionConfig *action.Configuration) ([]resource, error) {
	installClient := action.NewInstall(actionConfig)
	installClient.Namespace = ctrl.namespace
	installClient.ReleaseName = ctrl.chartName
	installClient.ClientOnly = true
	installClient.DryRun = true

	rel, _ := installClient.RunWithContext(ctx, ctrl.chart, map[string]interface{}{})
	var resources []resource
	if rel != nil {
		manifests := releaseutil.SplitManifests(rel.Manifest)
		for _, manifest := range manifests {
			cleanManifest := removeManifestHeader(manifest)
			if strings.TrimSpace(cleanManifest) == "" {
				continue
			}
			u := unstructured.Unstructured{}
			jsonData, err := yaml.YAMLToJSON([]byte(cleanManifest))
			if err != nil {
				return nil, fmt.Errorf("error converting YAML to JSON: %v", err)
			}
			_, _, err = unstructured.UnstructuredJSONScheme.Decode([]byte(jsonData), nil, &u)
			if err != nil {
				return nil, fmt.Errorf("error decoding manifest: %v", err)
			}

			resources = append(resources, resource{
				kind:  u.GetKind(),
				name:  u.GetName(),
				group: u.GroupVersionKind().Group,
			})
		}
		log.Infof("list of resources to clean: %d\n", len(resources))
	}
	return resources, nil
}

// Preinstall checks if previous operator was older than v1.3.8, in that case it requires deleting the KubeArmor k8s
// resources to be deleted explicitly to avoid conflict between controller that manages resources as helm need to be
// the controller to manage KubeArmor k8s resources
func (ctrl *Controller) Preinstall() error {
	// err := actionConfig.Init(settings.RESTClientGetter(), ctrl.namespace, "", func(format string, v ...interface{}) {})
	// if err != nil {
	// 	log.Fatalf("error initializing action config: %s", err.Error())
	// }
	config, err := settings.RESTClientGetter().ToRESTConfig()
	if err != nil {
		return err
	}

	required := checkIfCleanUpRequired(ctrl.actionConfig)
	if !required {
		return nil
	}

	dynamicClient, err := dynamic.NewForConfig(config)
	if err != nil {
		return err
	}

	discoveryClient, err := settings.RESTClientGetter().ToDiscoveryClient()
	mapper := restmapper.NewDeferredDiscoveryRESTMapper(memory.NewMemCacheClient(discoveryClient))
	// there will be an issue if action config is being shared and install client runs with clientOnly flag
	// therefore a new instance of action config used here
	// Ref: https://github.com/helm/helm/issues/11463
	resources, err := ctrl.cleanUpResources(context.Background(), new(action.Configuration))
	if err != nil {
		log.Warnf("error getting resources: %s\n", err.Error())
		return err
	}
	for _, resource := range resources {
		mapping, err := mapper.RESTMapping(schema.GroupKind{Group: resource.group, Kind: resource.kind})
		if err != nil {
			log.Warnf("failed to get mapping to kind: %s: %s\n", resource.kind, err.Error())
			continue
		}

		switch resource.kind {
		// cannot delete CRDs i.e. ksp, hsp, add helm annotation
		case "CustomResourceDefinition":
			resourceClient := dynamicClient.Resource(mapping.Resource)
			helmAnnotations := fmt.Sprintf(`{"metadata": { "annotations": {"meta.helm.sh/release-name": "%s", "meta.helm.sh/release-namespace": "%s"},"labels": {"app.kubernetes.io/managed-by": "Helm"}}}`, ctrl.chartName, ctrl.namespace)
			patch := []byte(helmAnnotations)
			_, err = resourceClient.Patch(context.TODO(), resource.name, types.StrategicMergePatchType, patch, metav1.PatchOptions{})
			if err != nil && !errors.IsNotFound(err) {
				log.Warnf("failed to annotate %s %s %s", resource.kind, resource.name, err.Error())
				continue
			} else if err != nil {
				log.Infof("not found %s: %s\n", resource.kind, resource.name)
			}
			log.Infof("Successfully annotated %s: %s\n", resource.kind, resource.name)
		case "ClusterRole", "ClusterRoleBinding", "MutatingWebhookConfiguration":
			resourceClient := dynamicClient.Resource(mapping.Resource)
			err = resourceClient.Delete(context.TODO(), resource.name, metav1.DeleteOptions{})
			if err != nil && !errors.IsNotFound(err) {
				log.Warnf("failed to delete %s %s: %v", resource.kind, resource.name, err)
			} else if err != nil {
				log.Infof("not found %s: %s\n", resource.kind, resource.name)
			}
			log.Infof("Successfully deleted %s: %s\n", resource.kind, resource.name)
		default:
			resourceClient := dynamicClient.Resource(mapping.Resource).Namespace(ctrl.namespace)
			err = resourceClient.Delete(context.TODO(), resource.name, metav1.DeleteOptions{})
			if err != nil && !errors.IsNotFound(err) {
				log.Warnf("failed to delete %s %s: %v", resource.kind, resource.name, err)
			} else if err != nil {
				log.Infof("not found %s: %s\n", resource.kind, resource.name)
			}
			log.Infof("Successfully deleted %s: %s\n", resource.kind, resource.name)
		}
	}
	// === handle kubearmor daemonset and controller seperately ===

	// GVR for daemonsets
	dsGvr := schema.GroupVersionResource{
		Group:    "apps",
		Version:  "v1",
		Resource: "daemonsets",
	}
	daemonSetClient := dynamicClient.Resource(dsGvr).Namespace(ctrl.namespace)
	daemonSets, err := daemonSetClient.List(context.TODO(), metav1.ListOptions{
		LabelSelector: "kubearmor-app=kubearmor",
	})
	if err != nil {
		log.Warnf("failed to list kubearmor daemonsets error=%s", err.Error())

	} else {
		for _, ds := range daemonSets.Items {
			err := daemonSetClient.Delete(context.Background(), ds.GetName(), metav1.DeleteOptions{})
			if err != nil {
				log.Infof("error deleteing daemonset %s error=%s", ds.GetName(), err.Error())
				return err
			}
			log.Infof("Successfully deleted %s: %s\n", ds.GetKind(), ds.GetName())
		}
	}

	// GVR for deployments
	depGvr := schema.GroupVersionResource{
		Group:    "apps",
		Version:  "v1",
		Resource: "deployments",
	}
	deployClient := dynamicClient.Resource(depGvr).Namespace(ctrl.namespace)
	err = deployClient.Delete(context.Background(), "kubearmor-controller", metav1.DeleteOptions{})
	if err != nil && !errors.IsNotFound(err) {
		log.Warnf("failed to delete deployment kubearmor-controller %s", err.Error())
		return err
	}
	log.Infof("Successfully deleted %s: %s\n", "Deployment", "kubearmor-controller")
	return nil
}

func (ctrl *Controller) upgradeRequired(currentRelease *release.Release, newVals map[string]interface{}) bool {
	if currentRelease == nil {
		return true
	}
	actionConfig := new(action.Configuration)
	err := actionConfig.Init(settings.RESTClientGetter(), ctrl.namespace, os.Getenv("HELM_DRIVER"), log.Infof)
	if err != nil {
		log.Errorf("error initializing dry-run upgrade action config: %s", err.Error())
		return true
	}
	upgradeClient := action.NewUpgrade(actionConfig)
	upgradeClient.Namespace = ctrl.namespace
	upgradeClient.DryRunOption = "server"
	upgradeClient.DryRun = true

	rel, err := upgradeClient.Run(ctrl.chartName, ctrl.chart, newVals)
	if err != nil {
		return true
	}

	return rel.Manifest != currentRelease.Manifest ||
		currentRelease.Info.Status == release.StatusFailed ||
		currentRelease.Info.Status == release.StatusSuperseded
}

// UpgradeRelease performs helm upgrade for helm chart defined with configuration
func (ctrl *Controller) UpgradeRelease(ctx context.Context) (*release.Release, error) {
	ctrl.mutex.Lock()
	defer ctrl.mutex.Unlock()

	histClient := action.NewHistory(ctrl.actionConfig)
	release, err := histClient.Run(ctrl.chartName)

	var vals map[string]interface{}
	// kaConfigValues and nodeConfigValues are mutually exclusive maps
	// merging them don't have any risk of overridden values
	vals = mergeMaps(ctrl.kaConfigValues, ctrl.nodeConfigValues)
	// vals = mergeMaps(ctrl.chart.Values, vals)

	// pin images if configured
	// will help with deployment in marketplaces
	if pinnedImages := getPinnedImagesValuesMap(); pinnedImages != nil {
		vals = mergeMaps(vals, pinnedImages)
	}

	// Not a best way to sync between kubearmorconfig reconiler and clusterwatcher
	// to check and deploy KubeArmor applications only if snitch detected node configuration
	// and kubearmoconfig CR instance has been detected
	if len(ctrl.kaConfigValues) < 1 || len(ctrl.nodeConfigValues) < 1 {
		return nil, fmt.Errorf("either nodes are not processed or kubearmorconfig CR instance not present")
	}

	log.Infof("helm values: %v", vals)

	if err != nil && err == driver.ErrReleaseNotFound {
		log.Infoln("no existing kubearmor release installing now")
		// release not found install release
		installClient := action.NewInstall(ctrl.actionConfig)
		if installClient == nil {
			return nil, fmt.Errorf("unable to create install client")
		}
		installClient.Namespace = ctrl.namespace
		installClient.ReleaseName = ctrl.chartName
		installClient.ClientOnly = false
		installClient.DryRun = false
		installClient.Wait = true
		installClient.Timeout = 5 * time.Minute
		// installClient.Atomic = true
		rel, err := installClient.RunWithContext(context.TODO(), ctrl.chart, vals)
		if err != nil {
			msg := fmt.Sprintf("failed to install release %s", ctrl.chartName)
			return nil, &InstallError{msg: msg, err: err.Error()}
		}
		return rel, nil
		// return installClient.Run(ctrl.chart, vals)
	}
	releaseutil.SortByRevision(release)
	log.Infoln("found existing kubearmor release upgrading now")
	if release[0].Info.Status.IsPending() {
		return nil, fmt.Errorf("previous release status is in pending state %s", release[0].Info.Status)
	}

	if !ctrl.upgradeRequired(release[0], vals) {
		log.Infoln("upgrade required")
		return release[0], nil
	}

	upgradeClient := action.NewUpgrade(ctrl.actionConfig)
	// upgradeClient.Atomic = true
	// upgradeClient.ResetValues = true
	upgradeClient.Wait = true
	upgradeClient.Timeout = 5 * time.Minute
	upgradeClient.Namespace = ctrl.namespace
	rel, err := upgradeClient.RunWithContext(context.TODO(), ctrl.chartName, ctrl.chart, vals)
	if err != nil {
		if ctrl.rollbackOnFailure {
			log.Warnf("performing rollback! due to failed upgrade error: %s")
			rollbackClient := action.NewRollback(ctrl.actionConfig)
			rollbackClient.Force = true
			err := rollbackClient.Run(ctrl.chartName)
			if err != nil {
				msg := fmt.Sprintf("failed to rollback after failed to upgrade %s release ", ctrl.chartName)
				return nil, &UpgradeError{msg: msg, err: err.Error()}
			}
			return release[0], nil // release??
		}
		msg := fmt.Sprintf("failed to upgrade release %s", ctrl.chartName)
		return nil, &UpgradeError{msg: msg, err: err.Error()}
	}
	return rel, nil
}

// mergeMaps
// https://pkg.go.dev/helm.sh/helm/v3@v3.15.2/pkg/cli/values#Options.MergeValues
func mergeMaps(a, b map[string]interface{}) map[string]interface{} {
	out := make(map[string]interface{}, len(a))
	for k, v := range a {
		out[k] = v
	}
	for k, v := range b {
		if v, ok := v.(map[string]interface{}); ok {
			if bv, ok := out[k]; ok {
				if bv, ok := bv.(map[string]interface{}); ok {
					out[k] = mergeMaps(bv, v)
					continue
				}
			}
		}
		out[k] = v
	}
	return out
}

func getPinnedImagesValuesMap() map[string]interface{} {

	vals := map[string]interface{}{}
	pinned := false

	vals["globalRegistry"] = ""
	vals["useGlobalRegistryForVendorImages"] = false

	if image := os.Getenv("RELATED_IMAGE_KUBEARMOR"); image != "" {
		pinned = true
		reg, repo, tag := common.ParseImage(image)
		vals["kubearmor"] = map[string]interface{}{
			"image": map[string]interface{}{
				"registry":   reg,
				"repository": repo,
				"tag":        tag,
			},
		}
	}

	if image := os.Getenv("RELATED_IMAGE_KUBEARMOR_INIT"); image != "" {
		pinned = true
		reg, repo, tag := common.ParseImage(image)
		vals["kubearmorInit"] = map[string]interface{}{
			"image": map[string]interface{}{
				"registry":   reg,
				"repository": repo,
				"tag":        tag,
			},
		}
	}

	if image := os.Getenv("RELATED_IMAGE_KUBEARMOR_RELAY_SERVER"); image != "" {
		pinned = true
		reg, repo, tag := common.ParseImage(image)
		vals["kubearmorRelay"] = map[string]interface{}{
			"image": map[string]interface{}{
				"registry":   reg,
				"repository": repo,
				"tag":        tag,
			},
		}
	}

	if image := os.Getenv("RELATED_IMAGE_KUBEARMOR_CONTROLLER"); image != "" {
		pinned = true
		reg, repo, tag := common.ParseImage(image)
		vals["kubearmorController"] = map[string]interface{}{
			"image": map[string]interface{}{
				"registry":   reg,
				"repository": repo,
				"tag":        tag,
			},
		}
	}

	if image := os.Getenv("RELATED_IMAGE_KUBE_RBAC_PROXY"); image != "" {
		pinned = true
		reg, repo, tag := common.ParseImage(image)
		vals["kubeRbacProxy"] = map[string]interface{}{
			"image": map[string]interface{}{
				"registry":   reg,
				"repository": repo,
				"tag":        tag,
			},
		}
	}

	if !pinned {
		return nil
	}

	return vals
}
