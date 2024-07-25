// SPDX-License-Identifier: Apache-2.0
// Copyright 2022 Authors of KubeArmor

package controller

import (
	"context"
	"fmt"
	"reflect"
	"slices"
	"time"

	operatorv2 "github.com/kubearmor/KubeArmor/pkg/KubeArmorOperator/api/operator.kubearmor.com/v2"
	helm "github.com/kubearmor/KubeArmor/pkg/KubeArmorOperator/internal/helm"
	"github.com/kubearmor/KubeArmor/pkg/KubeArmorOperator/internal/status"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/util/retry"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	ctrlutil "sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
)

const (
	kubearmorConfigFinalizer = "kubearmorconfig.operator.kubearmor.com"
)

// KubeArmorConfigReconciler reconciles a KubeArmorConfig object
type KubeArmorConfigReconciler struct {
	helmController *helm.Controller
	client.Client
	Scheme *runtime.Scheme
}

//+kubebuilder:rbac:groups=operator.kubearmor.com,resources=kubearmorconfigs,verbs=get;list;watch;create;update;patch;delete
//+kubebuilder:rbac:groups=operator.kubearmor.com,resources=kubearmorconfigs/status,verbs=get;update;patch
//+kubebuilder:rbac:groups=operator.kubearmor.com,resources=kubearmorconfigs/finalizers,verbs=update

// Reconcile is part of the main kubernetes reconciliation loop which aims to
// move the current state of the cluster closer to the desired state.
// TODO(user): Modify the Reconcile function to compare the state specified by
// the KubeArmorConfig object against the actual cluster state, and then
// perform operations to make the cluster state reflect the state specified by
// the user.
//
// For more details, check Reconcile and its Result here:
// - https://pkg.go.dev/sigs.k8s.io/controller-runtime@v0.16.3/pkg/reconcile
func (r *KubeArmorConfigReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	logger := log.FromContext(ctx)
	logger.Info("Reconcilation triggered")
	config := &operatorv2.KubeArmorConfig{}
	// TODO(user): your logic here
	err := r.Get(ctx, req.NamespacedName, config)
	if err != nil {
		if client.IgnoreNotFound(err) == nil {
			logger.Info("CR instance %s/%s not found, nothing to do", req.Namespace, req.Namespace)
		}
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	// TODO: add finalizer if not present
	if config.GetDeletionTimestamp().IsZero() && !slices.Contains(config.GetFinalizers(), kubearmorConfigFinalizer) {
		logger.Info("adding finalizer")
		ctrlutil.AddFinalizer(config, kubearmorConfigFinalizer)
		if err := r.Update(ctx, config); err != nil {
			// failed to add finalizer
			return ctrl.Result{}, fmt.Errorf("error while adding finalizer to %s/%s", config.GetNamespace(), config.GetName())
		}
	}

	if !config.GetDeletionTimestamp().IsZero() {
		logger.Info("CR deleted cleaning up resources")
		// kubearmorconfig CR instance has been deleted
		// check if (kubearmorconfig) finalizer is present
		if slices.Contains(config.GetFinalizers(), kubearmorConfigFinalizer) {
			// handle resource cleanup => uninstall kubearmor release
			// ensure that deletion take place first, then update status, and then update the object itself
			err := r.helmController.UninstallRelease()
			if err != nil {
				logger.Info("error while uninstalling release", "error", err.Error())
				// update status
				config.Status.SetCondition(status.FailedCondition(metav1.ConditionTrue, status.ReasonUninstallationError, err.Error()))
				config.Status.SetCondition(status.IrrecoverableCondition(metav1.ConditionTrue, status.ReasonReconcileError, err.Error()))
				return ctrl.Result{}, status.UpdateStatus(ctx, r.Client, config)
			} else {
				logger.Info("successfully uninstalled release")
				config.Status.SetCondition(status.FailedCondition(metav1.ConditionFalse, status.ReasonSuccessfulUninstallation, ""))
				config.Status.SetCondition(status.DeployedCondition(metav1.ConditionFalse, status.ReasonSuccessfulUninstallation, ""))
				err := status.UpdateStatus(ctx, r.Client, config)
				if err == nil {
					return ctrl.Result{}, r.updateWithRetry(ctx, r.Client, config, func(o client.Object) {
						ctrlutil.RemoveFinalizer(o, kubearmorConfigFinalizer)
					})
				}
				return ctrl.Result{}, err
			}
		} else {
			// log success message
			logger.Info("no finalizer present, nothing to do")
			return ctrl.Result{}, nil
		}
	}

	defer func() {
		logger.Info("status update deferred triggered")
		statusUpdateErr := status.UpdateStatus(ctx, r.Client, config)
		if err == nil && statusUpdateErr != nil {
			err = client.IgnoreNotFound(statusUpdateErr)
		}
	}()

	// update helm values from KubeArmorConfig CR instance
	// do helm upgrade
	logger.Info("upgrading release with kubearmorconfig changes")
	err = r.helmController.UpdateHelmValuesFromKubeArmorConfig(config)
	if err != nil {
		config.Status.SetCondition(status.IrrecoverableCondition(metav1.ConditionTrue, status.ReasonErrorUpdatingHelmValues, err.Error()))
		config.Status.SetCondition(status.FailedCondition(metav1.ConditionUnknown, status.ReasonErrorUpdatingHelmValues, ""))
		return ctrl.Result{}, nil
	}
	release, err := r.helmController.UpgradeRelease(context.TODO())
	if err != nil {
		switch err.(type) {
		case *helm.InstallError:
			config.Status.SetCondition(status.DeployedCondition(metav1.ConditionFalse, status.ReasonInstallationError, ""))
			config.Status.SetCondition(status.FailedCondition(metav1.ConditionTrue, status.ReasonInstallationError, err.Error()))
		case *helm.UpgradeError:
			config.Status.SetCondition(status.FailedCondition(metav1.ConditionTrue, status.ReasonUpgradeError, err.Error()))
		}
		if helm.IsReconcilableError(err) {
			fmt.Println("requeue after a minute")
			config.Status.SetCondition(status.IrrecoverableCondition(metav1.ConditionFalse, status.ReasonReconcileError, err.Error()))
			return ctrl.Result{RequeueAfter: 1 * time.Minute}, nil
		}
		config.Status.SetCondition(status.IrrecoverableCondition(metav1.ConditionTrue, status.ReasonReconcileError, err.Error()))
		return ctrl.Result{}, nil
	}
	logger.Info("successfully upgraded release", "name", release.Name, "version", release.Version)
	logger.Info("release status info", "status", release.Info.Status, "chartVersion", release.Chart.Metadata.Version)
	if release != nil && release.Version > 1 {
		config.Status.SetCondition(status.DeployedCondition(metav1.ConditionTrue, status.ReasonSuccessfulUpgrade, "release has been succesfully upgraded"))
	} else {
		config.Status.SetCondition(status.DeployedCondition(metav1.ConditionTrue, status.ReasonSuccessfulInstallation, "release has been succesfully installed"))
	}
	config.Status.SetCondition(status.FailedCondition(metav1.ConditionFalse, status.ReasonSuccessfulInstallationOrUpgrade, ""))
	logger.Info("Reconcile completed")
	return ctrl.Result{}, nil
}

func (r *KubeArmorConfigReconciler) updateWithRetry(ctx context.Context, c client.Client, obj client.Object, updateFunc func(client.Object)) error {
	return retry.RetryOnConflict(retry.DefaultRetry, func() error {
		current := obj.DeepCopyObject().(client.Object)
		if err := c.Get(ctx, client.ObjectKeyFromObject(obj), current); err != nil {
			return err
		}
		// update object
		updateFunc(current)

		return c.Update(ctx, current)
	})
}

// SetupWithManager sets up the controller with the Manager.
func (r *KubeArmorConfigReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&operatorv2.KubeArmorConfig{}).
		WithEventFilter(predicate.Funcs{
			UpdateFunc: func(ue event.UpdateEvent) bool {
				oldConfig := ue.ObjectOld.(*operatorv2.KubeArmorConfig)
				newConfig := ue.ObjectNew.(*operatorv2.KubeArmorConfig)
				return !reflect.DeepEqual(oldConfig.Spec, newConfig.Spec) || oldConfig.GetDeletionTimestamp() != newConfig.GetDeletionTimestamp()
			},
		}).
		Complete(r)
}
