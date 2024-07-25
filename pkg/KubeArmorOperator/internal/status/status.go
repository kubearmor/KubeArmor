// SPDX-License-Identifier: Apache-2.0
// Copyright 2022 Authors of KubeArmor

package status

import (
	"context"
	"fmt"

	operatorv2 "github.com/kubearmor/KubeArmor/pkg/KubeArmorOperator/api/operator.kubearmor.com/v2"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/util/retry"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

const (
	// condition types
	TypeInitialized     = "Initialized"
	TypeReleaseDeployed = "ReleaseDeployed"
	TypeReleaseFailed   = "ReleaseFailed"
	TypeIrrecoverable   = "Irrecoverable"

	// condition reasons
	ReasonErrorUpdatingHelmValues         = "ErrorUpdatingHelmValues"
	ReasonSuccessfulInstallationOrUpgrade = "InstallationOrUpgradeSuccessful"
	ReasonSuccessfulInstallation          = "InstalationSuccessful"
	ReasonSuccessfulUpgrade               = "UpgradeSuccessful"
	ReasonSuccessfulUninstallation        = "UninstallationSuccessful"
	ReasonInstallationError               = "InstallationError"
	ReasonUpgradeError                    = "UpgradeError"
	ReasonUninstallationError             = "UninstallationError"
	ReasonReconcileError                  = "ReconcileError"
)

func InitializedCondition(status metav1.ConditionStatus, reason, message string) metav1.Condition {
	return metav1.Condition{
		Type:    TypeInitialized,
		Status:  status,
		Reason:  reason,
		Message: message,
	}
}

func DeployedCondition(status metav1.ConditionStatus, reason, message string) metav1.Condition {
	return metav1.Condition{
		Type:    TypeReleaseDeployed,
		Status:  status,
		Reason:  reason,
		Message: message,
	}
}

func FailedCondition(status metav1.ConditionStatus, reason, message string) metav1.Condition {
	return metav1.Condition{
		Type:    TypeReleaseFailed,
		Status:  status,
		Reason:  reason,
		Message: message,
	}
}

func IrrecoverableCondition(status metav1.ConditionStatus, reason, message string) metav1.Condition {
	return metav1.Condition{
		Type:    TypeIrrecoverable,
		Status:  status,
		Reason:  reason,
		Message: message,
	}
}

func UpdateStatus(ctx context.Context, c client.Client, obj *operatorv2.KubeArmorConfig) error {
	fmt.Printf("updating status: %+v\n", obj.Status)
	return retry.RetryOnConflict(retry.DefaultRetry, func() error {
		current := &operatorv2.KubeArmorConfig{}
		if err := c.Get(ctx, client.ObjectKeyFromObject(obj), current); err != nil {
			fmt.Printf("error getting cr for status updation: %s\n", err.Error())
			return err
		}
		current.Status = obj.Status
		err := c.Status().Update(ctx, current)
		if err != nil {
			fmt.Printf("error updating status: %s\n", err.Error())
			return err
		}
		fmt.Println("successfully updated status")
		updated := &operatorv2.KubeArmorConfig{}
		if err := c.Get(ctx, client.ObjectKeyFromObject(current), updated); err == nil {
			fmt.Printf("status of updated CR: %+v", updated.Status)
		} else {
			fmt.Printf("error getting updated cr: %s\n", err.Error())
		}

		return nil
		// return c.Status().Update(ctx, current)
	})
}
