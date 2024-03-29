// SPDX-License-Identifier: Apache-2.0
// Copyright 2022 Authors of KubeArmor

// Code generated by informer-gen. DO NOT EDIT.

package v1

import (
	"context"
	time "time"

	securitykubearmorcomv1 "github.com/kubearmor/KubeArmor/pkg/KubeArmorController/api/security.kubearmor.com/v1"
	versioned "github.com/kubearmor/KubeArmor/pkg/KubeArmorController/client/clientset/versioned"
	internalinterfaces "github.com/kubearmor/KubeArmor/pkg/KubeArmorController/client/informers/externalversions/internalinterfaces"
	v1 "github.com/kubearmor/KubeArmor/pkg/KubeArmorController/client/listers/security.kubearmor.com/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	runtime "k8s.io/apimachinery/pkg/runtime"
	watch "k8s.io/apimachinery/pkg/watch"
	cache "k8s.io/client-go/tools/cache"
)

// KubeArmorPolicyInformer provides access to a shared informer and lister for
// KubeArmorPolicies.
type KubeArmorPolicyInformer interface {
	Informer() cache.SharedIndexInformer
	Lister() v1.KubeArmorPolicyLister
}

type kubeArmorPolicyInformer struct {
	factory          internalinterfaces.SharedInformerFactory
	tweakListOptions internalinterfaces.TweakListOptionsFunc
	namespace        string
}

// NewKubeArmorPolicyInformer constructs a new informer for KubeArmorPolicy type.
// Always prefer using an informer factory to get a shared informer instead of getting an independent
// one. This reduces memory footprint and number of connections to the server.
func NewKubeArmorPolicyInformer(client versioned.Interface, namespace string, resyncPeriod time.Duration, indexers cache.Indexers) cache.SharedIndexInformer {
	return NewFilteredKubeArmorPolicyInformer(client, namespace, resyncPeriod, indexers, nil)
}

// NewFilteredKubeArmorPolicyInformer constructs a new informer for KubeArmorPolicy type.
// Always prefer using an informer factory to get a shared informer instead of getting an independent
// one. This reduces memory footprint and number of connections to the server.
func NewFilteredKubeArmorPolicyInformer(client versioned.Interface, namespace string, resyncPeriod time.Duration, indexers cache.Indexers, tweakListOptions internalinterfaces.TweakListOptionsFunc) cache.SharedIndexInformer {
	return cache.NewSharedIndexInformer(
		&cache.ListWatch{
			ListFunc: func(options metav1.ListOptions) (runtime.Object, error) {
				if tweakListOptions != nil {
					tweakListOptions(&options)
				}
				return client.SecurityV1().KubeArmorPolicies(namespace).List(context.TODO(), options)
			},
			WatchFunc: func(options metav1.ListOptions) (watch.Interface, error) {
				if tweakListOptions != nil {
					tweakListOptions(&options)
				}
				return client.SecurityV1().KubeArmorPolicies(namespace).Watch(context.TODO(), options)
			},
		},
		&securitykubearmorcomv1.KubeArmorPolicy{},
		resyncPeriod,
		indexers,
	)
}

func (f *kubeArmorPolicyInformer) defaultInformer(client versioned.Interface, resyncPeriod time.Duration) cache.SharedIndexInformer {
	return NewFilteredKubeArmorPolicyInformer(client, f.namespace, resyncPeriod, cache.Indexers{cache.NamespaceIndex: cache.MetaNamespaceIndexFunc}, f.tweakListOptions)
}

func (f *kubeArmorPolicyInformer) Informer() cache.SharedIndexInformer {
	return f.factory.InformerFor(&securitykubearmorcomv1.KubeArmorPolicy{}, f.defaultInformer)
}

func (f *kubeArmorPolicyInformer) Lister() v1.KubeArmorPolicyLister {
	return v1.NewKubeArmorPolicyLister(f.Informer().GetIndexer())
}
