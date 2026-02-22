// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Authors of KubeArmor

package monitor

import (
	"bytes"
	"errors"
	"fmt"
	"hash/fnv"
	"os"
	"strconv"
	"strings"
	"time"

	tp "github.com/kubearmor/KubeArmor/KubeArmor/types"
)

const (
	batchAuditMaxPathLen           = 200
	batchAuditBufSize              = 32768
	batchAuditSampleSize           = batchAuditBufSize * 2
	batchAuditFallbackPollInterval = 60

	batchAuditRuleExec      uint16 = 1 << 0
	batchAuditRuleWrite     uint16 = 1 << 1
	batchAuditRuleRead      uint16 = 1 << 2
	batchAuditRuleOwner     uint16 = 1 << 3
	batchAuditRuleDir       uint16 = 1 << 4
	batchAuditRuleRecursive uint16 = 1 << 5
)

type batchAuditPath struct {
	Path   [batchAuditMaxPathLen]byte
	Source [batchAuditMaxPathLen]byte
}

type batchAuditPolicyKey struct {
	Okey  NsKey
	Paths batchAuditPath
}

type batchAuditPolicyVal struct {
	PolicyHash  uint64
	ProcessMask uint16
	FileMask    uint16
	Pad         uint32
}

type batchAuditAggregationKey struct {
	PolicyHash uint64
	EventHash  uint64
}

type batchAuditAggregationVal struct {
	Count           uint64
	LastSeen        uint64
	EntrySampleSize uint32
	RetSampleSize   uint32
	SampleData      [batchAuditSampleSize]byte
}

type batchAuditPolicyMeta struct {
	PolicyName      string
	Namespace       string
	Severity        int
	Tags            []string
	Message         string
	IntervalSeconds int32
}

type batchAuditDecodedSample struct {
	Ctx    SyscallContext
	Args   []any
	Hashes HashContext
}

func copyStringToArray(dst []byte, src string) {
	if len(dst) == 0 {
		return
	}
	copy(dst, []byte(src))
	if len(src) < len(dst) {
		dst[len(src)] = 0
	}
}

func normalizeBatchAuditDir(dir string) string {
	if dir == "" {
		return dir
	}
	if strings.HasSuffix(dir, "/") {
		return dir
	}
	return dir + "/"
}

func batchAuditPolicyHash(kind, namespace, name string) uint64 {
	h := fnv.New64a()
	_, _ = h.Write([]byte(kind + "/" + namespace + "/" + name))
	return h.Sum64()
}

func (mon *SystemMonitor) updateBatchAuditPolicyRule(ns NsKey, path, source string, processMask, fileMask uint16, policyHash uint64) {
	if mon.BatchAuditPolicyMap == nil || path == "" {
		return
	}

	key := batchAuditPolicyKey{Okey: ns}
	copyStringToArray(key.Paths.Path[:], path)
	copyStringToArray(key.Paths.Source[:], source)

	val := batchAuditPolicyVal{
		PolicyHash:  policyHash,
		ProcessMask: processMask,
		FileMask:    fileMask,
	}
	if err := mon.BatchAuditPolicyMap.Put(key, val); err != nil {
		mon.Logger.Warnf("failed to update batch audit rule map for path=%s source=%s: %s", path, source, err)
	}
}

func (mon *SystemMonitor) deleteBatchAuditPolicyEntriesForNs(ns NsKey) {
	if mon.BatchAuditPolicyMap == nil {
		return
	}

	it := mon.BatchAuditPolicyMap.Iterate()
	var key batchAuditPolicyKey
	var val batchAuditPolicyVal
	var keys []batchAuditPolicyKey

	for it.Next(&key, &val) {
		if key.Okey == ns {
			keys = append(keys, key)
		}
	}

	for _, k := range keys {
		if err := mon.BatchAuditPolicyMap.Delete(k); err != nil && !errors.Is(err, os.ErrNotExist) {
			mon.Logger.Warnf("failed to delete batch audit rule map entry: %s", err)
		}
	}
}

func (mon *SystemMonitor) deleteBatchAuditPolicyEntriesForHash(policyHash uint64) {
	if mon.BatchAuditPolicyMap == nil {
		return
	}

	it := mon.BatchAuditPolicyMap.Iterate()
	var key batchAuditPolicyKey
	var val batchAuditPolicyVal
	var keys []batchAuditPolicyKey

	for it.Next(&key, &val) {
		if val.PolicyHash == policyHash {
			keys = append(keys, key)
		}
	}

	for _, k := range keys {
		if err := mon.BatchAuditPolicyMap.Delete(k); err != nil && !errors.Is(err, os.ErrNotExist) {
			mon.Logger.Warnf("failed to delete batch audit policy map entry by hash: %s", err)
		}
	}
}

func (mon *SystemMonitor) deleteBatchAuditAggregationsForPolicyHash(policyHash uint64) {
	if mon.BatchAuditAggMap == nil {
		return
	}

	it := mon.BatchAuditAggMap.Iterate()
	var key batchAuditAggregationKey
	var val batchAuditAggregationVal
	var keys []batchAuditAggregationKey

	for it.Next(&key, &val) {
		if key.PolicyHash == policyHash {
			keys = append(keys, key)
		}
	}

	for _, k := range keys {
		if err := mon.BatchAuditAggMap.Delete(k); err != nil && !errors.Is(err, os.ErrNotExist) {
			mon.Logger.Warnf("failed to delete batch audit aggregation map entry by hash: %s", err)
		}
	}
}

func (mon *SystemMonitor) syncBatchAuditMetadataWithMap() {
	if mon.BatchAuditPolicyMap == nil {
		return
	}

	activeHashes := map[uint64]struct{}{}
	mon.BpfMapLock.RLock()
	it := mon.BatchAuditPolicyMap.Iterate()
	var key batchAuditPolicyKey
	var val batchAuditPolicyVal
	for it.Next(&key, &val) {
		activeHashes[val.PolicyHash] = struct{}{}
	}
	mon.BpfMapLock.RUnlock()

	mon.BatchAuditStateLock.Lock()
	for hash := range mon.BatchAuditPolicies {
		if _, ok := activeHashes[hash]; !ok {
			delete(mon.BatchAuditPolicies, hash)
		}
	}
	mon.BatchAuditStateLock.Unlock()
}

func (mon *SystemMonitor) upsertBatchAuditPolicyMeta(hash uint64, meta batchAuditPolicyMeta) {
	mon.BatchAuditStateLock.Lock()
	mon.BatchAuditPolicies[hash] = meta
	mon.BatchAuditStateLock.Unlock()
}

func (mon *SystemMonitor) endpointNsKeys(endPoint tp.EndPoint) []NsKey {
	containers := *(mon.Containers)
	containersLock := *(mon.ContainersLock)

	nsSet := map[NsKey]struct{}{}
	containersLock.RLock()
	for _, cid := range endPoint.Containers {
		ctr, ok := containers[cid]
		if !ok {
			continue
		}
		ns := NsKey{PidNS: ctr.PidNS, MntNS: ctr.MntNS}
		nsSet[ns] = struct{}{}
	}
	containersLock.RUnlock()

	nsKeys := make([]NsKey, 0, len(nsSet))
	for ns := range nsSet {
		nsKeys = append(nsKeys, ns)
	}
	return nsKeys
}

type batchAuditPolicySpec struct {
	Kind            string
	Namespace       string
	PolicyName      string
	Process         tp.ProcessType
	File            tp.FileType
	Severity        int
	Tags            []string
	Message         string
	IntervalSeconds int32
}

func (mon *SystemMonitor) applyBatchAuditPolicySpec(ns NsKey, spec batchAuditPolicySpec) {
	policyHash := batchAuditPolicyHash(spec.Kind, spec.Namespace, spec.PolicyName)
	mon.upsertBatchAuditPolicyMeta(policyHash, batchAuditPolicyMeta{
		PolicyName:      spec.PolicyName,
		Namespace:       spec.Namespace,
		Severity:        spec.Severity,
		Tags:            spec.Tags,
		Message:         spec.Message,
		IntervalSeconds: spec.IntervalSeconds,
	})

	for _, path := range spec.Process.MatchPaths {
		mask := batchAuditRuleExec
		if path.OwnerOnly {
			mask |= batchAuditRuleOwner
		}

		rulePath := path.Path
		if path.ExecName != "" {
			rulePath = path.ExecName
		}

		if len(path.FromSource) == 0 {
			mon.updateBatchAuditPolicyRule(ns, rulePath, "", mask, 0, policyHash)
			continue
		}

		for _, src := range path.FromSource {
			mon.updateBatchAuditPolicyRule(ns, rulePath, src.Path, mask, 0, policyHash)
		}
	}

	for _, dir := range spec.Process.MatchDirectories {
		mask := batchAuditRuleExec | batchAuditRuleDir
		if dir.OwnerOnly {
			mask |= batchAuditRuleOwner
		}
		if dir.Recursive {
			mask |= batchAuditRuleRecursive
		}

		ruleDir := normalizeBatchAuditDir(dir.Directory)
		if len(dir.FromSource) == 0 {
			mon.updateBatchAuditPolicyRule(ns, ruleDir, "", mask, 0, policyHash)
			continue
		}

		for _, src := range dir.FromSource {
			mon.updateBatchAuditPolicyRule(ns, ruleDir, src.Path, mask, 0, policyHash)
		}
	}

	for _, path := range spec.File.MatchPaths {
		mask := batchAuditRuleRead
		if !path.ReadOnly {
			mask |= batchAuditRuleWrite
		}
		if path.OwnerOnly {
			mask |= batchAuditRuleOwner
		}

		if len(path.FromSource) == 0 {
			mon.updateBatchAuditPolicyRule(ns, path.Path, "", 0, mask, policyHash)
			continue
		}

		for _, src := range path.FromSource {
			mon.updateBatchAuditPolicyRule(ns, path.Path, src.Path, 0, mask, policyHash)
		}
	}

	for _, dir := range spec.File.MatchDirectories {
		mask := batchAuditRuleRead | batchAuditRuleDir
		if !dir.ReadOnly {
			mask |= batchAuditRuleWrite
		}
		if dir.OwnerOnly {
			mask |= batchAuditRuleOwner
		}
		if dir.Recursive {
			mask |= batchAuditRuleRecursive
		}

		ruleDir := normalizeBatchAuditDir(dir.Directory)
		if len(dir.FromSource) == 0 {
			mon.updateBatchAuditPolicyRule(ns, ruleDir, "", 0, mask, policyHash)
			continue
		}

		for _, src := range dir.FromSource {
			mon.updateBatchAuditPolicyRule(ns, ruleDir, src.Path, 0, mask, policyHash)
		}
	}
}

func (mon *SystemMonitor) applyBatchAuditPoliciesForNS(ns NsKey, policies []tp.SecurityPolicy) {
	mon.deleteBatchAuditPolicyEntriesForNs(ns)

	for _, secPolicy := range policies {
		if secPolicy.Spec.Action != "BatchAudit" {
			continue
		}

		mon.applyBatchAuditPolicySpec(ns, batchAuditPolicySpec{
			Kind:            "container",
			Namespace:       secPolicy.Metadata["namespaceName"],
			PolicyName:      secPolicy.Metadata["policyName"],
			Process:         secPolicy.Spec.Process,
			File:            secPolicy.Spec.File,
			Severity:        secPolicy.Spec.Severity,
			Tags:            secPolicy.Spec.Tags,
			Message:         secPolicy.Spec.Message,
			IntervalSeconds: secPolicy.Spec.BatchAudit.IntervalSeconds,
		})
	}
}

func (mon *SystemMonitor) applyBatchAuditHostPolicies(ns NsKey, policies []tp.HostSecurityPolicy) {
	mon.deleteBatchAuditPolicyEntriesForNs(ns)

	for _, secPolicy := range policies {
		if secPolicy.Spec.Action != "BatchAudit" {
			continue
		}

		mon.applyBatchAuditPolicySpec(ns, batchAuditPolicySpec{
			Kind:            "host",
			PolicyName:      secPolicy.Metadata["policyName"],
			Process:         secPolicy.Spec.Process,
			File:            secPolicy.Spec.File,
			Severity:        secPolicy.Spec.Severity,
			Tags:            secPolicy.Spec.Tags,
			Message:         secPolicy.Spec.Message,
			IntervalSeconds: secPolicy.Spec.BatchAudit.IntervalSeconds,
		})
	}
}

func (mon *SystemMonitor) UpdateBatchAuditPoliciesForEndpoint(endPoint tp.EndPoint) error {
	if mon.BatchAuditPolicyMap == nil {
		return nil
	}

	nsKeys := mon.endpointNsKeys(endPoint)
	if len(nsKeys) == 0 {
		return nil
	}

	mon.BpfMapLock.Lock()
	for _, ns := range nsKeys {
		mon.applyBatchAuditPoliciesForNS(ns, endPoint.SecurityPolicies)
	}
	mon.BpfMapLock.Unlock()

	mon.syncBatchAuditMetadataWithMap()
	return nil
}

func (mon *SystemMonitor) UpdateBatchAuditPoliciesForHost(secPolicies []tp.HostSecurityPolicy) error {
	if mon.BatchAuditPolicyMap == nil {
		return nil
	}

	hostNS := NsKey{PidNS: 0, MntNS: 0}
	mon.BpfMapLock.Lock()
	mon.applyBatchAuditHostPolicies(hostNS, secPolicies)
	mon.BpfMapLock.Unlock()

	mon.syncBatchAuditMetadataWithMap()
	return nil
}

func (mon *SystemMonitor) HandleBatchAuditPolicyDelete(secPolicy tp.SecurityPolicy) {
	if mon.BatchAuditPolicyMap == nil {
		return
	}
	if secPolicy.Spec.Action != "BatchAudit" {
		return
	}

	policyHash := batchAuditPolicyHash(
		"container",
		secPolicy.Metadata["namespaceName"],
		secPolicy.Metadata["policyName"],
	)

	mon.BpfMapLock.Lock()
	mon.deleteBatchAuditPolicyEntriesForHash(policyHash)
	mon.deleteBatchAuditAggregationsForPolicyHash(policyHash)
	mon.BpfMapLock.Unlock()

	mon.BatchAuditStateLock.Lock()
	delete(mon.BatchAuditPolicies, policyHash)
	mon.BatchAuditStateLock.Unlock()
}

func (mon *SystemMonitor) HandleBatchAuditHostPolicyDelete(secPolicy tp.HostSecurityPolicy) {
	if mon.BatchAuditPolicyMap == nil {
		return
	}
	if secPolicy.Spec.Action != "BatchAudit" {
		return
	}

	policyHash := batchAuditPolicyHash("host", "", secPolicy.Metadata["policyName"])

	mon.BpfMapLock.Lock()
	mon.deleteBatchAuditPolicyEntriesForHash(policyHash)
	mon.deleteBatchAuditAggregationsForPolicyHash(policyHash)
	mon.BpfMapLock.Unlock()

	mon.BatchAuditStateLock.Lock()
	delete(mon.BatchAuditPolicies, policyHash)
	mon.BatchAuditStateLock.Unlock()
}

func (mon *SystemMonitor) minBatchAuditInterval() time.Duration {
	mon.BatchAuditStateLock.RLock()
	defer mon.BatchAuditStateLock.RUnlock()

	if len(mon.BatchAuditPolicies) == 0 {
		return time.Duration(batchAuditFallbackPollInterval) * time.Second
	}

	min := int32(0)
	for _, meta := range mon.BatchAuditPolicies {
		if meta.IntervalSeconds <= 0 {
			continue
		}
		if min == 0 || meta.IntervalSeconds < min {
			min = meta.IntervalSeconds
		}
	}

	if min <= 0 {
		return time.Duration(batchAuditFallbackPollInterval) * time.Second
	}
	return time.Duration(min) * time.Second
}

func decodeBatchAuditSample(raw []byte) (batchAuditDecodedSample, error) {
	out := batchAuditDecodedSample{}
	buf := bytes.NewBuffer(raw)

	ctx, err := readContextFromBuff(buf)
	if err != nil {
		return out, err
	}
	out.Ctx = ctx

	args, err := GetArgs(buf, ctx.Argnum)
	if err != nil {
		return out, err
	}
	out.Args = args

	if ctx.Hash == uint8(1) {
		hashes, err := GetHashes(buf)
		if err != nil {
			return out, err
		}
		out.Hashes = hashes
	}

	return out, nil
}

func formatBatchAuditBaseLog(mon *SystemMonitor, sample batchAuditDecodedSample) tp.Log {
	containerID := ""
	if sample.Ctx.PidID != 0 && sample.Ctx.MntID != 0 {
		containerID = mon.LookupContainerID(sample.Ctx.PidID, sample.Ctx.MntID)
	}

	return mon.BuildLogBase(sample.Ctx.EventID, ContextCombined{
		ContainerID: containerID,
		ContextSys:  sample.Ctx,
		HashData:    sample.Hashes,
	}, true)
}

func formatBatchAuditEvent(log *tp.Log, entry batchAuditDecodedSample, ret *batchAuditDecodedSample) error {
	switch entry.Ctx.EventID {
	case SysOpen:
		if len(entry.Args) != 2 {
			return fmt.Errorf("invalid open args")
		}
		path, _ := entry.Args[0].(string)
		flags, _ := entry.Args[1].(string)
		log.Operation = "File"
		log.Resource = path
		log.Data = "syscall=" + GetSyscallName(entry.Ctx.EventID) + " flags=" + flags
	case SysOpenAt:
		if len(entry.Args) != 3 {
			return fmt.Errorf("invalid openat args")
		}
		fd, _ := entry.Args[0].(int32)
		path, _ := entry.Args[1].(string)
		flags, _ := entry.Args[2].(string)
		log.Operation = "File"
		log.Resource = path
		log.Data = "syscall=" + GetSyscallName(entry.Ctx.EventID) + " fd=" + strconv.Itoa(int(fd)) + " flags=" + flags
	case SysUnlink:
		if len(entry.Args) != 1 {
			return fmt.Errorf("invalid unlink args")
		}
		path, _ := entry.Args[0].(string)
		log.Operation = "File"
		log.Resource = path
		log.Data = "syscall=" + GetSyscallName(entry.Ctx.EventID)
	case SysUnlinkAt:
		if len(entry.Args) != 3 {
			return fmt.Errorf("invalid unlinkat args")
		}
		path, _ := entry.Args[1].(string)
		flags, _ := entry.Args[2].(string)
		log.Operation = "File"
		log.Resource = path
		log.Data = "syscall=" + GetSyscallName(entry.Ctx.EventID) + " flags=" + flags
	case SysRmdir:
		if len(entry.Args) != 1 {
			return fmt.Errorf("invalid rmdir args")
		}
		path, _ := entry.Args[0].(string)
		log.Operation = "File"
		log.Resource = path
		log.Data = "syscall=" + GetSyscallName(entry.Ctx.EventID)
	case SysChown:
		if len(entry.Args) != 3 {
			return fmt.Errorf("invalid chown args")
		}
		path, _ := entry.Args[0].(string)
		uid, _ := entry.Args[1].(int32)
		gid, _ := entry.Args[2].(int32)
		log.Operation = "File"
		log.Resource = path
		log.Data = "syscall=" + GetSyscallName(entry.Ctx.EventID) + " userid=" + strconv.Itoa(int(uid)) + " group=" + strconv.Itoa(int(gid))
	case SysFChownAt:
		if len(entry.Args) != 5 {
			return fmt.Errorf("invalid fchownat args")
		}
		path, _ := entry.Args[1].(string)
		uid, _ := entry.Args[2].(int32)
		gid, _ := entry.Args[3].(int32)
		mode, _ := entry.Args[4].(int32)
		log.Operation = "File"
		log.Resource = path
		log.Data = "syscall=" + GetSyscallName(entry.Ctx.EventID) + " userid=" + strconv.Itoa(int(uid)) + " group=" + strconv.Itoa(int(gid)) + " mode=" + strconv.Itoa(int(mode))
	case SysExecve:
		if len(entry.Args) != 2 {
			return fmt.Errorf("invalid execve args")
		}
		execPath, _ := entry.Args[0].(string)
		log.Operation = "Process"
		log.Resource = execPath
		if argv, ok := entry.Args[1].([]string); ok {
			for idx, arg := range argv {
				if idx == 0 {
					continue
				}
				log.Resource += " " + arg
			}
		}
		log.Data = "syscall=" + GetSyscallName(entry.Ctx.EventID)
	case SysExecveAt:
		if len(entry.Args) != 4 {
			return fmt.Errorf("invalid execveat args")
		}
		fd, _ := entry.Args[0].(int32)
		execPath, _ := entry.Args[1].(string)
		procExecFlag, _ := entry.Args[3].(string)
		log.Operation = "Process"
		log.Resource = execPath
		switch v := entry.Args[2].(type) {
		case []string:
			for idx, arg := range v {
				if idx == 0 {
					continue
				}
				log.Resource += " " + arg
			}
		case string:
			if v != "" {
				log.Resource += " " + v
			}
		}
		log.Data = "syscall=" + GetSyscallName(entry.Ctx.EventID) + " fd=" + strconv.Itoa(int(fd)) + " flag=" + procExecFlag
	default:
		return fmt.Errorf("unsupported event id for batch audit: %d", entry.Ctx.EventID)
	}

	retCtx := entry.Ctx
	if ret != nil {
		retCtx = ret.Ctx
	}

	log.Result = "Passed"
	if retCtx.Retval < 0 {
		msg := getErrorMessage(retCtx.Retval)
		log.Result = fmt.Sprintf("Unknown (%d)", retCtx.Retval)
		if msg != "" {
			log.Result = msg
		}
	}

	log.ExecEvent.ExecID = strconv.FormatUint(retCtx.ExecID, 10)
	if comm := strings.TrimRight(string(retCtx.Comm[:]), "\x00"); comm != "" {
		log.ExecEvent.ExecutableName = comm
	}

	return nil
}

func (mon *SystemMonitor) emitBatchAuditAlert(key batchAuditAggregationKey, val batchAuditAggregationVal) {
	entrySize := int(val.EntrySampleSize)
	retSize := int(val.RetSampleSize)
	if entrySize <= 0 || entrySize > len(val.SampleData) {
		return
	}

	entrySample, err := decodeBatchAuditSample(val.SampleData[:entrySize])
	if err != nil {
		mon.Logger.Warnf("failed to decode batch audit entry sample: %s", err)
		return
	}

	var retSample *batchAuditDecodedSample
	retRawPath := ""
	if retSize > 0 && entrySize+retSize <= len(val.SampleData) {
		rs, err := decodeBatchAuditSample(val.SampleData[entrySize : entrySize+retSize])
		if err == nil {
			retSample = &rs
		} else {
			raw := val.SampleData[entrySize : entrySize+retSize]
			if n := bytes.IndexByte(raw, 0); n >= 0 {
				raw = raw[:n]
			}
			retRawPath = strings.TrimRight(string(raw), "\x00")
		}
	}

	log := formatBatchAuditBaseLog(mon, entrySample)
	if err := formatBatchAuditEvent(&log, entrySample, retSample); err != nil {
		mon.Logger.Warnf("failed to format batch audit event: %s", err)
		return
	}
	if log.Operation == "File" && retRawPath != "" {
		log.ProcessName = retRawPath
	}
	if log.Source == "" {
		if log.ProcessName != "" {
			log.Source = log.ProcessName
		}
		if log.ParentProcessName != "" {
			log.Source = log.ParentProcessName
		}
	}
	if mon.isProcessInformationMissing(&log) {
		return
	}

	mon.BatchAuditStateLock.RLock()
	meta, ok := mon.BatchAuditPolicies[key.PolicyHash]
	mon.BatchAuditStateLock.RUnlock()

	log.PolicyName = fmt.Sprintf("batch-audit-%d", key.PolicyHash)
	if ok {
		log.PolicyName = meta.PolicyName
		if log.NamespaceName == "" && meta.Namespace != "" {
			log.NamespaceName = meta.Namespace
		}
		if meta.Message != "" {
			log.Message = meta.Message
		}
		if meta.Severity != 0 {
			log.Severity = strconv.Itoa(meta.Severity)
		}
		if len(meta.Tags) > 0 {
			log.Tags = strings.Join(meta.Tags, ",")
			log.ATags = append([]string{}, meta.Tags...)
		}
	}

	log.Type = "MatchedPolicy"
	log.Enforcer = "eBPF Monitor"
	log.Action = "Audit"
	if log.Result == "" {
		log.Result = "Passed"
	}
	log.Data = strings.TrimSpace(log.Data + " count=" + strconv.FormatUint(val.Count, 10))

	mon.Logger.PushLog(log)
}

func (mon *SystemMonitor) pollBatchAuditMapOnce() {
	if mon.BatchAuditAggMap == nil {
		return
	}

	mon.BpfMapLock.Lock()
	it := mon.BatchAuditAggMap.Iterate()
	var key batchAuditAggregationKey
	var val batchAuditAggregationVal
	var keys []batchAuditAggregationKey
	var vals []batchAuditAggregationVal

	for it.Next(&key, &val) {
		keys = append(keys, key)
		vals = append(vals, val)
	}

	for _, k := range keys {
		if err := mon.BatchAuditAggMap.Delete(k); err != nil && !errors.Is(err, os.ErrNotExist) {
			mon.Logger.Warnf("failed to clear batch audit aggregation entry: %s", err)
		}
	}
	mon.BpfMapLock.Unlock()

	for i := range keys {
		mon.emitBatchAuditAlert(keys[i], vals[i])
	}
}

func (mon *SystemMonitor) PollBatchAuditEvents() {
	for {
		(*mon.MonitorLock).RLock()
		active := mon.Status
		(*mon.MonitorLock).RUnlock()
		if !active {
			return
		}

		interval := mon.minBatchAuditInterval()
		mon.pollBatchAuditMapOnce()
		time.Sleep(interval)
	}
}
