// SPDX-License-Identifier: Apache-2.0
// Copyright 2021 Authors of KubeArmor

package eventauditor

import (
	"encoding/binary"
	"fmt"
	"math"
	"os"
	"reflect"
	"strconv"
	"strings"

	kl "github.com/kubearmor/KubeArmor/KubeArmor/common"
	tp "github.com/kubearmor/KubeArmor/KubeArmor/types"
	lbpf "github.com/kubearmor/libbpf"
)

const (
	CodeGenSourcePrefix = "./BPF/codegen_"
	CodeGenSourceSuffix = ".bpf.c"
	CodeGenObjectPrefix = "codegen_"
	CodeGenObjectSuffix = ".bpf.o"
)

func getSourceName(probe string, index uint32) string {
	return fmt.Sprintf("%s%v-%v%s", CodeGenSourcePrefix, probe,
		index, CodeGenSourceSuffix)
}

func getObjectName(probe string, index uint32) string {
	return fmt.Sprintf("%s%v-%v%s", CodeGenObjectPrefix, probe,
		index, CodeGenObjectSuffix)
}

func getProgramName(probe string) string {
	return "ka_ea_codegen__" + probe
}

func getEventName(probe string) string {
	if strings.HasPrefix(probe, "sys_") {
		probe = strings.Split(probe, "sys_")[1]
	}

	return "syscalls/sys_enter_" + probe
}

// ========================== //
// ==   Argument Parsing   == //
// ========================== //

type TokenType int64
type TokenValue interface{}

const (
	Undefined TokenType = iota
	Number
	Range
	Glob
)

type Token struct {
	Type  TokenType
	Value TokenValue
}

func (t Token) isDefined() bool {
	return t.Type != Undefined
}

func (t Token) isNumber() bool {
	return t.Type == Number
}

func (t Token) getNumber() int64 {
	return t.Value.(int64)
}

func (t Token) isRange() bool {
	return t.Type == Range
}

func (t Token) getRange() []int64 {
	v0 := reflect.ValueOf(t.Value).Index(0).Interface().(int64)
	v1 := reflect.ValueOf(t.Value).Index(1).Interface().(int64)
	return []int64{v0, v1}
}

func (t Token) isGlob() bool {
	return t.Type == Glob
}

func scanNumber(value string) *Token {
	if tokenValue, err := strconv.ParseInt(value, 0, 32); err == nil {
		return &Token{
			Number,
			tokenValue,
		}
	}

	return nil
}

func scanRange(value string) *Token {
	if elems := strings.Split(value, "-"); len(elems) == 2 {
		v0 := scanNumber(elems[0])
		v1 := scanNumber(elems[1])

		if (v0 != nil) && (v1 != nil) {
			return &Token{
				Range,
				[2]int64{v0.Value.(int64), v1.Value.(int64)},
			}
		}
	}

	return nil
}

func scanGlob(value string) *Token {
	if value == "*" {
		return &Token{
			Glob,
			nil,
		}
	}

	return nil
}

func tokenize(value string, kind TokenType) *Token {
	var token *Token

	switch kind {
	case Number:
		token = scanNumber(value)
	case Range:
		token = scanRange(value)
	case Glob:
		token = scanGlob(value)
	default:
		token = nil
	}

	if token == nil {
		token = &Token{
			Undefined,
			value,
		}
	}

	return token
}

func (t *Token) optimizeRange() {
	if t.isRange() {
		v := t.getRange()
		if v[0] == v[1] {
			t.Type = Number
			t.Value = v[0]
		}
	}
}

func (t Token) isIpv4Octet() bool {
	if t.isNumber() {
		n := t.getNumber()
		return n >= 0 && n <= 255

	} else if t.isRange() {
		v := t.getRange()
		return v[0] >= 0 && v[0] <= 255 && v[1] >= 0 && v[1] <= 255

	} else if t.isGlob() {
		return true
	}

	return false
}

func scanIpv4(value string) []Token {
	var ipv4Tokens []Token
	var token *Token

	for _, n := range strings.Split(value, ".") {
		for _, kind := range [3]TokenType{Number, Range, Glob} {
			if token = tokenize(n, kind); token.isDefined() {
				break
			}
		}

		if token.isRange() {
			token.optimizeRange()
		}

		ipv4Tokens = append(ipv4Tokens, *token)
	}

	return ipv4Tokens
}

func ipv4CidrToPattern(ipv4Tokens []Token, prefix int) {
	ipv4Octets := make([]byte, 4)
	startOctets := make([]byte, 4)
	endOctets := make([]byte, 4)

	for idx, token := range ipv4Tokens {
		ipv4Octets[idx] = byte(token.getNumber())
	}

	mask1 := uint32(math.Pow(2, float64(32-prefix)) - 1)
	mask2 := ^mask1

	ip := binary.BigEndian.Uint32(ipv4Octets)
	ipFirst := ip & mask2
	binary.BigEndian.PutUint32(startOctets, ipFirst)

	ipLast := ipFirst | mask1
	binary.BigEndian.PutUint32(endOctets, ipLast)

	for idx := range startOctets {
		rangeStr := fmt.Sprintf("%d-%d", startOctets[idx], endOctets[idx])

		token := scanRange(rangeStr)
		token.optimizeRange()

		ipv4Tokens[idx] = *token
	}
}

func ipv4IsPatternNotation(ipv4Tokens []Token) bool {
	if len(ipv4Tokens) != 4 {
		return false
	}

	for _, token := range ipv4Tokens {
		if !token.isIpv4Octet() {
			return false
		}
	}

	return true
}

func ipv4IsCidrNotation(ipv4Tokens []Token, lastOctet *Token, prefix *int) bool {
	if len(ipv4Tokens) != 4 {
		return false
	}

	for _, token := range ipv4Tokens[:len(ipv4Tokens)-1] {
		if !token.isNumber() || !token.isIpv4Octet() {
			return false
		}
	}

	lastToken := ipv4Tokens[len(ipv4Tokens)-1]
	if lastToken.isDefined() {
		return false
	}

	values := strings.Split(lastToken.Value.(string), "/")
	if len(values) != 2 {
		return false
	}

	octetToken := tokenize(values[0], Number)
	prefixToken := tokenize(values[1], Number)

	if !octetToken.isIpv4Octet() || !prefixToken.isDefined() ||
		prefixToken.getNumber() < 0 || prefixToken.getNumber() > 32 {
		return false
	}

	if lastOctet != nil {
		*lastOctet = *octetToken
	}

	if prefix != nil {
		*prefix = int(prefixToken.getNumber())
	}

	return true
}

func ipv4Tokenize(ipv4Value string) ([]Token, error) {
	var octet Token
	var prefix int

	ipv4Value = strings.TrimSpace(ipv4Value)
	ipv4Tokens := scanIpv4(ipv4Value)

	if ipv4IsPatternNotation(ipv4Tokens) {
		return ipv4Tokens, nil
	}

	if ipv4IsCidrNotation(ipv4Tokens, &octet, &prefix) {
		ipv4Tokens[len(ipv4Tokens)-1] = octet
		ipv4CidrToPattern(ipv4Tokens, prefix)
		return ipv4Tokens, nil
	}

	return nil, fmt.Errorf("invalid parameter: %v (ipv4addr)", ipv4Value)
}

func generateIpv4Match(ipv4Tokens []Token, eventId uint32) string {
	matchGroup := []string{}
	for i, token := range ipv4Tokens {
		if token.isNumber() {
			matchGroup = append(matchGroup,
				fmt.Sprintf("((__ka_ea_evt%d_ipv4(ctx)->octet[%d]) == %d)",
					eventId, i, token.getNumber()))

		} else if token.isRange() {
			matchGroup = append(matchGroup,
				fmt.Sprintf("(((__ka_ea_evt%d_ipv4(ctx)->octet[%d]) >= %d) && ((__ka_ea_evt%d_ipv4(ctx)->octet[%d]) <= %d))",
					eventId, i, token.getRange()[0],
					eventId, i, token.getRange()[1]))
		}
	}

	match := "(" + strings.Join(matchGroup, " &&\n") + ")"
	return match
}

func generateIpv4MatchExclusion(ipv4Field string, eventId uint32) (string, error) {
	var err error
	var ipv4Tokens []Token
	var match string

	matchGroup := []string{}
	ipv4List := strings.Split(ipv4Field, ",")

	for _, ipv4Value := range ipv4List {
		ipv4Value = strings.TrimSpace(ipv4Value)

		if ipv4Value[0] == '-' {
			if ipv4Tokens, err = ipv4Tokenize(ipv4Value[1:]); err != nil {
				return "", err
			}

			matchGroup = append(matchGroup, generateIpv4Match(ipv4Tokens, eventId))
		}
	}

	if len(matchGroup) > 0 {
		match = "(" + strings.Join(matchGroup, " &&\n") + ")"
	}

	return match, nil
}

func generateIpv4MatchInclusion(ipv4Field string, eventId uint32) (string, error) {
	var err error
	var ipv4Tokens []Token
	var match string

	matchGroup := []string{}
	ipv4List := strings.Split(ipv4Field, ",")

	for _, ipv4Value := range ipv4List {
		ipv4Value = strings.TrimSpace(ipv4Value)

		if ipv4Value[0] != '-' {
			if ipv4Tokens, err = ipv4Tokenize(ipv4Value); err != nil {
				return "", err
			}

			matchGroup = append(matchGroup, generateIpv4Match(ipv4Tokens, eventId))
		}
	}

	if len(matchGroup) > 0 {
		match = "(" + strings.Join(matchGroup, " ||\n") + ")"
	}

	return match, nil
}

func scanPort(value string) Token {
	var portToken *Token

	if portToken = tokenize(value, Range); portToken.isDefined() {
		portToken.optimizeRange()
		return *portToken
	}

	portToken = tokenize(value, Number)
	return *portToken
}

func portTokenize(portValue string) (Token, error) {
	portValue = strings.TrimSpace(portValue)
	portToken := scanPort(portValue)

	if portToken.isNumber() {
		n := portToken.getNumber()
		if n >= 0 && n <= 65535 {
			return portToken, nil
		}
	}

	if portToken.isRange() {
		v := portToken.getRange()
		if v[0] >= 0 && v[0] <= 65535 && v[1] >= 0 && v[1] <= 65535 {
			return portToken, nil
		}
	}

	return Token{Undefined, nil},
		fmt.Errorf("invalid parameter: %v (port)", portValue)
}

func generatePortMatch(portField string, eventId uint32) (string, error) {
	var err error
	var portToken Token
	var match string

	matchGroup := []string{}
	portList := strings.Split(portField, ",")

	for _, portValue := range portList {
		if portToken, err = portTokenize(portValue); err != nil {
			return "", err
		}

		if portToken.isNumber() {
			matchGroup = append(matchGroup,
				fmt.Sprintf("(__ka_ea_evt%d_port(ctx) == %d)", eventId, portToken.getNumber()))

		} else if portToken.isRange() {
			matchGroup = append(matchGroup,
				fmt.Sprintf("((__ka_ea_evt%d_port(ctx) >= %d) && (__ka_ea_evt%d_port(ctx) <= %d))",
					eventId, portToken.getRange()[0],
					eventId, portToken.getRange()[1]))
		}
	}

	if len(matchGroup) > 0 {
		match = "(" + strings.Join(matchGroup, " ||\n") + ")"
	}

	return match, nil
}

func modeTokenize(modeValue string) (Token, error) {
	modeValue = strings.TrimSpace(modeValue)
	modeToken := tokenize(modeValue, Number)

	if modeToken.isNumber() {
		return *modeToken, nil
	}

	return Token{Undefined, nil},
		fmt.Errorf("invalid parameter: %v (mode)", modeValue)
}

func generateModeMatch(modeField string, eventId uint32) (string, error) {
	var err error
	var modeToken Token

	modeInt64 := int64(0)
	modeList := strings.Split(modeField, "|")

	for _, modeValue := range modeList {
		if modeToken, err = modeTokenize(modeValue); err != nil {
			return "", err
		}

		modeInt64 |= modeToken.getNumber()
	}

	match := fmt.Sprintf("(__ka_ea_evt%d_mode(ctx) == 0x%x)", eventId, modeInt64)
	return match, nil
}

func buildIpv4AddrParam(ipv4Field string, eventId uint32, inc *[]string, exc *[]string) error {
	if match, err := generateIpv4MatchInclusion(ipv4Field, eventId); err != nil {
		return err
	} else if len(match) > 0 {
		*inc = append(*inc, match)
	}

	if match, err := generateIpv4MatchExclusion(ipv4Field, eventId); err != nil {
		return err
	} else if len(match) > 0 {
		*exc = append(*exc, match)
	}

	return nil
}

func buildPortParam(portField string, eventId uint32, inc *[]string) error {
	if match, err := generatePortMatch(portField, eventId); err != nil {
		return err
	} else if len(match) > 0 {
		*inc = append(*inc, match)
	}

	return nil
}

func buildModeParam(modeField string, eventId uint32, inc *[]string) error {
	if match, err := generateModeMatch(modeField, eventId); err != nil {
		return err
	} else if len(match) > 0 {
		*inc = append(*inc, match)
	}

	return nil
}

// ========================== //
// == eBPF Code Generation == //
// ========================== //

func (ea *EventAuditor) generateCodeBlock(auditEvent tp.AuditEventType, probe string) (string, error) {
	var codeBlock string
	var matchInclusion []string
	var matchExclusion []string

	eventSupportsArgument := func(param string, value string) bool {
		if !kl.ContainsElement(ea.EntryPointParameters[probe], param) {
			ea.Logger.Warnf("Parameter `%v' is not supported for `%v' (skipped/%v)",
				param, probe, value)
			return false
		}
		return true
	}

	eventId := ea.SupportedEntryPoints[probe]
	if len(auditEvent.Ipv4Addr) > 0 {
		if eventSupportsArgument("Ipv4Addr", auditEvent.Ipv4Addr) {
			if err := buildIpv4AddrParam(auditEvent.Ipv4Addr, eventId, &matchInclusion, &matchExclusion); err != nil {
				return "", err
			}
		}
	}

	if len(auditEvent.Port) > 0 {
		if eventSupportsArgument("Port", auditEvent.Port) {
			if err := buildPortParam(auditEvent.Port, eventId, &matchInclusion); err != nil {
				return "", err
			}
		}
	}

	if len(auditEvent.Mode) > 0 {
		if eventSupportsArgument("Mode", auditEvent.Mode) {
			if err := buildModeParam(auditEvent.Mode, eventId, &matchInclusion); err != nil {
				return "", err
			}
		}
	}

	if len(matchExclusion) > 0 {
		// add skip block
		codeBlock += "\n// rule: skip\n"
		codeBlock += fmt.Sprintf("if (%v)\n{\n\treturn 0;\n}\n",
			strings.Join(matchExclusion, " || "))
	}

	if len(matchInclusion) > 0 {
		// add match and log block
		codeBlock += "\n// rule: match and log\n"
		codeBlock += fmt.Sprintf("if (%v)\n{\n\t__ka_ea_evt_log(\"%v\");\n}\n",
			strings.Join(matchInclusion, " && "), auditEvent.Message)

	} else {
		// add log block
		codeBlock += "\n// rule: log\n"
		codeBlock += fmt.Sprintf("__ka_ea_evt_log(\"%v\");\n", auditEvent.Message)
	}

	return codeBlock, nil
}

func (ea *EventAuditor) GenerateCodeBlock(auditEvent tp.AuditEventType) (string, error) {
	var err error
	var ok bool
	var codeBlock string
	var probe string

	ea.CacheIndexLock.Lock()
	defer ea.CacheIndexLock.Unlock()

	probe = auditEvent.Probe
	if strings.HasPrefix(probe, "sys_") {
		probe = strings.Split(auditEvent.Probe, "sys_")[1]
	}

	if _, ok = ea.SupportedEntryPoints[probe]; !ok {
		return "", fmt.Errorf("unsupported event: %s", probe)
	}

	eventStr := fmt.Sprintf("%v", auditEvent)
	if codeBlock, ok = ea.EventCodeBlockCache[eventStr]; ok {
		return codeBlock, nil

	} else if codeBlock, err = ea.generateCodeBlock(auditEvent, probe); err != nil {
		return "", err
	}

	ea.EventCodeBlockCache[eventStr] = codeBlock
	return codeBlock, nil
}

func (ea *EventAuditor) GenerateAuditProgram(probe string, codeBlocks []string) string {
	// add basic code
	source := "// SPDX-License-Identifier: GPL-2.0\n"
	source += "// Copyright 2021 Authors of KubeArmor\n\n"
	source += "#include \"codegen.bpf.h\"\n\n"

	source += "SEC(\"tracepoint/codegen\")\n"
	source += "int " + getProgramName(probe) + "(void *ctx)\n{\n"

	// common prologue
	source += "\tif (!ka_ea_check_inspect())\n\t"
	source += "{\n"
	source += "\t\treturn 0;\n\t"
	source += "}\n"

	// compiled rules
	for _, block := range codeBlocks {
		source += strings.Replace(block, "\n", "\n\t", -1)
	}

	source += "\n\treturn 0;"
	source += "\n}"
	return source
}

func (ea *EventAuditor) LoadAuditProgram(source string, probe string) (uint32, error) {
	ea.CacheIndexLock.Lock()
	defer ea.CacheIndexLock.Unlock()

	// if already loaded, return the index
	index := ea.NextJumpTableIndex
	if jumpTableIndex, ok := ea.EventProgramCache[source]; ok {
		return jumpTableIndex, nil
	}

	srcName := getSourceName(probe, index)
	objName := getObjectName(probe, index)
	bpfProg := KABPFProg{
		Name:      KABPFProgName(getProgramName(probe)),
		EventName: KABPFEventName(getEventName(probe)),
		EventType: lbpf.KABPFLinkTypeTracepoint,
		FileName:  KABPFObjFileName(objName),
	}

	// save source
	if file, err := os.Create(getSourceName(probe, index)); err != nil {
		return 0, fmt.Errorf("error writing to file: %v: %v", srcName, err)
	} else {
		file.WriteString(source)
		file.Close()
	}

	// build the source
	ea.Logger.Printf("Building %v", srcName)
	if output, ok := kl.GetCommandStdoutAndStderr("make", []string{"-C", "./BPF"}); !ok {
		return 0, fmt.Errorf("error compiling the source code: %v:\n%v", srcName, output)
	}

	// load bpf program
	ea.Logger.Printf("Loading %v", objName)
	if err := ea.BPFManager.InitProgram(bpfProg); err != nil {
		return 0, err
	}

	// TODO: populete ka_event_jump_table
	// set ka_event_jump_table[index] = progfd

	os.Remove(srcName)
	os.Remove(objName)

	ea.EventProgramCache[source] = index
	ea.NextJumpTableIndex += 1
	return index, nil
}
