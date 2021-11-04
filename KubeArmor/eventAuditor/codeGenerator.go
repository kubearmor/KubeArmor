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

	jenkins "leb.io/hashland/jenkins"
)

// Configuration
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

func getProgramName(probe string, index uint32) string {
	return fmt.Sprintf("%s_i%v", getFnName(probe), index)
}

func getFnName(probe string) string {
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

// TokenType Type
type TokenType int64

// TokenValue Type
type TokenValue interface{}

// TokenTypes
const (
	Undefined TokenType = iota
	Number
	Range
	Glob
)

// Token Structure
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

func generateIpv4Match(ipv4Tokens []Token) string {
	matchGroup := []string{}
	for i, token := range ipv4Tokens {
		if token.isNumber() {
			matchGroup = append(matchGroup,
				fmt.Sprintf("((v4ip.octet[%d]) == %d)", i, token.getNumber()))

		} else if token.isRange() {
			matchGroup = append(matchGroup,
				fmt.Sprintf("(((v4ip.octet[%d]) >= %d) && ((v4ip.octet[%d]) <= %d))",
					i, token.getRange()[0],
					i, token.getRange()[1]))
		}
	}

	match := "(" + strings.Join(matchGroup, " &&\n") + ")"
	return match
}

func generateIpv4MatchExclusion(ipv4Field string) (string, error) {
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

			matchGroup = append(matchGroup, generateIpv4Match(ipv4Tokens))
		}
	}

	if len(matchGroup) > 0 {
		match = "(" + strings.Join(matchGroup, " &&\n") + ")"
	}

	return match, nil
}

func generateIpv4MatchInclusion(ipv4Field string) (string, error) {
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

			matchGroup = append(matchGroup, generateIpv4Match(ipv4Tokens))
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

func generatePortMatch(portField string) (string, error) {
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
				fmt.Sprintf("(port == %d)", portToken.getNumber()))

		} else if portToken.isRange() {
			matchGroup = append(matchGroup,
				fmt.Sprintf("((port >= %d) && (port <= %d))",
					portToken.getRange()[0],
					portToken.getRange()[1]))
		}
	}

	if len(matchGroup) > 0 {
		match = "(" + strings.Join(matchGroup, " ||\n") + ")"
	}

	return match, nil
}

func scanRate(value string) []Token {
	var nanoSecPerSec = int64(1000000000)
	var rateTokens []Token
	var token *Token

	sliceValue := strings.Split(value, "p")
	if len(sliceValue) == 2 {
		numEvents := sliceValue[0]
		timeLimit := sliceValue[1]
		timeUnits := timeLimit[len(timeLimit)-1]

		if timeUnits == 's' || timeUnits == 'm' {
			token = tokenize(numEvents, Number)
			rateTokens = append(rateTokens, *token)

			token = tokenize(timeLimit[:len(timeLimit)-1], Number)
			rateTokens = append(rateTokens, *token)

			if token.isNumber() {
				perSecValue := token.getNumber()
				if timeUnits == 'm' {
					perSecValue *= 60
				}

				rateTokens[1] = Token{Number, perSecValue * nanoSecPerSec}
			}
		}
	}

	return rateTokens
}

func rateTokenize(rateValue string) ([]Token, error) {
	rateValue = strings.TrimSpace(rateValue)
	rateTokens := scanRate(rateValue)

	if len(rateTokens) == 2 {
		if rateTokens[0].isNumber() && rateTokens[1].isNumber() {
			return rateTokens, nil
		}
	}

	return nil, fmt.Errorf("invalid parameter: %v (rate)", rateValue)
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

func generateModeMatch(modeField string) (string, error) {
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

	match := fmt.Sprintf("(mode == 0x%x)", modeInt64)
	return match, nil
}

func flagsTokenize(flagsValue string) (Token, error) {
	flagsValue = strings.TrimSpace(flagsValue)
	flagsToken := tokenize(flagsValue, Number)

	if flagsToken.isNumber() {
		return *flagsToken, nil
	}

	return Token{Undefined, nil},
		fmt.Errorf("invalid parameter: %v (flags)", flagsValue)
}

func generateFlagsMatch(flagsField string) (string, error) {
	var err error
	var flagsToken Token

	flagsInt64 := int64(0)
	flagsList := strings.Split(flagsField, "|")

	for _, flagsValue := range flagsList {
		if flagsToken, err = flagsTokenize(flagsValue); err != nil {
			return "", err
		}

		flagsInt64 |= flagsToken.getNumber()
	}

	match := fmt.Sprintf("(flags == 0x%x)", flagsInt64)
	return match, nil
}

func generatePathMatch(pathField string) (string, error) {
	hashKey, _ := jenkins.HashString(pathField, 0, 0)
	match := fmt.Sprintf("(path == 0x%x)", hashKey)
	return match, nil
}

func buildIpv4AddrParam(ipv4Field string, inc *[]string, exc *[]string) error {
	if match, err := generateIpv4MatchInclusion(ipv4Field); err != nil {
		return err
	} else if len(match) > 0 {
		*inc = append(*inc, match)
	}

	if match, err := generateIpv4MatchExclusion(ipv4Field); err != nil {
		return err
	} else if len(match) > 0 {
		*exc = append(*exc, match)
	}

	return nil
}

func buildPortParam(portField string, inc *[]string) error {
	if match, err := generatePortMatch(portField); err != nil {
		return err
	} else if len(match) > 0 {
		*inc = append(*inc, match)
	}

	return nil
}

func buildModeParam(modeField string, inc *[]string) error {
	if match, err := generateModeMatch(modeField); err != nil {
		return err
	} else if len(match) > 0 {
		*inc = append(*inc, match)
	}

	return nil
}

func buildFlagsParam(flagsField string, inc *[]string) error {
	if match, err := generateFlagsMatch(flagsField); err != nil {
		return err
	} else if len(match) > 0 {
		*inc = append(*inc, match)
	}

	return nil
}

func buildPathParam(pathField string, inc *[]string) error {
	if match, err := generatePathMatch(pathField); err != nil {
		return err
	} else if len(match) > 0 {
		*inc = append(*inc, match)
	}

	return nil
}

// TryTokenizeIpv4 Function
func TryTokenizeIpv4(ipv4Value string) error {
	_, err := ipv4Tokenize(ipv4Value)
	return err
}

// TryTokenizePort Function
func TryTokenizePort(portValue string) error {
	_, err := portTokenize(portValue)
	return err
}

// TryTokenizeMode Function
func TryTokenizeMode(modeValue string) error {
	_, err := modeTokenize(modeValue)
	return err
}

// TryTokenizeFlags Function
func TryTokenizeFlags(flagsValue string) error {
	_, err := flagsTokenize(flagsValue)
	return err
}

// TryTokenizeRate Function
func TryTokenizeRate(rateValue string) error {
	_, err := rateTokenize(rateValue)
	return err
}

// ========================== //
// == eBPF Code Generation == //
// ========================== //

func (ea *EventAuditor) generateCodeBlock(auditEvent tp.AuditEventType, probe string, uniqID uint32) (string, error) {
	var codeBlock string
	var matchInclusion []string
	var matchExclusion []string
	var localVariables []string
	var logFnCall string

	eventSupportsArgument := func(param string, value string) bool {
		if !kl.ContainsElement(ea.EntryPointParameters[probe], param) {
			ea.Logger.Warnf("Parameter `%v' is not supported for `%v' (skipped/%v)",
				param, probe, value)
			return false
		}
		return true
	}

	logFnCall = fmt.Sprintf("__ka_ea_evt_log(\"%v\");", auditEvent.Message)
	eventID := ea.SupportedEntryPoints[probe]

	if len(auditEvent.Rate) > 0 {
		var err error
		var rateTokens []Token

		if rateTokens, err = rateTokenize(auditEvent.Rate); err != nil {
			return "", err
		}

		limitEvents := rateTokens[0].getNumber()
		limitTime := rateTokens[1].getNumber()

		logFnCall = fmt.Sprintf("__INIT_LOCAL_RATE(%d)\n", uniqID)
		logFnCall += fmt.Sprintf("__ka_ea_rl_log(%v, %v, %v, \"%v\");", uniqID,
			limitEvents, limitTime, auditEvent.Message)
	}

	if len(auditEvent.Ipv4Addr) > 0 {
		if eventSupportsArgument("Ipv4Addr", auditEvent.Ipv4Addr) {
			if err := buildIpv4AddrParam(auditEvent.Ipv4Addr, &matchInclusion, &matchExclusion); err != nil {
				return "", err
			}

			variable := fmt.Sprintf("__INIT_LOCAL_IPV4(%d)", eventID)
			localVariables = append(localVariables, variable)
		}
	}

	if len(auditEvent.Port) > 0 {
		if eventSupportsArgument("Port", auditEvent.Port) {
			if err := buildPortParam(auditEvent.Port, &matchInclusion); err != nil {
				return "", err
			}

			variable := fmt.Sprintf("__INIT_LOCAL_PORT(%d)", eventID)
			localVariables = append(localVariables, variable)
		}
	}

	if len(auditEvent.Mode) > 0 {
		if eventSupportsArgument("Mode", auditEvent.Mode) {
			if err := buildModeParam(auditEvent.Mode, &matchInclusion); err != nil {
				return "", err
			}

			variable := fmt.Sprintf("__INIT_LOCAL_MODE(%d)", eventID)
			localVariables = append(localVariables, variable)
		}
	}

	if len(auditEvent.Flags) > 0 {
		if eventSupportsArgument("Flags", auditEvent.Flags) {
			if err := buildFlagsParam(auditEvent.Flags, &matchInclusion); err != nil {
				return "", err
			}

			variable := fmt.Sprintf("__INIT_LOCAL_FLAGS(%d)", eventID)
			localVariables = append(localVariables, variable)
		}
	}

	if len(auditEvent.Path) > 0 {
		if eventSupportsArgument("Path", auditEvent.Path) {
			if err := buildPathParam(auditEvent.Path, &matchInclusion); err != nil {
				return "", err
			}

			variable := fmt.Sprintf("__INIT_LOCAL_PATH(%d)", eventID)
			localVariables = append(localVariables, variable)
		}
	}

	for _, variable := range localVariables {
		codeBlock += "\n" + variable
	}

	if len(matchExclusion) > 0 {
		// add skip block
		codeBlock += fmt.Sprintf("\nif (%v)\n{\nreturn 0;\n}\n",
			strings.Join(matchExclusion, " || "))
	}

	if len(matchInclusion) > 0 {
		// add match and log block
		codeBlock += fmt.Sprintf("\nif (%v)\n{\n%v\n}\n",
			strings.Join(matchInclusion, " && "), logFnCall)

	} else {
		// add log block
		codeBlock += fmt.Sprintf("\n%v\n", logFnCall)
	}

	return fmt.Sprintf("\n/* %v */\n{%v}\n", auditEvent, codeBlock), nil
}

// GenerateCodeBlock Function
func (ea *EventAuditor) GenerateCodeBlock(auditEvent tp.AuditEventType, uniqID uint32) (string, error) {
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

	} else if codeBlock, err = ea.generateCodeBlock(auditEvent, probe, uniqID); err != nil {
		return "", err
	}

	ea.EventCodeBlockCache[eventStr] = codeBlock
	return codeBlock, nil
}

// GenerateAuditProgram Function
func (ea *EventAuditor) GenerateAuditProgram(probe string, codeBlocks []string) string {
	// add basic code
	source := "// SPDX-License-Identifier: GPL-2.0\n"
	source += "// Copyright 2021 Authors of KubeArmor\n\n"
	source += "#include \"codegen.bpf.h\"\n\n"

	source += "SEC(\"tracepoint/codegen\")\n"
	source += "int " + getFnName(probe) + "(void *ctx)\n{\n"

	// common prologue
	source += "if (!ka_ea_audit_task())\n"
	source += "{\n"
	source += "return 0;\n"
	source += "}\n"

	// compiled rules
	for _, block := range codeBlocks {
		source += block
	}

	source += "\nreturn 0;"
	source += "\n}"
	return source
}

// LoadAuditProgram Function
func (ea *EventAuditor) LoadAuditProgram(source string, probe string) (uint32, error) {
	var eventJmpElement EventJumpTableElement

	tryRemoveFile := func(n string) {
		if _, err := os.Stat(n); err == nil {
			if err := os.Remove(n); err != nil {
				ea.Logger.Warnf("Failed to delete file `%v': %v", n, err)
			}
		}
	}

	ea.CacheIndexLock.Lock()
	defer ea.CacheIndexLock.Unlock()

	// if already loaded, return the index
	index := ea.NextJumpTableIndex
	if jumpTableIndex, ok := ea.EventProgramCache[source]; ok {
		ea.Logger.Printf("Event auditor bytecode loaded (cached/%v/%v)", probe, jumpTableIndex)
		return jumpTableIndex, nil
	}

	srcName := getSourceName(probe, index)
	objName := getObjectName(probe, index)
	bpfProg := KABPFProg{
		Name:      KABPFProgName(getProgramName(probe, index)),
		EventName: KABPFEventName(getEventName(probe)),
		EventType: lbpf.KABPFLinkTypeTracepoint,
		FileName:  KABPFObjFileName(objName),
	}

	defer tryRemoveFile(srcName)
	defer tryRemoveFile(objName)

	// save source
	file, err := os.Create(getSourceName(probe, index))
	if err != nil {
		return 0, fmt.Errorf("error writing to file: %v: %v", srcName, err)
	}

	// avoid program name duplication
	srcUniqFnName := strings.Replace(source, getFnName(probe), getProgramName(probe, index), 1)
	if err := kl.SafeFileWriteAndClose(file, srcUniqFnName); err != nil {
		return 0, err
	}

	// build the source
	if output, ok := kl.GetCommandStdoutAndStderr("make", []string{"-C", "./BPF"}); !ok {
		return 0, fmt.Errorf("error compiling audit program: %v:\n%v", srcName, output)
	}

	// load bpf program
	if err := ea.BPFManager.InitProgram(bpfProg); err != nil {
		return 0, err
	}

	// populate ka_ea_event_jmp_table
	eventJmpElement.SetKey(index)
	eventJmpElement.SetValue(uint32(ea.BPFManager.getProg(bpfProg.Name).FD()))
	if err := ea.BPFManager.MapUpdateElement(&eventJmpElement); err != nil {
		return 0, err
	}

	ea.Logger.Printf("Event auditor bytecode loaded (new/%v/%v)", probe, index)
	ea.EventProgramCache[source] = index
	ea.NextJumpTableIndex++
	return index, nil
}
