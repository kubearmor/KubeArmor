package eventAuditor

// =================== //
// == Event Auditor == //
// =================== //

// EventAuditor Structure
type EventAuditor struct {
	//
}

// NewEventAuditor Function
func NewEventAuditor() *EventAuditor { // (auditPolicies map[xxx]yyy, ...)
	ea := &EventAuditor{}

	// structure pointer for audit policies
	// assume that all macros are already applied to audit policies

	return ea
}

// DestroyEventAuditor Function
func (ea *EventAuditor) DestroyEventAuditor() error {
	return nil
}

// ============================= //
// == Audit Policy Management == //
// ============================= //

// UpdateAuditPolicies Function
func (ea *EventAuditor) UpdateAuditPolicies() { // (action string, auditPolicy yyy, ...)
	// update audit policies

	// call "entrypoint management"
	// call "shared map management"
}

// =========================== //
// == Entrypoint Management == //
// =========================== //

// handle kprobes, tracepoints
// handle entrypoint

// =========================== //
// == Shared Map Management == //
// =========================== //

// handle process-spec table

// ========================== //
// == eBPF Code Generation == //
// ========================== //

// TBD
