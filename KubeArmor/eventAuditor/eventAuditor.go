package eventAuditor

// =================== //
// == Event Auditor == //
// =================== //

// EventAuditor Structure
type EventAuditor struct {
	//
}

// NewEventAuditor Function
func NewEventAuditor() *EventAuditor {
	ea := &EventAuditor{}
	return ea
}

// DestroyEventAuditor Function
func (ea *EventAuditor) DestroyEventAuditor() error {
	return nil
}
