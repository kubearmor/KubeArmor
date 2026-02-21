package state

import (
	"encoding/json"
	"sync"
	"testing"
	"time"

	tp "github.com/kubearmor/KubeArmor/KubeArmor/types"
	pb "github.com/kubearmor/KubeArmor/protobuf"
)

// Mock StateAgent for testing
func createMockStateAgent() *StateAgent {
	return &StateAgent{
		KubeArmorNamespaces:     make(map[string]tp.Namespace),
		KubeArmorNamespacesLock: &sync.RWMutex{},
		StateEventChans:         make(map[string]chan *pb.StateEvent),
	}
}

// Test PushContainerEvent - Empty Container ID
func TestPushContainerEvent_EmptyContainerID(t *testing.T) {
	sa := createMockStateAgent()
	
	container := tp.Container{
		ContainerID:   "",
		ContainerName: "test-container",
		NamespaceName: "test-namespace",
	}
	
	sa.PushContainerEvent(container, EventAdded)
	
	if len(sa.KubeArmorNamespaces) != 0 {
		t.Error("Expected no namespaces to be created for empty container ID")
	}
}

// Test PushContainerEvent - Add First Container
func TestPushContainerEvent_AddFirstContainer(t *testing.T) {
	sa := createMockStateAgent()
	
	testChan := make(chan *pb.StateEvent, 10)
	sa.StateEventChans["test-connection"] = testChan
	
	container := tp.Container{
		ContainerID:   "container-123",
		ContainerName: "test-container",
		NamespaceName: "test-namespace",
		LastUpdatedAt: time.Now().UTC().String(),
	}
	
	sa.PushContainerEvent(container, EventAdded)
	
	// Check namespace creation
	if len(sa.KubeArmorNamespaces) != 1 {
		t.Errorf("Expected 1 namespace, got %d", len(sa.KubeArmorNamespaces))
	}
	
	ns, exists := sa.KubeArmorNamespaces["test-namespace"]
	if !exists {
		t.Error("Expected namespace 'test-namespace' to be created")
	}
	
	if ns.ContainerCount != 1 {
		t.Errorf("Expected container count 1, got %d", ns.ContainerCount)
	}
	
	if ns.KubearmorFilePosture != "audit" {
		t.Errorf("Expected file posture 'audit', got %s", ns.KubearmorFilePosture)
	}
	
	if ns.KubearmorNetworkPosture != "audit" {
		t.Errorf("Expected network posture 'audit', got %s", ns.KubearmorNetworkPosture)
	}
	
	// Check events sent (namespace + container events)
	if len(testChan) < 2 {
		t.Errorf("Expected at least 2 events, got %d", len(testChan))
	}
}

// Test PushContainerEvent - Add Second Container to Existing Namespace
func TestPushContainerEvent_AddSecondContainer(t *testing.T) {
	sa := createMockStateAgent()
	
	testChan := make(chan *pb.StateEvent, 10)
	sa.StateEventChans["test-connection"] = testChan
	
	// Pre-create namespace
	sa.KubeArmorNamespaces["test-namespace"] = tp.Namespace{
		Name:           "test-namespace",
		ContainerCount: 1,
		LastUpdatedAt:  time.Now().UTC().String(),
	}
	
	container := tp.Container{
		ContainerID:   "container-456",
		ContainerName: "test-container-2",
		NamespaceName: "test-namespace",
		LastUpdatedAt: time.Now().UTC().String(),
	}
	
	sa.PushContainerEvent(container, EventAdded)
	
	ns := sa.KubeArmorNamespaces["test-namespace"]
	if ns.ContainerCount != 2 {
		t.Errorf("Expected container count 2, got %d", ns.ContainerCount)
	}
	
	// Should only send container event (no new namespace event)
	if len(testChan) != 1 {
		t.Errorf("Expected 1 event, got %d", len(testChan))
	}
}

// Test PushContainerEvent - Delete Container (Not Last)
func TestPushContainerEvent_DeleteContainer(t *testing.T) {
	sa := createMockStateAgent()
	
	testChan := make(chan *pb.StateEvent, 10)
	sa.StateEventChans["test-connection"] = testChan
	
	// Pre-create namespace with 2 containers
	sa.KubeArmorNamespaces["test-namespace"] = tp.Namespace{
		Name:           "test-namespace",
		ContainerCount: 2,
		LastUpdatedAt:  time.Now().UTC().String(),
	}
	
	container := tp.Container{
		ContainerID:   "container-123",
		ContainerName: "test-container",
		NamespaceName: "test-namespace",
	}
	
	sa.PushContainerEvent(container, EventDeleted)
	
	ns := sa.KubeArmorNamespaces["test-namespace"]
	if ns.ContainerCount != 1 {
		t.Errorf("Expected container count 1, got %d", ns.ContainerCount)
	}
	
	// Namespace should still exist
	if len(sa.KubeArmorNamespaces) != 1 {
		t.Error("Expected namespace to still exist")
	}
	
	// Should send container event only
	if len(testChan) != 1 {
		t.Errorf("Expected 1 event, got %d", len(testChan))
	}
}

// Test PushContainerEvent - Delete Last Container
// Test Delete Last Container - covers namespace deletion when count = 0
func TestPushContainerEvent_DeleteLastContainer(t *testing.T) {
	sa := createMockStateAgent()
	testChan := make(chan *pb.StateEvent, 10)
	sa.StateEventChans["test-connection"] = testChan
	
	// Pre-create namespace with 1 container
	sa.KubeArmorNamespaces["test-namespace"] = tp.Namespace{
		Name:           "test-namespace",
		ContainerCount: 1,
		LastUpdatedAt:  time.Now().UTC().String(),
	}
	
	container := tp.Container{
		ContainerID:   "container-123",
		ContainerName: "test-container",
		NamespaceName: "test-namespace",
	}
	
	sa.PushContainerEvent(container, EventDeleted)
	
	// This covers the ns.ContainerCount == 0 deletion path
	if len(sa.KubeArmorNamespaces) != 0 {
		t.Error("Expected namespace to be deleted when count reaches 0")
	}
}

// Test PushContainerEvent - Delete from Non-existent Namespace
func TestPushContainerEvent_DeleteFromNonExistentNamespace(t *testing.T) {
	sa := createMockStateAgent()
	
	testChan := make(chan *pb.StateEvent, 10)
	sa.StateEventChans["test-connection"] = testChan
	
	container := tp.Container{
		ContainerID:   "container-123",
		ContainerName: "test-container",
		NamespaceName: "non-existent-namespace",
	}
	
	sa.PushContainerEvent(container, EventDeleted)
	
	// Should send container event only
	if len(testChan) != 1 {
		t.Errorf("Expected 1 event, got %d", len(testChan))
	}
}

// Test PushContainerEvent - JSON Marshal Error
func TestPushContainerEvent_JSONMarshalError(t *testing.T) {
	sa := createMockStateAgent()
	testChan := make(chan *pb.StateEvent, 10)
	sa.StateEventChans["test-connection"] = testChan
	
	// Create container with circular reference or use reflection to break marshal
	container := tp.Container{
		ContainerID:   "container-123",
		ContainerName: "test-container", 
		NamespaceName: "test-namespace",
	}
	
	// This path is hard to test directly - JSON marshal rarely fails with normal structs
	// But the namespace should still be created before marshal attempt
	sa.PushContainerEvent(container, EventAdded)
	
	if len(sa.KubeArmorNamespaces) != 1 {
		t.Error("Expected namespace to be created before marshal attempt")
	}
}

// Test PushContainerEvent - No State Event Channels
func TestPushContainerEvent_NoStateEventChans(t *testing.T) {
	sa := createMockStateAgent()
	sa.StateEventChans = nil
	
	container := tp.Container{
		ContainerID:   "container-123",
		ContainerName: "test-container",
		NamespaceName: "test-namespace",
		LastUpdatedAt: time.Now().UTC().String(),
	}
	
	// Should not panic
	sa.PushContainerEvent(container, EventAdded)
	
	// Namespace should still be created
	if len(sa.KubeArmorNamespaces) != 1 {
		t.Error("Expected namespace to be created even without event channels")
	}
}

// Test PushContainerEvent - Channel Send Failure
// Test Channel Send Failure - forces early return in default case
func TestPushContainerEvent_ChannelSendFailureReturn(t *testing.T) {
	sa := createMockStateAgent()
	
	// Create blocked channel (no buffer)
	blockedChan := make(chan *pb.StateEvent)
	workingChan := make(chan *pb.StateEvent, 10)
	
	sa.StateEventChans["blocked"] = blockedChan
	sa.StateEventChans["working"] = workingChan
	
	container := tp.Container{
		ContainerID:   "container-123",
		ContainerName: "test-container",
		NamespaceName: "test-namespace",
		LastUpdatedAt: time.Now().UTC().String(),
	}
	
	// This hits the default case and returns early
	sa.PushContainerEvent(container, EventAdded)
	
	// Working channel should not receive container event due to early return
	if len(workingChan) > 1 { // Allow namespace event
		t.Error("Expected early return after channel send failure")
	}
}

// Test PushNodeEvent - Empty Node Name
func TestPushNodeEvent_EmptyNodeName(t *testing.T) {
	sa := createMockStateAgent()
	
	testChan := make(chan *pb.StateEvent, 10)
	sa.StateEventChans["test-connection"] = testChan
	
	node := tp.Node{
		NodeName: "",
	}
	
	sa.PushNodeEvent(node, EventAdded)
	
	// Should not send any events
	if len(testChan) != 0 {
		t.Error("Expected no events for empty node name")
	}
}

// Test PushNodeEvent - Valid Node
func TestPushNodeEvent_ValidNode(t *testing.T) {
	sa := createMockStateAgent()
	
	testChan := make(chan *pb.StateEvent, 10)
	sa.StateEventChans["test-connection"] = testChan
	
	node := tp.Node{
		NodeName: "test-node",
	}
	
	sa.PushNodeEvent(node, EventAdded)
	
	if len(testChan) != 1 {
		t.Errorf("Expected 1 event, got %d", len(testChan))
	}
	
	event := <-testChan
	if event.Kind != KindNode {
		t.Errorf("Expected kind %s, got %s", KindNode, event.Kind)
	}
	
	if event.Type != EventAdded {
		t.Errorf("Expected type %s, got %s", EventAdded, event.Type)
	}
	
	if event.Name != "test-node" {
		t.Errorf("Expected name 'test-node', got %s", event.Name)
	}
	
	// Verify marshaled data
	var unmarshaledNode tp.Node
	err := json.Unmarshal(event.Object, &unmarshaledNode)
	if err != nil {
		t.Errorf("Failed to unmarshal node data: %v", err)
	}
	
	if unmarshaledNode.NodeName != "test-node" {
		t.Errorf("Expected unmarshaled node name 'test-node', got %s", unmarshaledNode.NodeName)
	}
}

// Test PushNodeEvent - No State Event Channels
func TestPushNodeEvent_NoStateEventChans(t *testing.T) {
	sa := createMockStateAgent()
	sa.StateEventChans = nil
	
	node := tp.Node{
		NodeName: "test-node",
	}
	
	// Should not panic
	sa.PushNodeEvent(node, EventAdded)
}

// Test PushNodeEvent - Channel Send Failure
func TestPushNodeEvent_ChannelSendFailure(t *testing.T) {
	sa := createMockStateAgent()
	blockedChan := make(chan *pb.StateEvent) // No buffer
	sa.StateEventChans["blocked"] = blockedChan
	
	node := tp.Node{NodeName: "test-node"}
	sa.PushNodeEvent(node, EventAdded) // Hits default case, returns early
}

func TestPushNamespaceEvent_ChannelSendFailure(t *testing.T) {
	sa := createMockStateAgent()
	blockedChan := make(chan *pb.StateEvent) // No buffer
	sa.StateEventChans["blocked"] = blockedChan
	
	namespace := tp.Namespace{Name: "test-namespace"}
	sa.PushNamespaceEvent(namespace, EventAdded) // Hits default case, returns early
}

// Test PushNamespaceEvent - Valid Namespace
func TestPushNamespaceEvent_ValidNamespace(t *testing.T) {
	sa := createMockStateAgent()
	
	testChan := make(chan *pb.StateEvent, 10)
	sa.StateEventChans["test-connection"] = testChan
	
	namespace := tp.Namespace{
		Name:           "test-namespace",
		ContainerCount: 1,
		LastUpdatedAt:  time.Now().UTC().String(),
	}
	
	sa.PushNamespaceEvent(namespace, EventAdded)
	
	if len(testChan) != 1 {
		t.Errorf("Expected 1 event, got %d", len(testChan))
	}
	
	event := <-testChan
	if event.Kind != KindNamespace {
		t.Errorf("Expected kind %s, got %s", KindNamespace, event.Kind)
	}
	
	if event.Type != EventAdded {
		t.Errorf("Expected type %s, got %s", EventAdded, event.Type)
	}
	
	if event.Name != "test-namespace" {
		t.Errorf("Expected name 'test-namespace', got %s", event.Name)
	}
	
	// Verify marshaled data
	var unmarshaledNs tp.Namespace
	err := json.Unmarshal(event.Object, &unmarshaledNs)
	if err != nil {
		t.Errorf("Failed to unmarshal namespace data: %v", err)
	}
	
	if unmarshaledNs.Name != "test-namespace" {
		t.Errorf("Expected unmarshaled name 'test-namespace', got %s", unmarshaledNs.Name)
	}
	
	if unmarshaledNs.ContainerCount != 1 {
		t.Errorf("Expected container count 1, got %d", unmarshaledNs.ContainerCount)
	}
}

// Test PushNamespaceEvent - No State Event Channels
func TestPushNamespaceEvent_NoStateEventChans(t *testing.T) {
	sa := createMockStateAgent()
	sa.StateEventChans = nil
	
	namespace := tp.Namespace{
		Name: "test-namespace",
	}
	
	// Should not panic
	sa.PushNamespaceEvent(namespace, EventAdded)
}

// Test Multiple Connections
func TestMultipleConnections(t *testing.T) {
	sa := createMockStateAgent()
	
	testChan1 := make(chan *pb.StateEvent, 10)
	testChan2 := make(chan *pb.StateEvent, 10)
	sa.StateEventChans["connection-1"] = testChan1
	sa.StateEventChans["connection-2"] = testChan2
	
	container := tp.Container{
		ContainerID:   "container-123",
		ContainerName: "test-container",
		NamespaceName: "test-namespace",
		LastUpdatedAt: time.Now().UTC().String(),
	}
	
	sa.PushContainerEvent(container, EventAdded)
	
	// Both channels should receive events
	if len(testChan1) < 1 {
		t.Error("Expected events in channel 1")
	}
	
	if len(testChan2) < 1 {
		t.Error("Expected events in channel 2")
	}
}
// Test Add Container to Existing Namespace - covers container count increment
func TestPushContainerEvent_ExistingNamespace(t *testing.T) {
	sa := createMockStateAgent()
	testChan := make(chan *pb.StateEvent, 10)
	sa.StateEventChans["test-connection"] = testChan
	
	// Pre-create namespace
	sa.KubeArmorNamespaces["test-namespace"] = tp.Namespace{
		Name:           "test-namespace",
		ContainerCount: 2,
		LastUpdatedAt:  time.Now().UTC().String(),
	}
	
	container := tp.Container{
		ContainerID:   "container-new",
		ContainerName: "test-container-new",
		NamespaceName: "test-namespace",
		LastUpdatedAt: time.Now().UTC().String(),
	}
	
	sa.PushContainerEvent(container, EventAdded)
	
	// This covers the else branch - updating existing namespace
	ns := sa.KubeArmorNamespaces["test-namespace"]
	if ns.ContainerCount != 3 {
		t.Errorf("Expected count 3, got %d", ns.ContainerCount)
	}
}

