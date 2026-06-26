package bpflsm

import (
	"testing"

	mon "github.com/kubearmor/KubeArmor/KubeArmor/monitor"
	tp "github.com/kubearmor/KubeArmor/KubeArmor/types"
)

func TestUpdateSocketEventLog(t *testing.T) {
	tests := []struct {
		name         string
		data         InnerKey
		wantResource string
	}{
		{
			name: "address family",
			data: InnerKey{
				Path: [200]byte{byte(FAMILY), 21},
			},
			wantResource: "domain=AF_RDS",
		},
		{
			name: "socket type",
			data: InnerKey{
				Path: [200]byte{byte(TYPE), 3},
			},
			wantResource: "type=SOCK_RAW",
		},
		{
			name: "protocol",
			data: InnerKey{
				Path: [200]byte{byte(PROTOCOL), 6},
			},
			wantResource: "protocol=TCP type=SOCK_STREAM",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			log := updateSocketEventLog(tp.Log{}, mon.SocketCreate, tt.data)

			if log.Operation != "Network" {
				t.Fatalf("Operation = %q, want Network", log.Operation)
			}
			if log.Resource != tt.wantResource {
				t.Fatalf("Resource = %q, want %q", log.Resource, tt.wantResource)
			}
			if log.Data != "lsm=SOCKET_CREATE "+tt.wantResource {
				t.Fatalf("Data = %q, want lsm=SOCKET_CREATE %s", log.Data, tt.wantResource)
			}
		})
	}
}
