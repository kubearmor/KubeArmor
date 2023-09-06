package systemd_test

import (
	"context"
	"os"

	pb "github.com/kubearmor/KubeArmor/protobuf"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/types/known/emptypb"
)

var _ = Describe("Systemd", func() {

	Describe(" Recieving policy data for systemd mode ", func() {
		It(" can recieve policy data through grpc client ", func() {
			gRPC := ""

			if val, ok := os.LookupEnv("KUBEARMOR_SERVICE"); ok {
				gRPC = val
			} else {
				gRPC = "localhost:32767"
			}

			conn, err := grpc.Dial(gRPC, grpc.WithInsecure())

			Expect(err).To(BeNil())

			client := pb.NewKarmorClient(conn)

			_, err = client.GetKarmorData(context.Background(), &emptypb.Empty{})

			Expect(err).To(BeNil())

		})
	})
})
