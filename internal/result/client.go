package result

import (
	"log"

	"github.com/ITA-Dnipro/Dp-230-Test-Sql_Injection/config"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

func New(c config.Config) CheckerClient {
	conn, err := grpc.Dial(c.GRPCConfig.ResultCollectorAddress, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		log.Printf("Cannot connect to gRPC server: %v\n", err)
	}

	return NewCheckerClient(conn)
}
