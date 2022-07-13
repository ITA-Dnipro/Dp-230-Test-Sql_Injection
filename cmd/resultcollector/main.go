// Package main just for testing grpc connection. Should be moved to a separate microservice.
package main

import (
	"context"
	"fmt"
	"log"
	"net"

	"github.com/ITA-Dnipro/Dp-230-Test-Sql_Injection/internal/result"
	"google.golang.org/grpc"
)

type gRPCServer struct {
	result.UnimplementedCheckerServer
}

func main() {
	lis, err := net.Listen("tcp", ":50001")
	if err != nil {
		log.Fatalf("Failed to listen for gRPC %v\n", err)
	}

	s := grpc.NewServer()
	result.RegisterCheckerServer(s, &gRPCServer{})

	log.Printf("gRPC server started on :50001")
	if err := s.Serve(lis); err != nil {
		log.Fatalf("Failed to listen for gRPC %v\n", err)
	}
}

func (s *gRPCServer) SendResult(ctx context.Context, request *result.ResultRequest) (*result.ResultResponse, error) {
	for _, v := range request.ResultData.Result {
		log.Println(v)
	}

	return &result.ResultResponse{Response: fmt.Sprintf("Got results for task %s\n", request.ResultData.TaskID)}, nil
}
