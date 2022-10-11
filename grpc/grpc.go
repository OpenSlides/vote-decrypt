// Package grpc implements the gRPC service.
//
// The service is started with `RunServer()`
package grpc

import (
	"context"
	"fmt"
	"log"
	"net"

	"github.com/OpenSlides/vote-decrypt/decrypt"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// RunServer runs a grpc server on the given addr until ctx is done.
func RunServer(ctx context.Context, decrypt *decrypt.Decrypt, addr string) error {
	lis, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("listen on address %q: %w", addr, err)
	}

	registrar := grpc.NewServer()
	RegisterDecryptServer(registrar, grpcServer{decrypt})

	wait := make(chan struct{})
	go func() {
		<-ctx.Done()
		registrar.GracefulStop()
		wait <- struct{}{}
	}()

	log.Printf("Running grpc server on %s\n", addr)
	if err := registrar.Serve(lis); err != nil {
		return fmt.Errorf("running grpc server: %w", err)
	}

	<-wait

	return nil
}

// Client holds the connection to a decrypt server.
//
// This is not needed vote vote-decrypt but is used by the vote-service.
type Client struct {
	decryptClient DecryptClient
}

// NewClient creates a connection to a decrypt grpc server and wrapps then
// into a decrypt.crypto interface.
func NewClient(addr string) (*Client, func() error, error) {
	// TODO: use secure connection
	conn, err := grpc.Dial(addr, grpc.WithInsecure())
	if err != nil {
		return nil, nil, fmt.Errorf("creating connection to decrypt service: %w", err)
	}

	return &Client{decryptClient: NewDecryptClient(conn)}, conn.Close, nil
}

// PublicMainKey calls the grpc method.
func (c *Client) PublicMainKey(ctx context.Context) ([]byte, error) {
	resp, err := c.decryptClient.PublicMainKey(ctx, &EmptyMessage{})
	if err != nil {
		return nil, fmt.Errorf("sending grpc request: %w", err)
	}

	return resp.PublicKey, nil
}

// Start calls the Start grpc message.
func (c *Client) Start(ctx context.Context, pollID string) (pubKey []byte, pubKeySig []byte, err error) {
	resp, err := c.decryptClient.Start(ctx, &StartRequest{Id: pollID})
	if err != nil {
		return nil, nil, fmt.Errorf("sending grpc message: %w", err)
	}

	return resp.PubKey, resp.PubSig, nil
}

// Stop calls the Stop grpc message.
func (c *Client) Stop(ctx context.Context, pollID string, voteList [][]byte) (decryptedContent, signature []byte, err error) {
	resp, err := c.decryptClient.Stop(ctx, &StopRequest{Id: pollID, Votes: voteList})
	if err != nil {
		return nil, nil, fmt.Errorf("sending grpc message: %w", err)
	}
	return resp.Votes, resp.Signature, nil
}

// Clear calls the Clear grpc message.
func (c *Client) Clear(ctx context.Context, pollID string) error {
	_, err := c.decryptClient.Clear(ctx, &ClearRequest{Id: pollID})
	if err != nil {
		return fmt.Errorf("sending grpc message: %w", err)
	}

	return nil
}

type grpcServer struct {
	decrypt *decrypt.Decrypt
}

// grpcError converts an error to a grpc error.
func (s grpcServer) grpcError(err error) error {
	// TODO: Set the logger on initialization.
	log.Printf("GRPC: %v", err)

	// Currently, all errors are internal
	return status.Error(codes.Internal, "Ups, someting went wrong!")
}

func (s grpcServer) Start(ctx context.Context, req *StartRequest) (*StartResponse, error) {
	log.Printf("Start request for id %s", req.Id)
	pubKey, pubKeySig, err := s.decrypt.Start(ctx, req.Id)
	if err != nil {
		return nil, s.grpcError(fmt.Errorf("starting vote: %w", err))
	}

	return &StartResponse{
		PubKey: pubKey,
		PubSig: pubKeySig,
	}, nil
}

func (s grpcServer) Stop(ctx context.Context, req *StopRequest) (*StopResponse, error) {
	log.Printf("Stop request for id %s", req.Id)
	decrypted, signature, err := s.decrypt.Stop(ctx, req.Id, req.Votes)
	if err != nil {
		return nil, s.grpcError(fmt.Errorf("stopping vote: %w", err))
	}

	return &StopResponse{
		Votes:     decrypted,
		Signature: signature,
	}, nil
}

func (s grpcServer) Clear(ctx context.Context, req *ClearRequest) (*EmptyMessage, error) {
	log.Printf("Stop request for id %s", req.Id)
	err := s.decrypt.Clear(ctx, req.Id)
	if err != nil {
		return nil, s.grpcError(fmt.Errorf("clearing vote: %w", err))
	}

	return new(EmptyMessage), nil
}

func (s grpcServer) PublicMainKey(ctx context.Context, req *EmptyMessage) (*PublicMainKeyResponse, error) {
	log.Printf("Public Poll Key request")
	key := s.decrypt.PublicMainKey(ctx)

	return &PublicMainKeyResponse{
		PublicKey: key,
	}, nil
}
