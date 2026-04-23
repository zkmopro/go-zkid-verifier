package grpc

import (
	"context"
	"errors"
	"log"
	"time"

	"github.com/zkmopro/go-zkid-verifier/linkverify"
	pb "github.com/zkmopro/go-zkid-verifier/proto/zkid/v1"
	"github.com/zkmopro/go-zkid-verifier/store"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// Server implements the zkid gRPC service.
type Server struct {
	pb.UnimplementedZkIDVerifierServer
	service *linkverify.Service
	store   store.Store
}

func NewServer(service *linkverify.Service, s store.Store) *Server {
	return &Server{service: service, store: s}
}

func (s *Server) CreateChallenge(ctx context.Context, _ *pb.CreateChallengeRequest) (*pb.CreateChallengeResponse, error) {
	c, err := s.store.CreateChallenge(ctx)
	if err != nil {
		log.Printf("create challenge error: %v", err)
		return nil, status.Errorf(codes.Internal, "failed to create challenge")
	}
	return &pb.CreateChallengeResponse{
		ChallengeId:    c.ID,
		ChallengeBytes: c.BytesHex,
		ExpiresAt:      c.ExpiresAt.Format(time.RFC3339),
	}, nil
}

func (s *Server) GetChallenge(ctx context.Context, req *pb.GetChallengeRequest) (*pb.GetChallengeResponse, error) {
	if req.ChallengeId == "" {
		return nil, status.Errorf(codes.InvalidArgument, "challenge_id is required")
	}
	c, err := s.store.GetChallenge(ctx, req.ChallengeId)
	if err != nil {
		log.Printf("get challenge error: %v", err)
		return nil, status.Errorf(codes.Internal, "internal error")
	}
	if c == nil {
		return nil, status.Errorf(codes.NotFound, "challenge not found")
	}
	if time.Now().After(c.ExpiresAt) {
		return nil, status.Errorf(codes.FailedPrecondition, "challenge expired")
	}
	return &pb.GetChallengeResponse{
		ChallengeId:    c.ID,
		ChallengeBytes: c.BytesHex,
		ExpiresAt:      c.ExpiresAt.Format(time.RFC3339),
	}, nil
}

func (s *Server) LinkVerify(ctx context.Context, req *pb.LinkVerifyRequest) (*pb.LinkVerifyResponse, error) {
	if req.ChallengeId == "" {
		return nil, status.Errorf(codes.InvalidArgument, "challenge_id is required")
	}
	if len(req.CertChainProof) == 0 || len(req.DeviceSigProof) == 0 {
		return nil, status.Errorf(codes.InvalidArgument, "cert_chain_proof and device_sig_proof are required")
	}
	if req.Nullifier == "" {
		return nil, status.Errorf(codes.InvalidArgument, "nullifier is required")
	}

	pt, err := linkverify.ParseProofType(req.CertChainType)
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "%v", err)
	}

	result, err := s.service.VerifyAndRecordByID(ctx, req.ChallengeId, req.Nullifier, linkverify.Request{
		CertChainProof: req.CertChainProof,
		DeviceSigProof: req.DeviceSigProof,
		ProofType:      pt,
	})
	if err != nil {
		return nil, mapServiceError(err, req.Nullifier)
	}

	if !result.Verified {
		return &pb.LinkVerifyResponse{
			Verified:  false,
			Nullifier: result.Nullifier,
			Reason:    result.Reason,
			SmtRoot:   smtRootOutcomeToProto(result.SmtRoot),
		}, nil
	}

	return &pb.LinkVerifyResponse{
		Verified:   true,
		Nullifier:  result.Nullifier,
		IdVerified: true,
		Persisted:  true,
		SmtRoot:    smtRootOutcomeToProto(result.SmtRoot),
	}, nil
}

func smtRootOutcomeToProto(o *linkverify.SmtRootOutcome) *pb.SmtRootOutcome {
	if o == nil {
		return nil
	}
	out := &pb.SmtRootOutcome{
		Issuer:      o.IssuerName,
		Match:       o.Match,
		Expected:    o.Expected,
		Observed:    o.Observed,
		TrustSource: o.TrustSource,
	}
	if !o.TrustedAt.IsZero() {
		out.TrustedAt = o.TrustedAt.Format(time.RFC3339)
	}
	return out
}

func mapServiceError(err error, nullifier string) error {
	switch {
	case errors.Is(err, store.ErrDuplicateNullifier):
		return status.Errorf(codes.AlreadyExists, "nullifier %s already registered", nullifier)
	case errors.Is(err, store.ErrChallengeNotFound):
		return status.Errorf(codes.NotFound, "challenge not found")
	case errors.Is(err, store.ErrChallengeExpired):
		return status.Errorf(codes.FailedPrecondition, "challenge expired")
	case errors.Is(err, store.ErrChallengeConsumed):
		return status.Errorf(codes.FailedPrecondition, "challenge already consumed")
	case errors.Is(err, linkverify.ErrSmtRootUnavailable):
		log.Printf("link-verify smt root unavailable: %v", err)
		return status.Errorf(codes.Unavailable, "smt root provider unavailable, retry later")
	default:
		log.Printf("link-verify error: %v", err)
		return status.Errorf(codes.Internal, "proof verification failed")
	}
}
