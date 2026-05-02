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
	appID   string
}

func NewServer(service *linkverify.Service, s store.Store, appID string) *Server {
	return &Server{service: service, store: s, appID: appID}
}

func (s *Server) CreateChallenge(ctx context.Context, _ *pb.CreateChallengeRequest) (*pb.CreateChallengeResponse, error) {
	c, err := s.store.CreateChallenge(ctx)
	if err != nil {
		log.Printf("create challenge error: %v", err)
		return nil, status.Errorf(codes.Internal, "failed to create challenge")
	}
	return &pb.CreateChallengeResponse{
		Challenge: c.Challenge,
		AppId:     s.appID,
		ExpiresAt: c.ExpiresAt.Format(time.RFC3339),
	}, nil
}

func (s *Server) GetChallenge(ctx context.Context, req *pb.GetChallengeRequest) (*pb.GetChallengeResponse, error) {
	if req.Challenge == "" {
		return nil, status.Errorf(codes.InvalidArgument, "challenge is required")
	}
	c, err := s.store.GetChallenge(ctx, req.Challenge)
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
		Challenge: c.Challenge,
		AppId:     s.appID,
		ExpiresAt: c.ExpiresAt.Format(time.RFC3339),
	}, nil
}

func (s *Server) LinkVerify(ctx context.Context, req *pb.LinkVerifyRequest) (*pb.LinkVerifyResponse, error) {
	if req.Challenge == "" {
		return nil, status.Errorf(codes.InvalidArgument, "challenge is required")
	}
	if len(req.CertChainProof) == 0 || len(req.DeviceSigProof) == 0 {
		return nil, status.Errorf(codes.InvalidArgument, "cert_chain_proof and device_sig_proof are required")
	}

	pt, err := linkverify.ParseProofType(req.CertChainType)
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "%v", err)
	}

	result, err := s.service.VerifyAndRecord(ctx, linkverify.Request{
		CertChainProof: req.CertChainProof,
		DeviceSigProof: req.DeviceSigProof,
		ProofType:      pt,
	})
	if err != nil {
		nullifier := ""
		if result != nil {
			nullifier = result.Nullifier
		}
		return nil, mapServiceError(err, nullifier)
	}

	if !result.Verified {
		return &pb.LinkVerifyResponse{
			Verified:      false,
			Nullifier:     result.Nullifier,
			Reason:        result.Reason,
			SmtRoot:       smtRootOutcomeToProto(result.SmtRoot),
			IssuerModulus: issuerModulusOutcomeToProto(result.IssuerModulus),
			AppId:         appIDOutcomeToProto(result.AppID),
			Challenge:     challengeOutcomeToProto(result.Challenge),
		}, nil
	}

	return &pb.LinkVerifyResponse{
		Verified:      true,
		Nullifier:     result.Nullifier,
		IdVerified:    true,
		Persisted:     true,
		SmtRoot:       smtRootOutcomeToProto(result.SmtRoot),
		IssuerModulus: issuerModulusOutcomeToProto(result.IssuerModulus),
		AppId:         appIDOutcomeToProto(result.AppID),
		Challenge:     challengeOutcomeToProto(result.Challenge),
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

func issuerModulusOutcomeToProto(o *linkverify.IssuerModulusOutcome) *pb.IssuerModulusOutcome {
	if o == nil {
		return nil
	}
	out := &pb.IssuerModulusOutcome{
		Issuer:         o.IssuerName,
		Match:          o.Match,
		ExpectedSha256: o.ExpectedSHA256,
		TrustSource:    o.TrustSource,
	}
	if !o.TrustedAt.IsZero() {
		out.TrustedAt = o.TrustedAt.Format(time.RFC3339)
	}
	return out
}

func appIDOutcomeToProto(o *linkverify.AppIDOutcome) *pb.AppIDOutcome {
	if o == nil {
		return nil
	}
	return &pb.AppIDOutcome{
		Match:    o.Match,
		Expected: o.Expected,
		Observed: o.Observed,
	}
}

func challengeOutcomeToProto(o *linkverify.ChallengeOutcome) *pb.ChallengeOutcome {
	if o == nil {
		return nil
	}
	return &pb.ChallengeOutcome{
		Match:    o.Match,
		Expected: o.Expected,
		Observed: o.Observed,
	}
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
	case errors.Is(err, linkverify.ErrIssuerCertUnavailable):
		log.Printf("link-verify issuer cert unavailable: %v", err)
		return status.Errorf(codes.Unavailable, "issuer cert provider unavailable, retry later")
	default:
		log.Printf("link-verify error: %v", err)
		return status.Errorf(codes.Internal, "proof verification failed")
	}
}
