package grpc

import (
	"context"
	"errors"
	"log"
	"time"

	"github.com/zkmopro/go-zkid-verifier/challenge"
	"github.com/zkmopro/go-zkid-verifier/linkverify"
	pb "github.com/zkmopro/go-zkid-verifier/proto/zkid/v1"
	"github.com/zkmopro/go-zkid-verifier/store"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// Server implements the ZkIDVerifier gRPC service.
type Server struct {
	pb.UnimplementedZkIDVerifierServer
	store   store.Store
	keysDir string
}

func NewServer(s store.Store, keysDir string) *Server {
	return &Server{store: s, keysDir: keysDir}
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

	pt, err := parseCertChainType(req.CertChainType)
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "%v", err)
	}

	// Validate challenge
	c, err := s.store.GetChallenge(ctx, req.ChallengeId)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "internal error")
	}
	if c == nil {
		return nil, status.Errorf(codes.NotFound, "challenge not found")
	}
	if time.Now().After(c.ExpiresAt) {
		return nil, status.Errorf(codes.FailedPrecondition, "challenge expired")
	}

	// Run ZK link-verify
	verified, err := linkverify.Verify(linkverify.Request{
		CertChainProof: req.CertChainProof,
		DeviceSigProof: req.DeviceSigProof,
		ProofType:      pt,
	}, s.keysDir)
	if err != nil {
		log.Printf("link-verify error: %v", err)
		return nil, status.Errorf(codes.Internal, "proof verification failed")
	}

	if !verified {
		return &pb.LinkVerifyResponse{
			Verified:  false,
			Nullifier: req.Nullifier,
		}, nil
	}

	// Record verification
	proofType := "link_rs2048"
	if pt == linkverify.ProofTypeRS4096 {
		proofType = "link_rs4096"
	}
	err = s.store.VerifyAndRecord(ctx, req.Nullifier, req.ChallengeId, nil, proofType)
	if err != nil {
		return nil, storeErrorToGRPC(err)
	}

	return &pb.LinkVerifyResponse{
		Verified:   true,
		Nullifier:  req.Nullifier,
		IdVerified: true,
		Persisted:  true,
	}, nil
}

func (s *Server) VerifyTBS(ctx context.Context, req *pb.VerifyTBSRequest) (*pb.VerifyTBSResponse, error) {
	if req.ChallengeId == "" {
		return nil, status.Errorf(codes.InvalidArgument, "challenge_id is required")
	}
	if req.Nullifier == "" {
		return nil, status.Errorf(codes.InvalidArgument, "nullifier is required")
	}

	c, err := s.store.GetChallenge(ctx, req.ChallengeId)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "internal error")
	}
	if c == nil {
		return nil, status.Errorf(codes.NotFound, "challenge not found")
	}
	if time.Now().After(c.ExpiresAt) {
		return nil, status.Errorf(codes.FailedPrecondition, "challenge expired")
	}

	// Convert int32 slice to int slice
	bits := make([]int, len(req.TbsHashBits))
	for i, b := range req.TbsHashBits {
		bits[i] = int(b)
	}

	verified := challenge.VerifyTBSHash(c.Bytes, bits)
	if !verified {
		return &pb.VerifyTBSResponse{
			Verified:  false,
			Nullifier: req.Nullifier,
		}, nil
	}

	err = s.store.VerifyAndRecord(ctx, req.Nullifier, req.ChallengeId, nil, "tbs")
	if err != nil {
		return nil, storeErrorToGRPC(err)
	}

	return &pb.VerifyTBSResponse{
		Verified:   true,
		Nullifier:  req.Nullifier,
		IdVerified: true,
		Persisted:  true,
	}, nil
}

func (s *Server) GetVerificationStatus(ctx context.Context, req *pb.GetVerificationStatusRequest) (*pb.GetVerificationStatusResponse, error) {
	if req.Nullifier == "" {
		return nil, status.Errorf(codes.InvalidArgument, "nullifier is required")
	}

	rec, err := s.store.GetVerification(ctx, req.Nullifier)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "internal error")
	}
	if rec == nil {
		return nil, status.Errorf(codes.NotFound, "nullifier not found")
	}

	return &pb.GetVerificationStatusResponse{
		Nullifier:   rec.Nullifier,
		IdVerified:  rec.IDVerified,
		ProofType:   rec.ProofType,
		VerifiedAt:  rec.VerifiedAt.Format(time.RFC3339),
		ChallengeId: rec.ChallengeID,
	}, nil
}

// parseCertChainType validates the cert_chain_type field.
func parseCertChainType(s string) (linkverify.ProofType, error) {
	switch s {
	case "", "rs2048":
		return linkverify.ProofTypeRS2048, nil
	case "rs4096":
		return linkverify.ProofTypeRS4096, nil
	default:
		return "", errors.New("invalid cert_chain_type: must be rs2048 or rs4096")
	}
}

func storeErrorToGRPC(err error) error {
	switch {
	case errors.Is(err, store.ErrDuplicateNullifier):
		return status.Errorf(codes.AlreadyExists, "nullifier already registered")
	case errors.Is(err, store.ErrChallengeNotFound):
		return status.Errorf(codes.NotFound, "challenge not found")
	case errors.Is(err, store.ErrChallengeExpired):
		return status.Errorf(codes.FailedPrecondition, "challenge expired")
	case errors.Is(err, store.ErrChallengeConsumed):
		return status.Errorf(codes.FailedPrecondition, "challenge already consumed")
	default:
		return status.Errorf(codes.Internal, "internal error")
	}
}
