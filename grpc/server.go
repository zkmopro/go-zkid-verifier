package grpc

import (
	"context"
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
		return nil, status.Errorf(codes.Internal, "failed to create challenge: %v", err)
	}
	return &pb.CreateChallengeResponse{
		ChallengeId:    c.ID,
		ChallengeBytes: c.BytesHex,
		ExpiresAt:      c.ExpiresAt.Format(time.RFC3339),
	}, nil
}

func (s *Server) GetChallenge(ctx context.Context, req *pb.GetChallengeRequest) (*pb.GetChallengeResponse, error) {
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
	if len(req.CertChainProof) == 0 || len(req.DeviceSigProof) == 0 {
		return nil, status.Errorf(codes.InvalidArgument, "cert_chain_proof and device_sig_proof are required")
	}
	if req.Nullifier == "" {
		return nil, status.Errorf(codes.InvalidArgument, "nullifier is required")
	}

	pt := linkverify.ProofTypeRS2048
	if req.CertChainType == "rs4096" {
		pt = linkverify.ProofTypeRS4096
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
		return nil, status.Errorf(codes.Internal, "verification failed: %v", err)
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

func storeErrorToGRPC(err error) error {
	switch {
	case err == store.ErrDuplicateNullifier:
		return status.Errorf(codes.AlreadyExists, "nullifier already registered")
	case err == store.ErrChallengeNotFound:
		return status.Errorf(codes.NotFound, "challenge not found")
	case err == store.ErrChallengeExpired:
		return status.Errorf(codes.FailedPrecondition, "challenge expired")
	case err == store.ErrChallengeConsumed:
		return status.Errorf(codes.FailedPrecondition, "challenge already consumed")
	default:
		return status.Errorf(codes.Internal, "internal error")
	}
}
