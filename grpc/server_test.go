package grpc

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/zkmopro/go-zkid-verifier/linkverify"
	"github.com/zkmopro/go-zkid-verifier/store"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestMapServiceError(t *testing.T) {
	cases := []struct {
		name     string
		err      error
		wantCode codes.Code
	}{
		{"duplicate nullifier", store.ErrDuplicateNullifier, codes.AlreadyExists},
		{"challenge not found", store.ErrChallengeNotFound, codes.NotFound},
		{"challenge expired", store.ErrChallengeExpired, codes.FailedPrecondition},
		{"challenge consumed", store.ErrChallengeConsumed, codes.FailedPrecondition},
		{"smt root unavailable", linkverify.ErrSmtRootUnavailable, codes.Unavailable},
		{"wrapped smt root unavailable", fmt.Errorf("g2: %w", linkverify.ErrSmtRootUnavailable), codes.Unavailable},
		{"issuer cert unavailable", linkverify.ErrIssuerCertUnavailable, codes.Unavailable},
		{"wrapped issuer cert unavailable", fmt.Errorf("g3: %w", linkverify.ErrIssuerCertUnavailable), codes.Unavailable},
		{"unknown infra error", errors.New("boom"), codes.Internal},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := mapServiceError(c.err, "null-1")
			st, ok := status.FromError(got)
			if !ok {
				t.Fatalf("not a grpc status: %v", got)
			}
			if st.Code() != c.wantCode {
				t.Errorf("code: got %v, want %v", st.Code(), c.wantCode)
			}
		})
	}
}

func TestMapServiceError_DuplicateNullifierIncludesNullifier(t *testing.T) {
	got := mapServiceError(store.ErrDuplicateNullifier, "abc-123")
	st, _ := status.FromError(got)
	if !strings.Contains(st.Message(), "abc-123") {
		t.Errorf("message missing nullifier: got %q", st.Message())
	}
}

func TestIssuerModulusOutcomeToProto(t *testing.T) {
	out := issuerModulusOutcomeToProto(&linkverify.IssuerModulusOutcome{
		IssuerName:     "g2",
		Match:          true,
		ExpectedSHA256: "0xc4c4",
		TrustSource:    "embedded",
	})
	if out == nil {
		t.Fatal("got nil, want proto outcome")
	}
	if out.Issuer != "g2" || !out.Match || out.ExpectedSha256 != "0xc4c4" || out.TrustSource != "embedded" {
		t.Errorf("fields not propagated: %+v", out)
	}
}

func TestIssuerModulusOutcomeToProto_Nil(t *testing.T) {
	if got := issuerModulusOutcomeToProto(nil); got != nil {
		t.Errorf("got %+v, want nil", got)
	}
}
