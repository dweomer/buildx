package policy

import (
	"errors"
	"testing"

	gwpb "github.com/moby/buildkit/frontend/gateway/pb"
	solverpb "github.com/moby/buildkit/solver/pb"
	"github.com/moby/buildkit/sourcepolicy/policysession"
	"github.com/stretchr/testify/require"
)

func TestPolicyIsPolicyErrorMatchesRecordedSource(t *testing.T) {
	p := NewPolicy(Opt{})
	req := &policysession.CheckPolicyRequest{
		Source: &gwpb.ResolveSourceMetaResponse{
			Source: &solverpb.SourceOp{
				Identifier: "docker-image://busybox:latest",
			},
		},
	}
	p.recordDenyIdentifier(req)

	err := errors.New("failed to solve: error evaluating the source policy: source \"docker-image://busybox:latest\" not allowed by policy: action DENY")
	require.True(t, p.IsPolicyError(err))
}

func TestPolicyIsPolicyErrorDoesNotMatchWithoutBuildkitPattern(t *testing.T) {
	p := NewPolicy(Opt{})
	req := &policysession.CheckPolicyRequest{
		Source: &gwpb.ResolveSourceMetaResponse{
			Source: &solverpb.SourceOp{
				Identifier: "docker-image://busybox:latest",
			},
		},
	}
	p.recordDenyIdentifier(req)

	err := errors.New("failed to parse dockerfile for docker-image://busybox:latest")
	require.False(t, p.IsPolicyError(err))
}

func TestPolicyIsPolicyErrorDoesNotMatchUnrelatedError(t *testing.T) {
	p := NewPolicy(Opt{})
	req := &policysession.CheckPolicyRequest{
		Source: &gwpb.ResolveSourceMetaResponse{
			Source: &solverpb.SourceOp{
				Identifier: "docker-image://busybox:latest",
			},
		},
	}
	p.recordDenyIdentifier(req)

	err := errors.New("failed to solve: error evaluating the source policy: source \"docker-image://alpine:latest\" not allowed by policy: action DENY")
	require.False(t, p.IsPolicyError(err))
}
