/*
Copyright 2024 Gravitational, Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package mfa

import (
	"context"

	"github.com/gravitational/trace"

	"github.com/gravitational/teleport/api/client/proto"
	mfav1 "github.com/gravitational/teleport/api/gen/proto/go/teleport/mfa/v1"
)

type MFACeremonyChallengeClient interface {
	// CreateAuthenticateChallenge creates and returns MFA challenges for a users registered MFA devices.
	CreateAuthenticateChallenge(ctx context.Context, in *proto.CreateAuthenticateChallengeRequest) (*proto.MFAAuthenticateChallenge, error)
}

type MFACeremonyPromptClient interface {
	// PromptMFA prompts the user for MFA.
	PromptMFA(ctx context.Context, chal *proto.MFAAuthenticateChallenge, promptOpts ...PromptOpt) (*proto.MFAAuthenticateResponse, error)
}

// PerformMFACeremony retrieves an MFA challenge from the server with the given challenge extensions
// and prompts the user to answer the challenge with the given promptOpts, and ultimately returning
// an MFA challenge response for the user.
func PerformMFACeremony(ctx context.Context, chalClient MFACeremonyChallengeClient, promptClient MFACeremonyPromptClient, challengeRequest *proto.CreateAuthenticateChallengeRequest, promptOpts ...PromptOpt) (*proto.MFAAuthenticateResponse, error) {
	if challengeRequest == nil {
		return nil, trace.BadParameter("missing challenge request")
	}

	if challengeRequest.ChallengeExtensions == nil {
		return nil, trace.BadParameter("missing challenge extensions")
	}

	if challengeRequest.ChallengeExtensions.Scope == mfav1.ChallengeScope_CHALLENGE_SCOPE_UNSPECIFIED {
		return nil, trace.BadParameter("mfa challenge scope must be specified")
	}

	chal, err := chalClient.CreateAuthenticateChallenge(ctx, challengeRequest)
	if err != nil {
		// CreateAuthenticateChallenge returns a bad parameter error when the client
		// user is not a Teleport user - for example, the AdminRole. Treat this as an MFA
		// not supported error so the client knows when it can be ignored.
		if trace.IsBadParameter(err) {
			return nil, &ErrMFANotSupported
		}
		return nil, trace.Wrap(err)
	}

	// If an MFA required check was provided, and the client discovers MFA is not required,
	// skip the MFA prompt and return an empty response.
	if chal.MFARequired == proto.MFARequired_MFA_REQUIRED_NO {
		return nil, &ErrMFANotRequired
	}

	return promptClient.PromptMFA(ctx, chal, promptOpts...)
}

type MFACeremony func(ctx context.Context, challengeRequest *proto.CreateAuthenticateChallengeRequest, promptOpts ...PromptOpt) (*proto.MFAAuthenticateResponse, error)

// PerformAdminActionMFACeremony retrieves an MFA challenge from the server for an admin
// action, prompts the user to answer the challenge, and returns the resulting MFA response.
func PerformAdminActionMFACeremony(ctx context.Context, mfaCeremony MFACeremony, allowReuse bool) (*proto.MFAAuthenticateResponse, error) {
	allowReuseExt := mfav1.ChallengeAllowReuse_CHALLENGE_ALLOW_REUSE_NO
	if allowReuse {
		allowReuseExt = mfav1.ChallengeAllowReuse_CHALLENGE_ALLOW_REUSE_YES
	}

	challengeRequest := &proto.CreateAuthenticateChallengeRequest{
		Request: &proto.CreateAuthenticateChallengeRequest_ContextUser{},
		MFARequiredCheck: &proto.IsMFARequiredRequest{
			Target: &proto.IsMFARequiredRequest_AdminAction{
				AdminAction: &proto.AdminAction{},
			},
		},
		ChallengeExtensions: &mfav1.ChallengeExtensions{
			Scope:      mfav1.ChallengeScope_CHALLENGE_SCOPE_ADMIN_ACTION,
			AllowReuse: allowReuseExt,
		},
	}

	return mfaCeremony(ctx, challengeRequest, WithPromptReasonAdminAction())
}
