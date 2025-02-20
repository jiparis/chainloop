//
// Copyright 2024 The Chainloop Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package action

import (
	"context"
	"fmt"

	pb "github.com/chainloop-dev/chainloop/app/controlplane/api/controlplane/v1"
	"github.com/chainloop-dev/chainloop/pkg/attestation/crafter"
	"github.com/go-kratos/kratos/v2/errors"
)

const AttestationResetTriggerFailed = "failure"
const AttestationResetTriggerCancelled = "cancellation"

type AttestationResetOpts struct {
	*ActionsOpts
	LocalStatePath string
}

type AttestationReset struct {
	*ActionsOpts
	*newCrafterOpts
	localStatePath string
}

func NewAttestationReset(cfg *AttestationResetOpts) (*AttestationReset, error) {
	return &AttestationReset{
		newCrafterOpts: &newCrafterOpts{cpConnection: cfg.CPConnection, opts: []crafter.NewOpt{crafter.WithLogger(&cfg.Logger)}},
		ActionsOpts:    cfg.ActionsOpts, localStatePath: cfg.LocalStatePath}, nil
}

func (action *AttestationReset) Run(ctx context.Context, attestationID, trigger, reason string) error {
	// initialize the crafter. If attestation-id is provided we assume the attestation is performed using remote state
	crafter, err := newCrafter(&newCrafterStateOpts{enableRemoteState: attestationID != "", localStatePath: action.localStatePath}, action.CPConnection, action.newCrafterOpts.opts...)
	if err != nil {
		return fmt.Errorf("failed to load crafter: %w", err)
	}

	if initialized, err := crafter.AlreadyInitialized(ctx, attestationID); err != nil {
		return fmt.Errorf("checking if attestation is already initialized: %w", err)
	} else if !initialized {
		return ErrAttestationNotInitialized
	}

	if err := crafter.LoadCraftingState(ctx, attestationID); err != nil {
		action.Logger.Err(err).Msg("loading existing attestation")
		return err
	}

	if !crafter.CraftingState.DryRun {
		client := pb.NewAttestationServiceClient(action.CPConnection)
		if _, err := client.Cancel(context.Background(), &pb.AttestationServiceCancelRequest{
			WorkflowRunId: crafter.CraftingState.GetAttestation().GetWorkflow().GetWorkflowRunId(),
			Reason:        reason,
			Trigger:       parseTrigger(trigger),
		}); err != nil {
			if errors.IsNotFound(err) {
				action.Logger.Warn().Msg("workflow run not found in the control plane")
			} else {
				return err
			}
		}
	}

	return crafter.Reset(ctx, attestationID)
}

func parseTrigger(in string) pb.AttestationServiceCancelRequest_TriggerType {
	if in == AttestationResetTriggerFailed {
		return pb.AttestationServiceCancelRequest_TRIGGER_TYPE_FAILURE
	} else if in == AttestationResetTriggerCancelled {
		return pb.AttestationServiceCancelRequest_TRIGGER_TYPE_CANCELLATION
	}

	return pb.AttestationServiceCancelRequest_TRIGGER_TYPE_UNSPECIFIED
}
