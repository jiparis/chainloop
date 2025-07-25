//
// Copyright 2025 The Chainloop Authors.
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

package materials

import (
	"context"
	"encoding/json"
	"fmt"
	"os"

	schemaapi "github.com/chainloop-dev/chainloop/app/controlplane/api/workflowcontract/v1"
	"github.com/chainloop-dev/chainloop/internal/schemavalidators"
	api "github.com/chainloop-dev/chainloop/pkg/attestation/crafter/api/attestation/v1"
	"github.com/chainloop-dev/chainloop/pkg/casclient"
	"github.com/rs/zerolog"
)

type RunnerContextCrafter struct {
	backend *casclient.CASBackend
	*crafterCommon
}

func NewRunnerContextCrafter(materialSchema *schemaapi.CraftingSchema_Material, backend *casclient.CASBackend, l *zerolog.Logger) (*RunnerContextCrafter, error) {
	if materialSchema.Type != schemaapi.CraftingSchema_Material_CHAINLOOP_RUNNER_CONTEXT {
		return nil, fmt.Errorf("material type is not Chainloop runner context")
	}

	return &RunnerContextCrafter{
		backend:       backend,
		crafterCommon: &crafterCommon{logger: l, input: materialSchema},
	}, nil
}

func (r *RunnerContextCrafter) Craft(ctx context.Context, filePath string) (*api.Attestation_Material, error) {
	f, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("can't open the file: %w", err)
	}

	var v interface{}
	if err := json.Unmarshal(f, &v); err != nil {
		r.logger.Debug().Err(err).Msg("error decoding file")
		return nil, fmt.Errorf("invalid Chainloop runner context file: %w", ErrInvalidMaterialType)
	}

	// Setting the version to empty string to validate against the latest version of the schema
	err = schemavalidators.ValidateChainloopRunnerContext(v, "")
	if err != nil {
		r.logger.Debug().Err(err).Msgf("error decoding file: %#v", err)
		return nil, fmt.Errorf("invalid Chainloop runner context file: %w", ErrInvalidMaterialType)
	}

	return uploadAndCraft(ctx, r.input, r.backend, filePath, r.logger)
}
