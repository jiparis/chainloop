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

package cmd

import (
	"fmt"
	"strings"

	"github.com/chainloop-dev/chainloop/app/cli/internal/action"
	schemaapi "github.com/chainloop-dev/chainloop/app/controlplane/api/workflowcontract/v1"
	"github.com/spf13/cobra"
)

func newPolicyDevelopEvalCmd() *cobra.Command {
	var (
		materialPath string
		kind         string
		annotations  []string
		policyPath   string
		inputs       []string
	)

	cmd := &cobra.Command{
		Use:   "eval",
		Short: "Evaluate policy against provided material",
		Long: `Perform a full evaluation of the policy against the provided material type.
The command checks if there is a path in the policy for the specified kind and
evaluates the policy against the provided material or attestation.`,
		Example: `  
  # Evaluate policy against a material file
  chainloop policy eval --policy policy.yaml --material sbom.json --kind SBOM_CYCLONEDX_JSON --annotation key1=value1,key2=value2 --input key3=value3`,
		RunE: func(_ *cobra.Command, _ []string) error {
			opts := &action.PolicyEvalOpts{
				MaterialPath: materialPath,
				Kind:         kind,
				Annotations:  parseKeyValue(annotations),
				PolicyPath:   policyPath,
				Inputs:       parseKeyValue(inputs),
			}

			policyEval, err := action.NewPolicyEval(opts, actionOpts)
			if err != nil {
				return fmt.Errorf("failed to initialize policy evaluation: %w", err)
			}

			result, err := policyEval.Run()
			if err != nil {
				return newGracefulError(err)
			}

			switch {
			case result.Skipped:
				logger.Info().Msg("policy evaluation skipped")
				for _, reason := range result.SkipReasons {
					logger.Info().Msgf("%s", reason)
				}

			case len(result.Violations) > 0:
				for _, violation := range result.Violations {
					logger.Info().Msgf("- %s", violation)
				}
				logger.Info().Msg("policy evaluation failed")

			default:
				if result.Ignored {
					logger.Info().Msg("policy was ignored")
				}
				logger.Info().Msg("policy evaluation passed")
			}

			return nil
		},
	}

	cmd.Flags().StringVar(&materialPath, "material", "", "path to material or attestation file")
	cobra.CheckErr(cmd.MarkFlagRequired("material"))
	cmd.Flags().StringVar(&kind, "kind", "", fmt.Sprintf("kind of the material: %q", schemaapi.ListAvailableMaterialKind()))
	cmd.Flags().StringSliceVar(&annotations, "annotation", []string{}, "key-value pairs of material annotations (key=value)")
	cmd.Flags().StringVar(&policyPath, "policy", "", "path to custom policy file")
	cobra.CheckErr(cmd.MarkFlagRequired("policy"))
	cmd.Flags().StringSliceVar(&inputs, "input", []string{}, "key-value pairs of policy inputs (key=value)")

	return cmd
}

func parseKeyValue(raw []string) map[string]string {
	parsed := make(map[string]string)
	for _, a := range raw {
		if key, val, ok := strings.Cut(a, "="); ok {
			parsed[key] = val
		}
	}
	return parsed
}
