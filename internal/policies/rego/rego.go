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

package rego

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"

	"github.com/chainloop-dev/chainloop/internal/policies"
	"github.com/open-policy-agent/opa/ast"
	"github.com/open-policy-agent/opa/rego"
)

type Rego struct {
}

func (r *Rego) Verify(ctx context.Context, policy *policies.Policy, input []byte) ([]policies.PolicyViolation, error) {
	policyString := string(policy.Module)
	parsedModule, err := ast.ParseModule(policy.Name, policyString)
	if err != nil {
		return nil, fmt.Errorf("failed to parse rego policy: %w", err)
	}

	// Decode input as json
	decoder := json.NewDecoder(bytes.NewReader(input))
	decoder.UseNumber()
	var decodedInput interface{}
	if err := decoder.Decode(&decodedInput); err != nil {
		return nil, fmt.Errorf("failed to parse input: %w", err)
	}

	// add input
	regoInput := rego.Input(decodedInput)
	// add module
	regoFunc := rego.ParsedModule(parsedModule)
	// add query
	query := rego.Query(fmt.Sprintf("%v.deny\n", parsedModule.Package.Path))
	regoEval := rego.New(regoInput, regoFunc, query)

	res, err := regoEval.Eval(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to evaluate policy: %w", err)
	}

	violations := make([]policies.PolicyViolation, 0)
	for _, exp := range res {
		for _, val := range exp.Expressions {
			denyReasons, ok := val.Value.([]interface{})
			if !ok {
				return nil, fmt.Errorf("failed to evaluate policy expression evaluation result: %s", val.Text)
			}

			for _, reason := range denyReasons {
				reasonStr, ok := reason.(string)
				if !ok {
					return nil, fmt.Errorf("failed to evaluate deny reason: %s", val.Text)
				}

				violations = append(violations, policies.PolicyViolation{
					Subject:   policy.Name,
					Violation: reasonStr,
				})
			}
		}
	}

	return violations, nil
}