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
	"context"

	"github.com/chainloop-dev/chainloop/internal/policies"
	"github.com/open-policy-agent/opa/rego"
)

type Rego struct {
}

func (r Rego) CheckPolicy(policy string, input any) ([]policies.PolicyViolation, error) {
	module := `
package example.authz

import rego.v1

default allow := false

allow if {
    input.method == "GET"
    input.path == ["salary", input.subject.user]
}

allow if is_admin

is_admin if "admin" in input.subject.groups
`

	ctx := context.TODO()

	query, err := rego.New(
		rego.Query("x = data.example.authz.allow"),
		rego.Module("example.rego", module),
	).PrepareForEval(ctx)

	if err != nil {
		// Handle error.
	}

	results, err := query.Eval(ctx, rego.EvalInput(input))
}
