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

package action

import (
	"fmt"

	"github.com/chainloop-dev/chainloop/app/cli/internal/policydevel"
)

type PolicyInitOpts struct {
	Force       bool
	Embedded    bool
	Name        string
	Description string
	Directory   string
}

type PolicyInit struct {
	*ActionsOpts
	opts *PolicyInitOpts
}

func NewPolicyInit(opts *PolicyInitOpts, actionOpts *ActionsOpts) (*PolicyInit, error) {
	return &PolicyInit{
		ActionsOpts: actionOpts,
		opts:        opts,
	}, nil
}

func (action *PolicyInit) Run() error {
	initOpts := &policydevel.InitOptions{
		Directory:   action.opts.Directory,
		Embedded:    action.opts.Embedded,
		Force:       action.opts.Force,
		Name:        action.opts.Name,
		Description: action.opts.Description,
	}

	if err := policydevel.Initialize(initOpts); err != nil {
		return fmt.Errorf("initializing policy: %w", err)
	}

	return nil
}
