//
// Copyright 2024-2025 The Chainloop Authors.
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

package biz_test

import (
	"context"
	"os"
	"testing"

	schemav1 "github.com/chainloop-dev/chainloop/app/controlplane/api/workflowcontract/v1"
	"github.com/chainloop-dev/chainloop/app/controlplane/pkg/biz"
	"github.com/chainloop-dev/chainloop/app/controlplane/pkg/biz/testhelpers"
	"github.com/chainloop-dev/chainloop/app/controlplane/pkg/unmarshal"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
)

func (s *workflowContractIntegrationTestSuite) TestUpdate() {
	ctx := context.Background()

	updatedSchema := &schemav1.CraftingSchema{SchemaVersion: "v1", Runner: &schemav1.CraftingSchema_Runner{Type: schemav1.CraftingSchema_Runner_AZURE_PIPELINE}}
	updatedSchemaRawFormat, err := biz.SchemaToRawContract(updatedSchema)
	require.NoError(s.T(), err)

	updatedSchemaInYAML := &biz.Contract{Format: unmarshal.RawFormatYAML, Raw: []byte(`schemaVersion: v1`)}

	testCases := []struct {
		name                string
		orgID, contractName string
		input               *biz.WorkflowContractUpdateOpts
		inputSchema         *biz.Contract
		wantErrMsg          string
		wantRevision        int
		wantDescription     string
	}{
		{
			name:       "non-updates",
			wantErrMsg: "no updates",
		},
		{
			name:         "non-existing contract",
			orgID:        s.org.ID,
			input:        &biz.WorkflowContractUpdateOpts{},
			contractName: uuid.NewString(),
			wantErrMsg:   "not found",
		},
		{
			name:         "updating schema bumps revision",
			orgID:        s.org.ID,
			contractName: s.contractOrg1.Name,
			input:        &biz.WorkflowContractUpdateOpts{},
			inputSchema:  updatedSchemaRawFormat,
			wantRevision: 2,
		},
		{
			name:         "updating with same schema DOES NOT bump revision",
			orgID:        s.org.ID,
			contractName: s.contractOrg1.Name,
			input:        &biz.WorkflowContractUpdateOpts{},
			inputSchema:  updatedSchemaRawFormat,
			wantRevision: 2,
		},
		{
			name:            "updating description does not bump revision",
			orgID:           s.org.ID,
			contractName:    s.contractOrg1.Name,
			input:           &biz.WorkflowContractUpdateOpts{Description: toPtrS("new description")},
			wantDescription: "new description",
			wantRevision:    2,
		},
		{
			name:         "the format of the contract can be updated to yaml",
			orgID:        s.org.ID,
			contractName: s.contractOrg1.Name,
			input:        &biz.WorkflowContractUpdateOpts{},
			inputSchema:  updatedSchemaInYAML,
			wantRevision: 3,
		},
		{
			name:         "it validates the format of the contract",
			orgID:        s.org.ID,
			contractName: s.contractOrg1.Name,
			input: &biz.WorkflowContractUpdateOpts{
				RawSchema: []byte(`{invalid: yaml`),
			},
			wantErrMsg:   "format not found",
			wantRevision: 3,
		},
		{
			name:         "it validates contract is valid",
			orgID:        s.org.ID,
			contractName: s.contractOrg1.Name,
			input: &biz.WorkflowContractUpdateOpts{
				RawSchema: []byte(`apiVersion: v12`),
			},
			wantErrMsg:   "validation error",
			wantRevision: 3,
		},
	}

	for _, tc := range testCases {
		s.Run(tc.name, func() {
			if tc.inputSchema != nil {
				tc.input.RawSchema = tc.inputSchema.Raw
			}

			contract, err := s.WorkflowContract.Update(ctx, tc.orgID, tc.contractName, tc.input)
			if tc.wantErrMsg != "" {
				s.ErrorContains(err, tc.wantErrMsg)
				return
			}
			require.NoError(s.T(), err)

			if tc.wantDescription != "" {
				s.Equal(tc.wantDescription, contract.Contract.Description)
			}

			if tc.inputSchema != nil {
				s.Equal(tc.inputSchema.Raw, contract.Version.Schema.Raw)
				s.Equal(tc.inputSchema.Format, contract.Version.Schema.Format)
			}

			s.NotNil(contract.Version.Schema.Schema)
			s.Equal(tc.wantRevision, contract.Version.Revision)
		})
	}
}

func (s *workflowContractIntegrationTestSuite) TestCreateDuplicatedName() {
	ctx := context.Background()

	const contractName = "name"
	contract, err := s.WorkflowContract.Create(ctx, &biz.WorkflowContractCreateOpts{OrgID: s.org.ID, Name: contractName})
	require.NoError(s.T(), err)

	s.Run("can't create a contract with the same name", func() {
		_, err := s.WorkflowContract.Create(ctx, &biz.WorkflowContractCreateOpts{OrgID: s.org.ID, Name: contractName})
		s.ErrorContains(err, "name already taken")
	})

	s.Run("but if we delete it we can", func() {
		err = s.WorkflowContract.Delete(ctx, s.org.ID, contract.ID.String())
		require.NoError(s.T(), err)

		_, err := s.WorkflowContract.Create(ctx, &biz.WorkflowContractCreateOpts{OrgID: s.org.ID, Name: contractName})
		require.NoError(s.T(), err)
	})
}

func (s *workflowContractIntegrationTestSuite) TestCreate() {
	ctx := context.Background()

	testCases := []struct {
		name            string
		input           *biz.WorkflowContractCreateOpts
		wantErrMsg      string
		wantName        string
		wantDescription string
	}{
		{
			name:       "org missing",
			input:      &biz.WorkflowContractCreateOpts{Name: "name"},
			wantErrMsg: "required",
		},
		{
			name:       "name missing",
			input:      &biz.WorkflowContractCreateOpts{OrgID: s.org.ID},
			wantErrMsg: "required",
		},
		{
			name:       "invalid name",
			input:      &biz.WorkflowContractCreateOpts{OrgID: s.org.ID, Name: "this/not/valid"},
			wantErrMsg: "RFC 1123",
		},
		{
			name:       "another invalid name",
			input:      &biz.WorkflowContractCreateOpts{OrgID: s.org.ID, Name: "this-not Valid"},
			wantErrMsg: "RFC 1123",
		},
		{
			name:  "non-existing contract name",
			input: &biz.WorkflowContractCreateOpts{OrgID: s.org.ID, Name: "name"},
		},
		{
			name:       "existing contract name",
			input:      &biz.WorkflowContractCreateOpts{OrgID: s.org.ID, Name: "name"},
			wantErrMsg: "taken",
		},
		{
			name:     "can create same name in different org",
			input:    &biz.WorkflowContractCreateOpts{OrgID: s.org2.ID, Name: "name"},
			wantName: "name",
		},
		{
			name:  "or ask to generate a random name",
			input: &biz.WorkflowContractCreateOpts{OrgID: s.org.ID, Name: "name", AddUniquePrefix: true},
		},
		{
			name:            "you can include a description",
			input:           &biz.WorkflowContractCreateOpts{OrgID: s.org.ID, Name: "name-2", Description: toPtrS("description")},
			wantName:        "name-2",
			wantDescription: "description",
		},
	}

	for _, tc := range testCases {
		s.Run(tc.name, func() {
			contract, err := s.WorkflowContract.Create(ctx, tc.input)
			if tc.wantErrMsg != "" {
				s.ErrorContains(err, tc.wantErrMsg)
				return
			}

			require.NoError(s.T(), err)
			s.NotEmpty(contract.ID)
			s.NotEmpty(contract.CreatedAt)

			if tc.wantDescription != "" {
				s.Equal(tc.wantDescription, contract.Description)
			}

			if tc.wantName != "" {
				s.Equal(tc.wantName, contract.Name)
			}
		})
	}
}

func (s *workflowContractIntegrationTestSuite) TestList() {
	ctx := context.Background()

	s.Run("by default it returns all the contracts from the org both global and scoped", func() {
		contracts, err := s.WorkflowContract.List(ctx, s.org.ID)
		s.NoError(err)
		s.Equal(3, len(contracts))
	})

	s.Run("if filtered by project it returns the contracts scoped to the project alongside the global contracts", func() {
		contracts, err := s.WorkflowContract.List(ctx, s.org.ID, biz.WithProjectFilter([]uuid.UUID{s.p1.ID}))
		s.NoError(err)
		s.Equal(2, len(contracts))
		s.Equal(s.contractScopedToProject.ID, contracts[0].ID)
		s.True(contracts[0].IsProjectScoped())
		s.Equal(s.contractOrg1.ID, contracts[1].ID)
		s.True(contracts[1].IsGlobalScoped())
	})
}

func (s *workflowContractIntegrationTestSuite) TestCreateWithCustomContract() {
	ctx := context.Background()

	testCases := []struct {
		name         string
		contractPath string
		wantErrMsg   string
		format       unmarshal.RawFormat
	}{
		{
			name:         "from-cue",
			contractPath: "testdata/contracts/contract.cue",
			format:       unmarshal.RawFormatCUE,
		},
		{
			name:         "from-yaml",
			contractPath: "testdata/contracts/contract.yaml",
			format:       unmarshal.RawFormatYAML,
		},
		{
			name:         "from-json",
			contractPath: "testdata/contracts/contract.json",
			format:       unmarshal.RawFormatJSON,
		},
		{
			name:         "invalid-contract",
			contractPath: "testdata/contracts/invalid_contract.json",
			wantErrMsg:   "validation error",
		},
		{
			name:         "invalid-json",
			contractPath: "testdata/contracts/invalid_format.json",
			wantErrMsg:   "format not found",
		},
	}

	for _, tc := range testCases {
		s.Run(tc.name, func() {
			d, err := os.ReadFile(tc.contractPath)
			require.NoError(s.T(), err)
			contract, err := s.WorkflowContract.Create(ctx, &biz.WorkflowContractCreateOpts{OrgID: s.org.ID, Name: tc.name, RawSchema: d})
			if tc.wantErrMsg != "" {
				s.ErrorContains(err, tc.wantErrMsg)
				return
			}
			require.NoError(s.T(), err)

			contractWithVersion, err := s.WorkflowContract.Describe(ctx, s.org.ID, contract.ID.String(), 1)
			require.NoError(s.T(), err)
			s.Equal(d, contractWithVersion.Version.Schema.Raw)
			s.Equal(tc.format, contractWithVersion.Version.Schema.Format)
			s.NotNil(contractWithVersion.Version.Schema.Schema)
		})
	}

	s.Run("not providing contract creates one automatically", func() {
		contract, err := s.WorkflowContract.Create(ctx, &biz.WorkflowContractCreateOpts{OrgID: s.org.ID, Name: "empty"})
		require.NoError(s.T(), err)
		contractWithVersion, err := s.WorkflowContract.Describe(ctx, s.org.ID, contract.ID.String(), 1)
		require.NoError(s.T(), err)
		s.Equal(biz.EmptyDefaultContract.Format, unmarshal.RawFormatYAML)
		s.Equal(biz.EmptyDefaultContract.Raw, contractWithVersion.Version.Schema.Raw)
		s.NotNil(contractWithVersion.Version.Schema.Schema)
	})
}

// Run the tests
func TestWorkflowContractUseCase(t *testing.T) {
	suite.Run(t, new(workflowContractIntegrationTestSuite))
}

// Utility struct to hold the test suite
type workflowContractIntegrationTestSuite struct {
	testhelpers.UseCasesEachTestSuite
	org, org2 *biz.Organization
	p1        *biz.Project

	contractOrg1            *biz.WorkflowContract
	contractScopedToProject *biz.WorkflowContract
}

func (s *workflowContractIntegrationTestSuite) SetupTest() {
	s.TestingUseCases = testhelpers.NewTestingUseCases(s.T())

	var err error
	ctx := context.Background()
	s.org, err = s.Organization.CreateWithRandomName(ctx)
	s.NoError(err)
	s.org2, err = s.Organization.CreateWithRandomName(ctx)
	s.NoError(err)

	s.p1, err = s.Project.Create(ctx, s.org.ID, "a-valid-project")
	s.NoError(err)

	p2, err := s.Project.Create(ctx, s.org.ID, "a-valid-project-2")
	s.NoError(err)

	s.contractOrg1, err = s.WorkflowContract.Create(ctx, &biz.WorkflowContractCreateOpts{OrgID: s.org.ID, Name: "a-valid-contract"})
	s.NoError(err)

	s.contractScopedToProject, err = s.WorkflowContract.Create(ctx, &biz.WorkflowContractCreateOpts{OrgID: s.org.ID, Name: "a-valid-contract-scoped-to-project", ProjectID: &s.p1.ID})
	s.NoError(err)

	_, err = s.WorkflowContract.Create(ctx, &biz.WorkflowContractCreateOpts{OrgID: s.org.ID, Name: "a-valid-contract-scoped-to-project-2", ProjectID: &p2.ID})
	s.Require().NoError(err)
}
