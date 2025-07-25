//
// Copyright 2023 The Chainloop Authors.
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
	"errors"
	"testing"

	"github.com/chainloop-dev/chainloop/app/controlplane/pkg/biz"
	"github.com/chainloop-dev/chainloop/app/controlplane/pkg/biz/testhelpers"
	"github.com/chainloop-dev/chainloop/app/controlplane/plugins/sdk/v1"
	integrationMocks "github.com/chainloop-dev/chainloop/app/controlplane/plugins/sdk/v1/mocks"
	creds "github.com/chainloop-dev/chainloop/pkg/credentials/mocks"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
	"google.golang.org/protobuf/types/known/structpb"
)

func (s *testSuite) TestCreate() {
	const kind = "my-integration"
	assert := assert.New(s.T())

	// Mocked integration that will return both generic configuration and credentials
	integration := integrationMocks.NewFanOut(s.T())

	ctx := context.Background()
	integration.On("Describe").Return(&sdk.IntegrationInfo{ID: kind}).Maybe()
	integration.On("ValidateRegistrationRequest", mock.Anything).Maybe().Return(nil)
	integration.On("Register", ctx, mock.Anything).Return(&sdk.RegistrationResponse{
		Configuration: s.config, Credentials: &sdk.Credentials{
			Password: "key", URL: "host"},
	}, nil).Maybe()

	testCases := []struct {
		caseName    string
		orgID       string
		name        string
		description string
		wantErrMsg  string
	}{
		{
			caseName:   "org missing",
			wantErrMsg: "required",
		},
		{
			caseName:   "name missing",
			orgID:      s.org.ID,
			wantErrMsg: "required",
		},
		{
			caseName:   "invalid name",
			orgID:      s.org.ID,
			name:       "invalid name",
			wantErrMsg: "RFC 1123",
		},
		{
			caseName: "with valid name",
			orgID:    s.org.ID,
			name:     "valid-name",
		},
		{
			caseName:    "with valid name and description",
			orgID:       s.org.ID,
			name:        "valid-name-2",
			description: "valid description",
		},
		{
			caseName:   "with duplicated name",
			orgID:      s.org.ID,
			name:       "valid-name",
			wantErrMsg: "name already taken",
		},
	}

	for _, tc := range testCases {
		s.Run(tc.caseName, func() {
			got, err := s.Integration.RegisterAndSave(ctx, tc.orgID, tc.name, tc.description, integration, s.configStruct)
			if tc.wantErrMsg != "" {
				s.ErrorContains(err, tc.wantErrMsg)
				return
			}

			require.NoError(s.T(), err)
			assert.Equal(kind, got.Kind)
			assert.Equal(tc.name, got.Name)
			assert.Equal(tc.description, got.Description)
			// Check configuration was stored
			assert.Equal(s.config, got.Config)
			// Check credential was stored
			assert.Equal("stored-integration-secret", got.SecretName)
		})
	}
}

func (s *testSuite) TestAttachWorkflow() {
	assert := assert.New(s.T())
	s.Run("org does not exist", func() {
		_, err := s.Integration.AttachToWorkflow(context.Background(), &biz.AttachOpts{
			OrgID:             uuid.NewString(),
			IntegrationID:     s.integration.ID.String(),
			WorkflowID:        s.workflow.ID.String(),
			FanOutIntegration: s.fanOutIntegration,
			AttachmentConfig:  s.configStruct,
		})
		assert.ErrorAs(err, &biz.ErrNotFound{})
	})

	s.Run("workflow does not exist", func() {
		_, err := s.Integration.AttachToWorkflow(context.Background(), &biz.AttachOpts{
			OrgID:             s.org.ID,
			IntegrationID:     s.integration.ID.String(),
			WorkflowID:        uuid.NewString(),
			FanOutIntegration: s.fanOutIntegration,
			AttachmentConfig:  s.configStruct,
		})
		assert.ErrorAs(err, &biz.ErrNotFound{})
	})

	s.Run("workflow belongs to another org", func() {
		_, err := s.Integration.AttachToWorkflow(context.Background(), &biz.AttachOpts{
			OrgID:             s.emptyOrg.ID,
			IntegrationID:     s.integration.ID.String(),
			WorkflowID:        s.workflow.ID.String(),
			FanOutIntegration: s.fanOutIntegration,
			AttachmentConfig:  s.configStruct,
		})
		assert.ErrorAs(err, &biz.ErrNotFound{})
	})

	s.Run("integration does not exist", func() {
		_, err := s.Integration.AttachToWorkflow(context.Background(), &biz.AttachOpts{
			OrgID:             s.org.ID,
			IntegrationID:     uuid.NewString(),
			WorkflowID:        s.workflow.ID.String(),
			FanOutIntegration: s.fanOutIntegration,
			AttachmentConfig:  s.configStruct,
		})
		assert.ErrorAs(err, &biz.ErrNotFound{})
	})

	s.Run("integration belongs to another org", func() {
		_, err := s.Integration.AttachToWorkflow(context.Background(), &biz.AttachOpts{
			OrgID:             s.emptyOrg.ID,
			IntegrationID:     s.integration.ID.String(),
			WorkflowID:        s.workflow.ID.String(),
			FanOutIntegration: s.fanOutIntegration,
			AttachmentConfig:  s.configStruct,
		})
		assert.ErrorAs(err, &biz.ErrNotFound{})
	})

	s.Run("attachable not provided", func() {
		_, err := s.Integration.AttachToWorkflow(context.Background(), &biz.AttachOpts{
			OrgID:             s.org.ID,
			IntegrationID:     s.integration.ID.String(),
			WorkflowID:        s.workflow.ID.String(),
			FanOutIntegration: nil,
			AttachmentConfig:  s.configStruct,
		})
		assert.ErrorAs(err, &biz.ErrValidation{})
	})

	s.Run("attachment OK", func() {
		ctx := context.Background()
		s.fanOutIntegration.On("Attach", ctx, mock.Anything).Return(&sdk.AttachmentResponse{
			Configuration: s.config,
		}, nil).Once()
		s.fanOutIntegration.On("ValidateAttachmentRequest", mock.Anything).Return(nil)

		got, err := s.Integration.AttachToWorkflow(ctx, &biz.AttachOpts{
			OrgID:             s.org.ID,
			IntegrationID:     s.integration.ID.String(),
			WorkflowID:        s.workflow.ID.String(),
			FanOutIntegration: s.fanOutIntegration,
			AttachmentConfig:  s.configStruct,
		})
		assert.NoError(err)

		// Check configuration was stored
		assert.Equal(s.config, got.Config)
		assert.Equal(s.integration.ID, got.IntegrationID)
		assert.Equal(s.workflow.ID, got.WorkflowID)

		// Make sure it has been stored
		attachments, err := s.Integration.ListAttachments(ctx, s.org.ID, &biz.ListAttachmentsOpts{WorkflowID: &s.workflow.ID})
		assert.NoError(err)
		assert.Len(attachments, 1)
	})

	s.Run("attachment fails", func() {
		ctx := context.Background()
		s.fanOutIntegration.On("Attach", ctx, mock.Anything).Return(nil, errors.New("invalid attachment options")).Once()
		s.fanOutIntegration.On("ValidateAttachmentRequest", mock.Anything).Return(nil)

		_, err := s.Integration.AttachToWorkflow(ctx, &biz.AttachOpts{
			OrgID:             s.org.ID,
			IntegrationID:     s.integration.ID.String(),
			WorkflowID:        s.workflow.ID.String(),
			FanOutIntegration: s.fanOutIntegration,
			AttachmentConfig:  s.configStruct,
		})
		assert.ErrorAs(err, &biz.ErrValidation{})
		assert.ErrorContains(err, "invalid attachment options")
	})
}

func (s *testSuite) TestListAttachments() {
	assert := assert.New(s.T())
	ctx := context.Background()

	s.fanOutIntegration.On("Attach", ctx, mock.Anything).Return(&sdk.AttachmentResponse{
		Configuration: s.config,
	}, nil).Once()
	s.fanOutIntegration.On("ValidateAttachmentRequest", mock.Anything).Return(nil)

	// Attach the integration to the workflow
	_, err := s.Integration.AttachToWorkflow(ctx, &biz.AttachOpts{
		OrgID:             s.org.ID,
		IntegrationID:     s.integration.ID.String(),
		WorkflowID:        s.workflow.ID.String(),
		FanOutIntegration: s.fanOutIntegration,
		AttachmentConfig:  s.configStruct,
	})
	assert.NoError(err)

	// List the attachments
	attachments, err := s.Integration.ListAttachments(ctx, s.org.ID, &biz.ListAttachmentsOpts{WorkflowID: &s.workflow.ID})
	assert.NoError(err)
	assert.Len(attachments, 1)
	assert.NotNil(attachments[0].Integration)
	assert.NotNil(attachments[0].IntegrationAttachment)
	assert.Equal(s.integration.ID, attachments[0].Integration.ID)
	assert.Equal(s.integration.Name, attachments[0].Integration.Name)
	assert.Equal(s.integration.Kind, attachments[0].Integration.Kind)
	assert.Equal(s.integration.Description, attachments[0].Integration.Description)
	assert.Equal(s.integration.Config, attachments[0].Integration.Config)
	assert.Equal(s.integration.SecretName, attachments[0].Integration.SecretName)
	assert.Equal(s.workflow.ID, attachments[0].WorkflowID)
	assert.Equal(s.config, attachments[0].IntegrationAttachment.Config)
}

func (s *testSuite) SetupTest() {
	t := s.T()
	assert := assert.New(t)
	ctx := context.Background()

	// Override credentials writer to set expectations
	s.mockedCredsReaderWriter = creds.NewReaderWriter(t)
	// integration credentials
	s.mockedCredsReaderWriter.On(
		"SaveCredentials", ctx, mock.Anything, &sdk.Credentials{URL: "host", Password: "key"},
	).Return("stored-integration-secret", nil).Maybe()

	s.TestingUseCases = testhelpers.NewTestingUseCases(t, testhelpers.WithCredsReaderWriter(s.mockedCredsReaderWriter))

	var err error
	// Create org, integration and oci repository
	s.org, err = s.Organization.Create(ctx, "testing-org")
	assert.NoError(err)
	s.emptyOrg, err = s.Organization.Create(ctx, "empty-org")
	assert.NoError(err)

	// Workflow
	s.workflow, err = s.Workflow.Create(ctx, &biz.WorkflowCreateOpts{Name: "test-workflow", OrgID: s.org.ID, Project: "test-project"})
	assert.NoError(err)

	// Integration configuration
	s.configStruct, err = structpb.NewStruct(map[string]interface{}{"firstName": "John"})
	assert.NoError(err)

	s.config = []byte("deadbeef")

	// Mocked fanOut that will return both generic configuration and credentials
	fanOut := integrationMocks.NewFanOut(s.T())
	fanOut.On("Describe").Return(&sdk.IntegrationInfo{})
	fanOut.On("ValidateRegistrationRequest", mock.Anything).Return(nil)
	fanOut.On("Register", ctx, mock.Anything).Return(&sdk.RegistrationResponse{Configuration: s.config}, nil)
	s.fanOutIntegration = fanOut

	s.integration, err = s.Integration.RegisterAndSave(ctx, s.org.ID, "my-registration", "my integration instance", fanOut, s.configStruct)
	assert.NoError(err)
}

// Run the tests
func TestIntegration(t *testing.T) {
	suite.Run(t, new(testSuite))
}

// Utility struct to hold the test suite
type testSuite struct {
	testhelpers.UseCasesEachTestSuite
	org, emptyOrg           *biz.Organization
	workflow                *biz.Workflow
	integration             *biz.Integration
	mockedCredsReaderWriter *creds.ReaderWriter
	config                  []byte
	configStruct            *structpb.Struct
	fanOutIntegration       *integrationMocks.FanOut
}
