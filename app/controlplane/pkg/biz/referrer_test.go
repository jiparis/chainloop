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

package biz

import (
	"bytes"
	"encoding/json"
	"os"
	"testing"

	conf "github.com/chainloop-dev/chainloop/app/controlplane/internal/conf/controlplane/config/v1"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/secure-systems-lab/go-securesystemslib/dsse"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
)

func (s *referrerTestSuite) TestInitialization() {
	testCases := []struct {
		name       string
		conf       *conf.ReferrerSharedIndex
		wantErrMsg string
	}{
		{
			name: "nil configuration",
		},
		{
			name: "disabled",
			conf: &conf.ReferrerSharedIndex{
				Enabled: false,
			},
		},
		{
			name: "enabled but without orgs",
			conf: &conf.ReferrerSharedIndex{
				Enabled: true,
			},
			wantErrMsg: "invalid shared index config: index is enabled, but no orgs are allowed",
		},
		{
			name: "enabled with invalid orgs",
			conf: &conf.ReferrerSharedIndex{
				Enabled:     true,
				AllowedOrgs: []string{"invalid"},
			},
			wantErrMsg: "invalid shared index config: invalid org id: invalid",
		},
		{
			name: "enabled with valid orgs",
			conf: &conf.ReferrerSharedIndex{
				Enabled:     true,
				AllowedOrgs: []string{"00000000-0000-0000-0000-000000000000"},
			},
		},
	}

	for _, tc := range testCases {
		s.T().Run(tc.name, func(t *testing.T) {
			_, err := NewReferrerUseCase(nil, nil, nil, nil, tc.conf, nil)
			if tc.wantErrMsg != "" {
				assert.EqualError(t, err, tc.wantErrMsg)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func (s *referrerTestSuite) TestExtractReferrers() {
	var fullAttReferrer = &Referrer{
		Digest: "sha256:63f811807585a7359882fc4e28bc8e08555d9743aa07a2965217b30ef2ba14a5",
		Kind:   "ATTESTATION",
	}

	var withDuplicatedRefferer = &Referrer{
		Digest: "sha256:decfbb49b42593ffc8be415cf9eef5532355d78bd6fcfe57b8e7750b2579b91b",
		Kind:   "ATTESTATION",
	}

	var withGitSubject = &Referrer{
		Digest: "sha256:2e9bf8e13acd112eff355787b2b72eb8af4ee51fc22c7e65611939f2225e1dc5",
		Kind:   "ATTESTATION",
	}

	testCases := []struct {
		name      string
		inputPath string
		expectErr bool
		want      []*Referrer
	}{
		{
			name:      "all materials linked bidirectionally to the attestation",
			inputPath: "testdata/attestations/full.json",
			want: []*Referrer{
				{
					Digest:       fullAttReferrer.Digest,
					Kind:         "ATTESTATION",
					Downloadable: true,
					Metadata: map[string]string{
						"contractName":             "",
						"contractVersion":          "",
						"name":                     "only-sbom",
						"organization":             "",
						"team":                     "",
						"project":                  "foo",
						"projectVersion":           "",
						"projectVersionPrerelease": "false",
						"hasPolicyViolations":      "false",
					},
					Annotations: map[string]string{
						"branch":   "stable",
						"toplevel": "true",
					},
					References: []*Referrer{
						{
							Digest: "sha256:264f55a6ff9cec2f4742a9faacc033b29f65c04dd4480e71e23579d484288d61",
							Kind:   "CONTAINER_IMAGE",
						},
						{
							Digest: "sha256:16159bb881eb4ab7eb5d8afc5350b0feeed1e31c0a268e355e74f9ccbe885e0c",
							Kind:   "SBOM_CYCLONEDX_JSON",
						},
					},
				},
				{
					Digest: "sha256:264f55a6ff9cec2f4742a9faacc033b29f65c04dd4480e71e23579d484288d61",
					Kind:   "CONTAINER_IMAGE",
					// There is a link back to the attestation
					References: []*Referrer{fullAttReferrer},
				},
				{
					Digest:       "sha256:16159bb881eb4ab7eb5d8afc5350b0feeed1e31c0a268e355e74f9ccbe885e0c",
					Kind:         "SBOM_CYCLONEDX_JSON",
					Downloadable: true,
					References:   []*Referrer{fullAttReferrer},
				},
			},
		},
		{
			name:      "with string value material to be discarded",
			inputPath: "testdata/attestations/with-string.json",
			want: []*Referrer{
				{
					Digest:       "sha256:9f270dcb263c228c55351d513ae367c611bdf8d3a3a066861b88e25722519e7b",
					Kind:         "ATTESTATION",
					Downloadable: true,
					References: []*Referrer{
						{
							Digest: "sha1:58442b61a6564df94857ff69ad7c340c55703e20",
							Kind:   "GIT_HEAD_COMMIT",
						},
					},
					Metadata: map[string]string{
						"contractName":             "",
						"contractVersion":          "",
						"name":                     "test",
						"organization":             "",
						"team":                     "",
						"project":                  "bar",
						"projectVersion":           "",
						"projectVersionPrerelease": "false",
						"hasPolicyViolations":      "false",
					},
					Annotations: map[string]string{
						"version": "oss",
					},
				},
				// the git commit a subject in the attestation
				{
					Digest: "sha1:58442b61a6564df94857ff69ad7c340c55703e20",
					Kind:   "GIT_HEAD_COMMIT",
					References: []*Referrer{
						{
							Digest: "sha256:9f270dcb263c228c55351d513ae367c611bdf8d3a3a066861b88e25722519e7b",
							Kind:   "ATTESTATION",
						},
					},
				},
			},
		},
		{
			name:      "with two materials with same digest",
			inputPath: "testdata/attestations/with-duplicated-sha.json",
			want: []*Referrer{
				{
					Digest:       withDuplicatedRefferer.Digest,
					Kind:         "ATTESTATION",
					Downloadable: true,
					Metadata: map[string]string{
						"contractName":             "",
						"contractVersion":          "",
						"name":                     "only-sbom",
						"organization":             "",
						"team":                     "",
						"project":                  "foo",
						"projectVersion":           "",
						"projectVersionPrerelease": "false",
						"hasPolicyViolations":      "false",
					},
					Annotations: map[string]string{
						"branch":   "stable",
						"toplevel": "true",
					},
					References: []*Referrer{
						{
							Digest: "sha256:264f55a6ff9cec2f4742a9faacc033b29f65c04dd4480e71e23579d484288d61",
							Kind:   "CONTAINER_IMAGE",
						},
						{
							Digest: "sha256:264f55a6ff9cec2f4742a9faacc033b29f65c04dd4480e71e23579d484288d61",
							Kind:   "SBOM_CYCLONEDX_JSON",
						},
						{
							Digest: "sha256:16159bb881eb4ab7eb5d8afc5350b0feeed1e31c0a268e355e74f9ccbe885e0c",
							Kind:   "SBOM_CYCLONEDX_JSON",
						},
					},
				},
				{
					Digest:     "sha256:264f55a6ff9cec2f4742a9faacc033b29f65c04dd4480e71e23579d484288d61",
					Kind:       "CONTAINER_IMAGE",
					References: []*Referrer{withDuplicatedRefferer},
				},
				{
					Digest:       "sha256:16159bb881eb4ab7eb5d8afc5350b0feeed1e31c0a268e355e74f9ccbe885e0c",
					Kind:         "SBOM_CYCLONEDX_JSON",
					Downloadable: true,
					References:   []*Referrer{withDuplicatedRefferer},
				},
				{
					Digest:       "sha256:264f55a6ff9cec2f4742a9faacc033b29f65c04dd4480e71e23579d484288d61",
					Kind:         "SBOM_CYCLONEDX_JSON",
					Downloadable: true,
					References:   []*Referrer{withDuplicatedRefferer},
				},
			},
		},
		{
			name:      "with git subject",
			inputPath: "testdata/attestations/with-git-subject.json",
			want: []*Referrer{
				// NOTE: the result is sorted by kind
				{
					Digest:       "sha256:385c4188b9c080499413f2e0fa0b3951ed107b5f0cb35c2f2b1f07a7be9a7512",
					Kind:         "ARTIFACT",
					Downloadable: true,
					References:   []*Referrer{withGitSubject},
				},
				{
					Digest:       withGitSubject.Digest,
					Kind:         "ATTESTATION",
					Downloadable: true,
					Metadata: map[string]string{
						"contractName":             "",
						"contractVersion":          "",
						"name":                     "test-new-types",
						"organization":             "my-org",
						"team":                     "my-team",
						"project":                  "test",
						"projectVersion":           "",
						"projectVersionPrerelease": "false",
						"hasPolicyViolations":      "false",
					},
					References: []*Referrer{
						{
							Digest: "sha256:fbd9335f55d83d8aaf9ab1a539b0f2a87b444e8c54f34c9a1ca9d7df15605db4",
							Kind:   "CONTAINER_IMAGE",
						},
						{
							Digest: "sha256:385c4188b9c080499413f2e0fa0b3951ed107b5f0cb35c2f2b1f07a7be9a7512",
							Kind:   "ARTIFACT",
						},
						{
							Digest: "sha256:c4a63494f9289dd9fd44f841efb4f5b52765c2de6332f2d86e5f6c0340b40a95",
							Kind:   "SARIF",
						},
						{
							Digest: "sha256:16159bb881eb4ab7eb5d8afc5350b0feeed1e31c0a268e355e74f9ccbe885e0c",
							Kind:   "SBOM_CYCLONEDX_JSON",
						},
						{
							Digest: "sha256:b4bd86d5855f94bcac0a92d3100ae7b85d050bd2e5fb9037a200e5f5f0b073a2",
							Kind:   "OPENVEX",
						},
						{
							Digest: "sha1:78ac366c9e8a300d51808d581422ca61f7b5b721",
							Kind:   "GIT_HEAD_COMMIT",
						},
					},
				},
				{
					Digest: "sha256:fbd9335f55d83d8aaf9ab1a539b0f2a87b444e8c54f34c9a1ca9d7df15605db4",
					Kind:   "CONTAINER_IMAGE",
					References: []*Referrer{
						{
							Digest: withGitSubject.Digest,
							Kind:   "ATTESTATION",
						},
					},
				},
				{
					Digest: "sha1:78ac366c9e8a300d51808d581422ca61f7b5b721",
					Kind:   "GIT_HEAD_COMMIT",
					// the git commit a subject in the attestation
					References: []*Referrer{
						{
							Digest: withGitSubject.Digest,
							Kind:   "ATTESTATION",
						},
					},
				},
				{
					Digest:       "sha256:b4bd86d5855f94bcac0a92d3100ae7b85d050bd2e5fb9037a200e5f5f0b073a2",
					Kind:         "OPENVEX",
					Downloadable: true,
					References:   []*Referrer{withGitSubject},
				},
				{
					Digest:       "sha256:c4a63494f9289dd9fd44f841efb4f5b52765c2de6332f2d86e5f6c0340b40a95",
					Kind:         "SARIF",
					Downloadable: true,
					References:   []*Referrer{withGitSubject},
				},
				{
					Digest:       "sha256:16159bb881eb4ab7eb5d8afc5350b0feeed1e31c0a268e355e74f9ccbe885e0c",
					Kind:         "SBOM_CYCLONEDX_JSON",
					Downloadable: true,
					References:   []*Referrer{withGitSubject},
				},
			},
		},
	}

	for _, tc := range testCases {
		s.Run(tc.name, func() {
			// Load attestation
			attJSON, err := os.ReadFile(tc.inputPath)
			require.NoError(s.T(), err)
			h, _, err := v1.SHA256(bytes.NewReader(attJSON))
			require.NoError(s.T(), err)
			var envelope *dsse.Envelope
			require.NoError(s.T(), json.Unmarshal(attJSON, &envelope))

			got, err := extractReferrers(envelope, h, nil)
			if tc.expectErr {
				s.Error(err)
				return
			}

			require.NoError(s.T(), err)
			s.Equal(tc.want, got)
		})
	}
}

type referrerTestSuite struct {
	suite.Suite
}

func TestReferrer(t *testing.T) {
	suite.Run(t, new(referrerTestSuite))
}
