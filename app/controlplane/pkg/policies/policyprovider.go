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

package policies

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"

	schemaapi "github.com/chainloop-dev/chainloop/app/controlplane/api/workflowcontract/v1"
	"github.com/chainloop-dev/chainloop/app/controlplane/pkg/unmarshal"
	"github.com/chainloop-dev/chainloop/pkg/policies"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
)

const (
	policiesEndpoint = "policies"
	validateAction   = "validate"
	groupsEndpoint   = "groups"

	digestParam        = "digest"
	orgNameParam       = "organization_name"
	organizationHeader = "Chainloop-Organization"
)

// PolicyProvider represents an external policy provider
type PolicyProvider struct {
	name, url string
	isDefault bool
}

type ProviderResponse struct {
	// Deprecated: Raw is the preferred approach
	Data             map[string]any `json:"data"`
	Digest           string         `json:"digest"`
	Raw              *RawMessage    `json:"raw"`
	OrganizationName string         `json:"organizationName"`
}

type ValidateRequest struct {
	PolicyAttachment string `json:"policy_attachment"`
}

type ValidateResponse struct {
	Valid            bool     `json:"valid"`
	ValidationErrors []string `json:"validationErrors"`
}

type RawMessage struct {
	Body   []byte `json:"body"`
	Format string `json:"format"`
}

type PolicyReference struct {
	URL    string
	Digest string
}

type ProviderAuthOpts struct {
	Token   string
	OrgName string
}

var ErrNotFound = fmt.Errorf("policy not found")

// Resolve calls the remote provider for retrieving a policy
func (p *PolicyProvider) Resolve(policyName, policyOrgName string, authOpts ProviderAuthOpts) (*schemaapi.Policy, *PolicyReference, error) {
	if policyName == "" || authOpts.Token == "" {
		return nil, nil, fmt.Errorf("both policyname and auth opts are mandatory")
	}

	// the policy name might include a digest in the form of <name>@sha256:<digest>
	policyName, digest := policies.ExtractDigest(policyName)

	var policy schemaapi.Policy
	endpoint, err := url.JoinPath(p.url, policiesEndpoint, policyName)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to resolve policy: %w", err)
	}
	url, err := url.Parse(endpoint)
	if err != nil {
		return nil, nil, fmt.Errorf("error parsing policy provider URL: %w", err)
	}
	// we want to override the orgName with the one in the response
	// since we might have resolved it implicitly
	providerDigest, orgName, err := p.queryProvider(url, digest, policyOrgName, authOpts, &policy)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to resolve policy: %w", err)
	}

	return &policy, createRef(url, policyName, providerDigest, orgName), nil
}

func (p *PolicyProvider) ValidateAttachment(att *schemaapi.PolicyAttachment, token string) error {
	endpoint, err := url.JoinPath(p.url, policiesEndpoint, validateAction)
	if err != nil {
		return fmt.Errorf("invalid url: %w", err)
	}
	url, err := url.Parse(endpoint)
	if err != nil {
		return fmt.Errorf("error parsing policy provider URL: %w", err)
	}

	attBody, err := protojson.Marshal(att)
	if err != nil {
		return fmt.Errorf("error serializing policy attachment: %w", err)
	}

	validateReq := &ValidateRequest{
		PolicyAttachment: string(attBody),
	}

	reqBody, err := json.Marshal(validateReq)
	if err != nil {
		return fmt.Errorf("error serializing policy validation request: %w", err)
	}

	req, err := http.NewRequest("POST", url.String(), bytes.NewReader(reqBody))
	if err != nil {
		return fmt.Errorf("error creating policy request: %w", err)
	}

	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token))
	req.Header.Set("Content-Type", "application/json")

	// make the request
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("error executing policy request: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		if resp.StatusCode == http.StatusNotFound || resp.StatusCode == http.StatusMethodNotAllowed {
			// Ignore endpoint not found as it might not be implemented by the provider
			return nil
		}

		return fmt.Errorf("expected status code 200 but got %d", resp.StatusCode)
	}

	resBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("error reading validation response: %w", err)
	}

	defer resp.Body.Close()

	// unmarshall response
	var response ValidateResponse
	if err := json.Unmarshal(resBytes, &response); err != nil {
		return fmt.Errorf("error unmarshalling validation response: %w", err)
	}

	if !response.Valid {
		return fmt.Errorf("validation failures: %v", response.ValidationErrors)
	}

	return nil
}

// ResolveGroup calls remote provider for retrieving a policy group definition
func (p *PolicyProvider) ResolveGroup(groupName, groupOrgName string, authOpts ProviderAuthOpts) (*schemaapi.PolicyGroup, *PolicyReference, error) {
	if groupName == "" || authOpts.Token == "" {
		return nil, nil, fmt.Errorf("both policyname and token are mandatory")
	}

	// the policy name might include a digest in the form of <name>@sha256:<digest>
	groupName, digest := policies.ExtractDigest(groupName)

	var group schemaapi.PolicyGroup
	endpoint, err := url.JoinPath(p.url, groupsEndpoint, groupName)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to resolve group: %w", err)
	}
	url, err := url.Parse(endpoint)
	if err != nil {
		return nil, nil, fmt.Errorf("error parsing policy provider URL: %w", err)
	}
	// we want to override the orgName with the one in the response
	// since we might have resolved it implicitly
	providerDigest, orgName, err := p.queryProvider(url, digest, groupOrgName, authOpts, &group)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to resolve group: %w", err)
	}

	return &group, createRef(url, groupName, providerDigest, orgName), nil
}

// returns digest, orgname, error
func (p *PolicyProvider) queryProvider(url *url.URL, digest, orgName string, authOpts ProviderAuthOpts, out proto.Message) (string, string, error) {
	query := url.Query()
	if digest != "" {
		query.Set(digestParam, digest)
	}

	if orgName != "" {
		query.Set(orgNameParam, orgName)
	}

	url.RawQuery = query.Encode()

	req, err := http.NewRequest("GET", url.String(), nil)
	if err != nil {
		return "", "", fmt.Errorf("error creating policy request: %w", err)
	}

	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", authOpts.Token))
	if authOpts.OrgName != "" {
		req.Header.Set(organizationHeader, authOpts.OrgName)
	}

	// make the request
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", "", fmt.Errorf("error executing policy request: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		if resp.StatusCode == http.StatusNotFound {
			return "", "", ErrNotFound
		}

		return "", "", fmt.Errorf("expected status code 200 but got %d", resp.StatusCode)
	}

	resBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", "", fmt.Errorf("error reading policy response: %w", err)
	}

	// unmarshall response
	var response ProviderResponse
	if err := json.Unmarshal(resBytes, &response); err != nil {
		return "", "", fmt.Errorf("error unmarshalling policy response: %w", err)
	}

	// if raw message is provided, just interpret it as a base64 encoded string
	if response.Raw != nil {
		if err := unmarshalFromRaw(response.Raw, out); err != nil {
			return "", "", fmt.Errorf("error unmarshalling policy response: %w", err)
		}
	} else if response.Data != nil {
		// extract the policy payload from the query response
		jsonPolicy, err := json.Marshal(response.Data)
		if err != nil {
			return "", "", fmt.Errorf("error marshalling policy response: %w", err)
		}

		if err := protojson.Unmarshal(jsonPolicy, out); err != nil {
			return "", "", fmt.Errorf("error unmarshalling policy response: %w", err)
		}
	}

	// override the orgName with the one in the response if its provided
	// this is mainly a protection against misconfiguration on the policy provider
	// that might end up wiping out the orgName from the request
	if response.OrganizationName != "" {
		orgName = response.OrganizationName
	}

	return response.Digest, orgName, nil
}

func unmarshalFromRaw(raw *RawMessage, out proto.Message) error {
	var format unmarshal.RawFormat
	switch raw.Format {
	case "FORMAT_JSON":
		format = unmarshal.RawFormatJSON
	case "FORMAT_YAML":
		format = unmarshal.RawFormatYAML
	case "FORMAT_CUE":
		format = unmarshal.RawFormatCUE
	default:
		return fmt.Errorf("unsupported format: %s", raw.Format)
	}

	err := unmarshal.FromRaw(raw.Body, format, out, false)
	if err != nil {
		return fmt.Errorf("error unmarshalling policy response: %w", err)
	}

	return nil
}

func createRef(policyURL *url.URL, name, digest, orgName string) *PolicyReference {
	refURL := fmt.Sprintf("chainloop://%s/%s", policyURL.Host, name)
	if orgName != "" {
		refURL = fmt.Sprintf("%s?org=%s", refURL, orgName)
	}
	return &PolicyReference{
		URL:    refURL,
		Digest: digest,
	}
}
