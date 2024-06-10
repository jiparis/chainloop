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
	"bytes"
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"sort"

	pb "github.com/chainloop-dev/chainloop/app/controlplane/api/controlplane/v1"
	"github.com/chainloop-dev/chainloop/internal/attestation/renderer/chainloop"
	"github.com/chainloop-dev/chainloop/internal/attestation/verifier"
	intoto "github.com/in-toto/attestation/go/v1"
	"github.com/secure-systems-lab/go-securesystemslib/dsse"
	"github.com/sigstore/cosign/v2/pkg/blob"
	"github.com/sigstore/sigstore/pkg/cryptoutils"
)

type WorkflowRunDescribe struct {
	cfg *ActionsOpts
}

type WorkflowRunDescribeOpts struct {
	ChainPath string
	KeyRef    string
	Verify    bool
}

type WorkflowRunItemFull struct {
	WorkflowRun *WorkflowRunItem            `json:"workflowRun"`
	Workflow    *WorkflowItem               `json:"workflow"`
	Attestation *WorkflowRunAttestationItem `json:"attestation,omitempty"`
	Verified    bool                        `json:"verified"`
}

type WorkflowRunAttestationItem struct {
	Envelope    *dsse.Envelope `json:"envelope"`
	statement   *intoto.Statement
	Materials   []*Material   `json:"materials,omitempty"`
	EnvVars     []*EnvVar     `json:"envvars,omitempty"`
	Annotations []*Annotation `json:"annotations,omitempty"`
	// Digest in CAS backend
	Digest string `json:"digest"`
}

type Material struct {
	Name           string        `json:"name"`
	Value          string        `json:"value"`
	Hash           string        `json:"hash"`
	Tag            string        `json:"tag"`
	Filename       string        `json:"filename"`
	Type           string        `json:"type"`
	Annotations    []*Annotation `json:"annotations,omitempty"`
	UploadedToCAS  bool          `json:"uploadedToCAS,omitempty"`
	EmbeddedInline bool          `json:"embeddedInline,omitempty"`
}

type EnvVar struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

type Annotation struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

func (i *WorkflowRunAttestationItem) Statement() *intoto.Statement {
	return i.statement
}

func NewWorkflowRunDescribe(cfg *ActionsOpts) *WorkflowRunDescribe {
	return &WorkflowRunDescribe{cfg}
}

func (action *WorkflowRunDescribe) Run(ctx context.Context, runID string, digest string, opts *WorkflowRunDescribeOpts) (*WorkflowRunItemFull, error) {
	client := pb.NewWorkflowRunServiceClient(action.cfg.CPConnection)

	req := &pb.WorkflowRunServiceViewRequest{}
	if digest != "" {
		req.Ref = &pb.WorkflowRunServiceViewRequest_Digest{Digest: digest}
	} else if runID != "" {
		req.Ref = &pb.WorkflowRunServiceViewRequest_Id{Id: runID}
	}

	resp, err := client.View(ctx, req)
	if err != nil {
		return nil, err
	}

	wr := resp.GetResult().GetWorkflowRun()
	wf := wr.GetWorkflow()

	item := &WorkflowRunItemFull{
		WorkflowRun: pbWorkflowRunItemToAction(wr),
		Workflow:    pbWorkflowItemToAction(wf),
	}

	if wr.FinishedAt != nil {
		item.WorkflowRun.FinishedAt = toTimePtr(wr.FinishedAt.AsTime())
	}

	attestation := resp.GetResult().GetAttestation()
	// The item does not have associated attestation
	if attestation == nil {
		return item, nil
	}

	envelope, err := decodeEnvelope(attestation.Envelope)
	if err != nil {
		return nil, err
	}

	if opts.Verify {
		v, err := buildVerifier(opts)
		if err != nil {
			return nil, fmt.Errorf("couldn't build a verifier: %v", err)
		}
		err = v.Verify(ctx, envelope)
		if err != nil {
			action.cfg.Logger.Debug().Err(err).Msg("verifying the envelope")
			return nil, errors.New("invalid signature, did you provide the right key?")
		}

		item.Verified = true
	}

	statement, err := chainloop.ExtractStatement(envelope)
	if err != nil {
		return nil, fmt.Errorf("extracting statement: %w", err)
	}

	envVars := make([]*EnvVar, 0, len(attestation.GetEnvVars()))
	for _, v := range attestation.GetEnvVars() {
		envVars = append(envVars, &EnvVar{Name: v.Name, Value: v.Value})
	}

	materials := make([]*Material, 0, len(attestation.GetMaterials()))
	for _, v := range attestation.GetMaterials() {
		materials = append(materials, materialPBToAction(v))
	}

	keys := make([]string, 0, len(attestation.GetAnnotations()))
	for k := range attestation.GetAnnotations() {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	annotations := make([]*Annotation, 0, len(attestation.GetAnnotations()))
	for _, k := range keys {
		annotations = append(annotations, &Annotation{
			Name: k, Value: attestation.GetAnnotations()[k],
		})
	}

	item.Attestation = &WorkflowRunAttestationItem{
		Envelope:    envelope,
		statement:   statement,
		EnvVars:     envVars,
		Materials:   materials,
		Annotations: annotations,
		Digest:      attestation.DigestInCasBackend,
	}

	return item, nil
}

func materialPBToAction(in *pb.AttestationItem_Material) *Material {
	m := &Material{
		Name:           in.Name,
		Value:          in.Value,
		Type:           in.Type,
		Hash:           in.Hash,
		Tag:            in.Tag,
		UploadedToCAS:  in.UploadedToCas,
		Filename:       in.Filename,
		EmbeddedInline: in.EmbeddedInline,
	}

	// append annotations sorted
	if in.Annotations != nil {
		keys := make([]string, 0, len(in.Annotations))
		for k := range in.Annotations {
			keys = append(keys, k)
		}
		sort.Strings(keys)

		for _, k := range keys {
			m.Annotations = append(m.Annotations, &Annotation{Name: k, Value: in.Annotations[k]})
		}
	}

	return m
}

func buildVerifier(opts *WorkflowRunDescribeOpts) (*verifier.Verifier, error) {
	vo := &verifier.VerifierOptions{
		KeyRef: opts.KeyRef,
	}

	// x509 PEM-encoded certificate list. Assuming first in the chain is the signing certificate, and last one is the root CA
	if opts.ChainPath != "" {
		cert, chain, root, err := loadCertificates(opts.ChainPath)
		if err != nil {
			return nil, fmt.Errorf("loading certificates: %w", err)
		}
		vo.Intermediates = chain
		vo.Cert = cert
		vo.RootCA = root
	}

	return verifier.NewVerifier(vo), nil
}

func loadCertificates(chainPath string) (*x509.Certificate, *x509.CertPool, *x509.Certificate, error) {
	// Use cosign API to load cert PEM from supported URI schemes
	content, err := blob.LoadFileOrURL(chainPath)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("reading chain file: %w", err)
	}
	certs, err := cryptoutils.LoadCertificatesFromPEM(bytes.NewReader(content))
	if err != nil {
		return nil, nil, nil, fmt.Errorf("loading certificates: %w", err)
	}
	if len(certs) == 0 {
		return nil, nil, nil, fmt.Errorf("no certificates found in the chain")
	}

	var root *x509.Certificate
	var intermediates *x509.CertPool
	leaf := certs[0]
	if len(certs) > 1 {
		root = certs[len(certs)-1]
	}
	if len(certs) > 2 {
		intermediates = x509.NewCertPool()
		for _, c := range certs[1 : len(certs)-1] {
			intermediates.AddCert(c)
		}
	}

	return leaf, intermediates, root, nil
}
