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

package verifier

import (
	"context"
	"crypto/x509"
	"fmt"

	"github.com/secure-systems-lab/go-securesystemslib/dsse"
	"github.com/sigstore/cosign/v2/pkg/cosign"
	sigs "github.com/sigstore/cosign/v2/pkg/signature"
	"github.com/sigstore/sigstore/pkg/signature"
	sigdsee "github.com/sigstore/sigstore/pkg/signature/dsse"
)

type VerifierOptions struct {
	Cert          *x509.Certificate
	KeyRef        string
	RootCA        *x509.Certificate
	Intermediates *x509.CertPool
}

type Verifier struct {
	opts *VerifierOptions
}

func NewVerifier(opts *VerifierOptions) *Verifier {
	return &Verifier{opts: opts}
}

func (v *Verifier) Verify(ctx context.Context, e *dsse.Envelope) error {
	// Currently we only support basic cosign public key check
	// TODO: Add more verification methods
	var (
		verifier signature.Verifier
		err      error
	)

	if v.opts.Cert == nil && v.opts.KeyRef == "" {
		return fmt.Errorf("no certificate or key provided")
	}

	// Use keyref for local verification from public key
	if v.opts.KeyRef != "" {
		verifier, err = sigs.PublicKeyFromKeyRef(ctx, v.opts.KeyRef)
		if err != nil {
			return err
		}
	}

	// x509 PEM-encoded certificate
	if v.opts.Cert != nil {
		// Load root if any
		rootPool, err := loadRootCert(v.opts)
		if err != nil {
			return fmt.Errorf("loading root cert: %w", err)
		}
		verifier, err = cosign.ValidateAndUnpackCert(v.opts.Cert, &cosign.CheckOpts{
			RootCerts:         rootPool,
			IntermediateCerts: v.opts.Intermediates,
			IgnoreSCT:         true,
		})
		if err != nil {
			return fmt.Errorf("validating cert file: %w", err)
		}
	}

	dsseVerifier, err := dsse.NewEnvelopeVerifier(&sigdsee.VerifierAdapter{SignatureVerifier: verifier})
	if err != nil {
		return err
	}

	_, err = dsseVerifier.Verify(ctx, e)
	return err
}

func loadRootCert(opts *VerifierOptions) (*x509.CertPool, error) {
	if opts.RootCA == nil {
		return nil, nil
	}

	pool := x509.NewCertPool()

	// Get only the latest one (root)
	pool.AddCert(opts.RootCA)
	return pool, nil
}
