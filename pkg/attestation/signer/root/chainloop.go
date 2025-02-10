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

package root

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/x509"
	"fmt"
	"time"

	"github.com/sigstore/sigstore-go/pkg/root"
	"github.com/sigstore/sigstore/pkg/signature"
)

type ChainloopPublicKeyMaterial struct {
	root.BaseTrustedMaterial
	ca                *x509.Certificate
	publicKeyVerifier func(string) (root.TimeConstrainedVerifier, error)
}

func NewChainloopPublicKeyMaterial(ca *x509.Certificate) *ChainloopPublicKeyMaterial {
	return &ChainloopPublicKeyMaterial{
		ca: ca,
		publicKeyVerifier: func(string) (root.TimeConstrainedVerifier, error) {
			pk := ca.PublicKey
			verifier, err := signature.LoadECDSAVerifier(pk.(*ecdsa.PublicKey), crypto.SHA256)
			if err != nil {
				return nil, fmt.Errorf("failed to load ECDSA verifier: %w", err)
			}
			return &nonExpiringVerifier{verifier}, nil
		},
	}
}

func (cpm *ChainloopPublicKeyMaterial) PublicKeyVerifier(keyID string) (root.TimeConstrainedVerifier, error) {
	return cpm.publicKeyVerifier(keyID)
}

func (cpm *ChainloopPublicKeyMaterial) FulcioCertificateAuthorities() []root.CertificateAuthority {
	return []root.CertificateAuthority{
		{
			Root:                cpm.ca,
			Intermediates:       []*x509.Certificate{},
			ValidityPeriodStart: cpm.ca.NotBefore,
			ValidityPeriodEnd:   cpm.ca.NotAfter,
		},
	}
}

type nonExpiringVerifier struct {
	signature.Verifier
}

func (*nonExpiringVerifier) ValidAtTime(_ time.Time) bool {
	return true
}
