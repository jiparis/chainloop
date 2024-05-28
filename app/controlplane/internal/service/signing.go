package service

import (
	"context"

	v1 "github.com/chainloop-dev/chainloop/app/controlplane/api/controlplane/v1"
	"github.com/chainloop-dev/chainloop/app/controlplane/internal/biz"
	"github.com/go-kratos/kratos/v2/errors"
)

type SigningService struct {
	v1.UnimplementedSigningServiceServer
	*service

	signing biz.SigningCertCreator
}

var _ v1.SigningServiceServer = (*SigningService)(nil)

func NewSigningService(signing biz.SigningCertCreator) *SigningService {
	return &SigningService{
		signing: signing,
	}
}

func (s *SigningService) SigningCert(ctx context.Context, req *v1.SigningCertRequest) (*v1.SigningCertResponse, error) {
	if len(req.GetCertificateSigningRequest()) == 0 {
		return nil, errors.BadRequest("missing csr", "a certificate request is expected")
	}

	org, err := requireCurrentOrg(ctx)
	if err != nil {
		return nil, errors.Unauthorized("missing org", "an organization is required")
	}

	_, err = s.signing.CreateSigningCert(ctx, org.ID, req.GetCertificateSigningRequest())
	if err != nil {
		return nil, handleUseCaseErr(err, s.log)
	}

	return nil, nil
}
