//
// Copyright 2023-2025 The Chainloop Authors.
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

package service

import (
	"context"
	"os"

	pb "github.com/chainloop-dev/chainloop/app/controlplane/api/controlplane/v1"
	conf "github.com/chainloop-dev/chainloop/app/controlplane/internal/conf/controlplane/config/v1"
	"github.com/chainloop-dev/chainloop/app/controlplane/pkg/biz"
	"github.com/go-kratos/kratos/v2/errors"
)

type StatusService struct {
	loginURL, version string
	pb.UnimplementedStatusServiceServer
	casClient *biz.CASClientUseCase
	bootstrap *conf.Bootstrap
}

func NewStatusService(logingURL, version string, casClient *biz.CASClientUseCase, bootstrap *conf.Bootstrap) *StatusService {
	return &StatusService{loginURL: logingURL, version: version, casClient: casClient, bootstrap: bootstrap}
}

// Only on readiness probes we check this service external dependencies
func (s *StatusService) Statusz(ctx context.Context, r *pb.StatuszRequest) (*pb.StatuszResponse, error) {
	if r.Readiness {
		if ok, err := s.casClient.IsReady(ctx); err != nil || !ok {
			return nil, errors.ServiceUnavailable("CAS_NOT_READY", err.Error())
		}
	}
	return &pb.StatuszResponse{}, nil
}

func (s *StatusService) Infoz(_ context.Context, _ *pb.InfozRequest) (*pb.InfozResponse, error) {
	return &pb.InfozResponse{
		LoginUrl:              s.loginURL,
		Version:               s.version,
		ChartVersion:          os.Getenv("CHART_VERSION"),
		RestrictedOrgCreation: s.bootstrap.RestrictOrgCreation,
	}, nil
}
