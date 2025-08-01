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

package usercontext

import (
	"context"
	"errors"
	"fmt"
	"time"

	v1 "github.com/chainloop-dev/chainloop/app/controlplane/api/controlplane/v1"
	"github.com/chainloop-dev/chainloop/app/controlplane/internal/usercontext/entities"
	"github.com/chainloop-dev/chainloop/app/controlplane/pkg/biz"
	"github.com/go-kratos/kratos/v2/log"
	"github.com/go-kratos/kratos/v2/middleware"
	"github.com/google/uuid"
	"github.com/hashicorp/golang-lru/v2/expirable"
)

// membershipsCache caches user memberships to save some database queries during intensive sessions
var membershipsCache = expirable.NewLRU[string, *entities.Membership](0, nil, time.Second*1)

func WithCurrentMembershipsMiddleware(membershipUC biz.MembershipsRBAC) middleware.Middleware {
	return func(handler middleware.Handler) middleware.Handler {
		return func(ctx context.Context, req interface{}) (interface{}, error) {
			// Get the current user and return if not found, meaning we are probably coming from an API Token
			u := entities.CurrentUser(ctx)
			if u == nil {
				return handler(ctx, req)
			}

			var err error
			// Let's store all memberships in the context.
			ctx, err = setCurrentMembershipsForUser(ctx, u, membershipUC)
			if err != nil {
				return nil, fmt.Errorf("error setting current org membership: %w", err)
			}

			return handler(ctx, req)
		}
	}
}

func WithCurrentOrganizationMiddleware(userUseCase biz.UserOrgFinder, logger *log.Helper) middleware.Middleware {
	return func(handler middleware.Handler) middleware.Handler {
		return func(ctx context.Context, req interface{}) (interface{}, error) {
			// Get the current user and return if not found, meaning we are probably coming from an API Token
			u := entities.CurrentUser(ctx)
			if u == nil {
				return handler(ctx, req)
			}

			orgName, err := entities.GetOrganizationNameFromHeader(ctx)
			if err != nil {
				return nil, fmt.Errorf("error getting organization name: %w", err)
			}

			if orgName != "" {
				ctx, err = setCurrentOrganizationFromHeader(ctx, u, orgName, userUseCase)
				if err != nil {
					return nil, v1.ErrorUserNotMemberOfOrgErrorNotInOrg("user is not a member of organization %s", orgName)
				}
			} else {
				// If no organization name is provided, we use the DB to find the current organization
				// DEPRECATED: in favor of header based org selection
				ctx, err = setCurrentOrganizationFromDB(ctx, u, userUseCase, logger)
				if err != nil {
					return nil, fmt.Errorf("error setting current org: %w", err)
				}
			}

			org := entities.CurrentOrg(ctx)
			if org == nil {
				return nil, errors.New("org not found")
			}

			logger.Infow("msg", "[authN] processed organization", "org-id", org.ID, "credentials type", "user")

			return handler(ctx, req)
		}
	}
}

// setCurrentMembershipsForUser retrieves all user memberships for RBAC
func setCurrentMembershipsForUser(ctx context.Context, u *entities.User, membershipUC biz.MembershipsRBAC) (context.Context, error) {
	var membership *entities.Membership
	var ok bool

	if membership, ok = membershipsCache.Get(u.ID); !ok {
		uid, err := uuid.Parse(u.ID)
		if err != nil {
			return nil, err
		}

		mm, err := membershipUC.ListAllMembershipsForUser(ctx, uid)
		if err != nil {
			return nil, fmt.Errorf("error getting membership list: %w", err)
		}

		resourceMemberships := make([]*entities.ResourceMembership, 0, len(mm))
		for _, m := range mm {
			resourceMemberships = append(resourceMemberships, &entities.ResourceMembership{
				Role:         m.Role,
				ResourceType: m.ResourceType,
				ResourceID:   m.ResourceID,
				MembershipID: m.ID,
			})
		}

		membership = &entities.Membership{UserID: uuid.MustParse(u.ID), Resources: resourceMemberships}
		membershipsCache.Add(u.ID, membership)
	}

	return entities.WithMembership(ctx, membership), nil
}

func ResetMembershipsCache() {
	membershipsCache.Purge()
}

func setCurrentOrganizationFromHeader(ctx context.Context, user *entities.User, orgName string, userUC biz.UserOrgFinder) (context.Context, error) {
	membership, err := userUC.MembershipInOrg(ctx, user.ID, orgName)
	if err != nil {
		return nil, fmt.Errorf("failed to find membership: %w", err)
	}

	ctx = entities.WithCurrentOrg(ctx, &entities.Org{Name: membership.Org.Name, ID: membership.Org.ID, CreatedAt: membership.CreatedAt})
	// Set the authorization subject that will be used to check the policies
	return WithAuthzSubject(ctx, string(membership.Role)), nil
}

// Find the current membership of the user and sets it on the context
func setCurrentOrganizationFromDB(ctx context.Context, user *entities.User, userUC biz.UserOrgFinder, logger *log.Helper) (context.Context, error) {
	// We load the current organization
	membership, err := userUC.CurrentMembership(ctx, user.ID)
	if err != nil {
		if biz.IsNotFound(err) {
			return nil, v1.ErrorUserWithNoMembershipErrorNotInOrg("user with id %s has no current organization", user.ID)
		}

		return nil, err
	}

	if membership == nil {
		logger.Warnf("user with id %s has no current organization", user.ID)
		return nil, errors.New("org not found")
	}

	ctx = entities.WithCurrentOrg(ctx, &entities.Org{Name: membership.Org.Name, ID: membership.Org.ID, CreatedAt: membership.CreatedAt})

	// Set the authorization subject that will be used to check the policies
	ctx = WithAuthzSubject(ctx, string(membership.Role))

	return ctx, nil
}
