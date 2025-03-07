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

package usercontext

import (
	"context"
	"errors"
	"fmt"

	"github.com/go-kratos/kratos/v2/log"
	"github.com/golang-jwt/jwt/v4"

	"github.com/chainloop-dev/chainloop/app/controlplane/internal/usercontext/entities"
	"github.com/chainloop-dev/chainloop/app/controlplane/pkg/biz"
	"github.com/chainloop-dev/chainloop/app/controlplane/pkg/jwt/user"
	"github.com/go-kratos/kratos/v2/middleware"
	jwtMiddleware "github.com/go-kratos/kratos/v2/middleware/auth/jwt"
)

// Middleware that injects the current user + organization to the context
func WithCurrentUserMiddleware(userUseCase biz.UserOrgFinder, logger *log.Helper) middleware.Middleware {
	return func(handler middleware.Handler) middleware.Handler {
		return func(ctx context.Context, req interface{}) (interface{}, error) {
			rawClaims, ok := jwtMiddleware.FromContext(ctx)
			// If not found means that there is no currentUser set in the context
			if !ok {
				logger.Warn("couldn't extract user, JWT parser middleware not running before this one?")
				return nil, errors.New("can't extract JWT info from the context")
			}

			genericClaims, ok := rawClaims.(jwt.MapClaims)
			if !ok {
				return nil, errors.New("error mapping the claims")
			}

			// Check wether the token is for a user or an API-token and handle accordingly
			// We've received a token for a user
			if genericClaims.VerifyAudience(user.Audience, true) {
				userID, ok := genericClaims["user_id"].(string)
				if !ok || userID == "" {
					return nil, errors.New("error mapping the user claims")
				}

				var err error
				ctx, err = setCurrentUser(ctx, userUseCase, userID, logger)
				if err != nil {
					return nil, fmt.Errorf("error setting current user: %w", err)
				}

				logger.Infow("msg", "[authN] processed credentials", "id", userID, "type", "user")
			}

			return handler(ctx, req)
		}
	}
}

// Find the user by its ID and sets it on the context
func setCurrentUser(ctx context.Context, userUC biz.UserOrgFinder, userID string, logger *log.Helper) (context.Context, error) {
	u, err := userUC.FindByID(ctx, userID)
	if err != nil {
		return nil, err
	}

	if u == nil {
		logger.Warnf("user with id %s not found", userID)
		return nil, errors.New("user not found")
	}

	return entities.WithCurrentUser(ctx, &entities.User{Email: u.Email, ID: u.ID, CreatedAt: u.CreatedAt}), nil
}
