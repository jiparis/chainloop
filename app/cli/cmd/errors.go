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

package cmd

import (
	"errors"
	"time"

	"github.com/cenkalti/backoff/v4"
	v1 "github.com/chainloop-dev/chainloop/app/controlplane/api/controlplane/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// GracefulError represents an error that has been marked as gracefully handled
// In some parts of our code, we want to raise errors but we don't want the CLI to fail
// because of the flakiness or active development of the tool
type GracefulError struct {
	err error
}

func (e GracefulError) Error() string {
	return e.err.Error()
}

func (e GracefulError) Unwrap() error {
	return e.err
}

func newGracefulError(err error) error {
	return GracefulError{err}
}

var ErrAttestationNotInitialized = errors.New("attestation not yet initialized, execute the init command first")
var ErrAttestationAlreadyExist = errors.New("attestation already initialized, to override it use the --replace flag`")
var ErrAttestationTokenRequired = errors.New("chainloop Token required, please provide it via --token flag or CHAINLOOP_TOKEN environment variable")
var ErrKeylessNotSupported = errors.New("keyless signing not supported, please provide a private key reference with --key instead")

func isRetriableAPIError(err error) bool {
	// we retry state conflicts and other transient errors
	if v1.IsAttestationStateErrorConflict(err) {
		return true
	}

	st, ok := status.FromError(err)
	if !ok {
		return false
	}

	retriableCodes := []codes.Code{
		codes.Unavailable,
		codes.Internal,
		codes.ResourceExhausted,
		codes.DeadlineExceeded,
	}

	for _, code := range retriableCodes {
		if st.Code() == code {
			return true
		}
	}

	return false
}

func runWithBackoffRetry(fn func() error) error {
	return backoff.RetryNotify(
		func() error {
			err := fn()
			if !isRetriableAPIError(err) {
				return backoff.Permanent(err)
			}
			return err
		},
		backoff.NewExponentialBackOff(backoff.WithMaxElapsedTime(3*time.Minute)),
		func(err error, delay time.Duration) {
			logger.Err(err).Msgf("retrying in %s", delay)
		})
}
