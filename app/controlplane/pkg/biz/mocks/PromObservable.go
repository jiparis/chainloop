// Code generated by mockery v2.53.4. DO NOT EDIT.

package mocks

import (
	context "context"

	biz "github.com/chainloop-dev/chainloop/app/controlplane/pkg/biz"

	mock "github.com/stretchr/testify/mock"
)

// PromObservable is an autogenerated mock type for the PromObservable type
type PromObservable struct {
	mock.Mock
}

// ObserveAttestationIfNeeded provides a mock function with given fields: ctx, run, status
func (_m *PromObservable) ObserveAttestationIfNeeded(ctx context.Context, run *biz.WorkflowRun, status biz.WorkflowRunStatus) bool {
	ret := _m.Called(ctx, run, status)

	if len(ret) == 0 {
		panic("no return value specified for ObserveAttestationIfNeeded")
	}

	var r0 bool
	if rf, ok := ret.Get(0).(func(context.Context, *biz.WorkflowRun, biz.WorkflowRunStatus) bool); ok {
		r0 = rf(ctx, run, status)
	} else {
		r0 = ret.Get(0).(bool)
	}

	return r0
}

// NewPromObservable creates a new instance of PromObservable. It also registers a testing interface on the mock and a cleanup function to assert the mocks expectations.
// The first argument is typically a *testing.T value.
func NewPromObservable(t interface {
	mock.TestingT
	Cleanup(func())
}) *PromObservable {
	mock := &PromObservable{}
	mock.Mock.Test(t)

	t.Cleanup(func() { mock.AssertExpectations(t) })

	return mock
}
