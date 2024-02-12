// Code generated by protoc-gen-validate. DO NOT EDIT.
// source: controlplane/v1/attestation_state.proto

package v1

import (
	"bytes"
	"errors"
	"fmt"
	"net"
	"net/mail"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	"google.golang.org/protobuf/types/known/anypb"
)

// ensure the imports are used
var (
	_ = bytes.MinRead
	_ = errors.New("")
	_ = fmt.Print
	_ = utf8.UTFMax
	_ = (*regexp.Regexp)(nil)
	_ = (*strings.Reader)(nil)
	_ = net.IPv4len
	_ = time.Duration(0)
	_ = (*url.URL)(nil)
	_ = (*mail.Address)(nil)
	_ = anypb.Any{}
	_ = sort.Sort
)

// Validate checks the field values on
// AttestationStateServiceInitializedRequest with the rules defined in the
// proto definition for this message. If any rules are violated, the first
// error encountered is returned, or nil if there are no violations.
func (m *AttestationStateServiceInitializedRequest) Validate() error {
	return m.validate(false)
}

// ValidateAll checks the field values on
// AttestationStateServiceInitializedRequest with the rules defined in the
// proto definition for this message. If any rules are violated, the result is
// a list of violation errors wrapped in
// AttestationStateServiceInitializedRequestMultiError, or nil if none found.
func (m *AttestationStateServiceInitializedRequest) ValidateAll() error {
	return m.validate(true)
}

func (m *AttestationStateServiceInitializedRequest) validate(all bool) error {
	if m == nil {
		return nil
	}

	var errors []error

	if utf8.RuneCountInString(m.GetWorkflowRunId()) < 1 {
		err := AttestationStateServiceInitializedRequestValidationError{
			field:  "WorkflowRunId",
			reason: "value length must be at least 1 runes",
		}
		if !all {
			return err
		}
		errors = append(errors, err)
	}

	if len(errors) > 0 {
		return AttestationStateServiceInitializedRequestMultiError(errors)
	}

	return nil
}

// AttestationStateServiceInitializedRequestMultiError is an error wrapping
// multiple validation errors returned by
// AttestationStateServiceInitializedRequest.ValidateAll() if the designated
// constraints aren't met.
type AttestationStateServiceInitializedRequestMultiError []error

// Error returns a concatenation of all the error messages it wraps.
func (m AttestationStateServiceInitializedRequestMultiError) Error() string {
	var msgs []string
	for _, err := range m {
		msgs = append(msgs, err.Error())
	}
	return strings.Join(msgs, "; ")
}

// AllErrors returns a list of validation violation errors.
func (m AttestationStateServiceInitializedRequestMultiError) AllErrors() []error { return m }

// AttestationStateServiceInitializedRequestValidationError is the validation
// error returned by AttestationStateServiceInitializedRequest.Validate if the
// designated constraints aren't met.
type AttestationStateServiceInitializedRequestValidationError struct {
	field  string
	reason string
	cause  error
	key    bool
}

// Field function returns field value.
func (e AttestationStateServiceInitializedRequestValidationError) Field() string { return e.field }

// Reason function returns reason value.
func (e AttestationStateServiceInitializedRequestValidationError) Reason() string { return e.reason }

// Cause function returns cause value.
func (e AttestationStateServiceInitializedRequestValidationError) Cause() error { return e.cause }

// Key function returns key value.
func (e AttestationStateServiceInitializedRequestValidationError) Key() bool { return e.key }

// ErrorName returns error name.
func (e AttestationStateServiceInitializedRequestValidationError) ErrorName() string {
	return "AttestationStateServiceInitializedRequestValidationError"
}

// Error satisfies the builtin error interface
func (e AttestationStateServiceInitializedRequestValidationError) Error() string {
	cause := ""
	if e.cause != nil {
		cause = fmt.Sprintf(" | caused by: %v", e.cause)
	}

	key := ""
	if e.key {
		key = "key for "
	}

	return fmt.Sprintf(
		"invalid %sAttestationStateServiceInitializedRequest.%s: %s%s",
		key,
		e.field,
		e.reason,
		cause)
}

var _ error = AttestationStateServiceInitializedRequestValidationError{}

var _ interface {
	Field() string
	Reason() string
	Key() bool
	Cause() error
	ErrorName() string
} = AttestationStateServiceInitializedRequestValidationError{}

// Validate checks the field values on
// AttestationStateServiceInitializedResponse with the rules defined in the
// proto definition for this message. If any rules are violated, the first
// error encountered is returned, or nil if there are no violations.
func (m *AttestationStateServiceInitializedResponse) Validate() error {
	return m.validate(false)
}

// ValidateAll checks the field values on
// AttestationStateServiceInitializedResponse with the rules defined in the
// proto definition for this message. If any rules are violated, the result is
// a list of violation errors wrapped in
// AttestationStateServiceInitializedResponseMultiError, or nil if none found.
func (m *AttestationStateServiceInitializedResponse) ValidateAll() error {
	return m.validate(true)
}

func (m *AttestationStateServiceInitializedResponse) validate(all bool) error {
	if m == nil {
		return nil
	}

	var errors []error

	if all {
		switch v := interface{}(m.GetResult()).(type) {
		case interface{ ValidateAll() error }:
			if err := v.ValidateAll(); err != nil {
				errors = append(errors, AttestationStateServiceInitializedResponseValidationError{
					field:  "Result",
					reason: "embedded message failed validation",
					cause:  err,
				})
			}
		case interface{ Validate() error }:
			if err := v.Validate(); err != nil {
				errors = append(errors, AttestationStateServiceInitializedResponseValidationError{
					field:  "Result",
					reason: "embedded message failed validation",
					cause:  err,
				})
			}
		}
	} else if v, ok := interface{}(m.GetResult()).(interface{ Validate() error }); ok {
		if err := v.Validate(); err != nil {
			return AttestationStateServiceInitializedResponseValidationError{
				field:  "Result",
				reason: "embedded message failed validation",
				cause:  err,
			}
		}
	}

	if len(errors) > 0 {
		return AttestationStateServiceInitializedResponseMultiError(errors)
	}

	return nil
}

// AttestationStateServiceInitializedResponseMultiError is an error wrapping
// multiple validation errors returned by
// AttestationStateServiceInitializedResponse.ValidateAll() if the designated
// constraints aren't met.
type AttestationStateServiceInitializedResponseMultiError []error

// Error returns a concatenation of all the error messages it wraps.
func (m AttestationStateServiceInitializedResponseMultiError) Error() string {
	var msgs []string
	for _, err := range m {
		msgs = append(msgs, err.Error())
	}
	return strings.Join(msgs, "; ")
}

// AllErrors returns a list of validation violation errors.
func (m AttestationStateServiceInitializedResponseMultiError) AllErrors() []error { return m }

// AttestationStateServiceInitializedResponseValidationError is the validation
// error returned by AttestationStateServiceInitializedResponse.Validate if
// the designated constraints aren't met.
type AttestationStateServiceInitializedResponseValidationError struct {
	field  string
	reason string
	cause  error
	key    bool
}

// Field function returns field value.
func (e AttestationStateServiceInitializedResponseValidationError) Field() string { return e.field }

// Reason function returns reason value.
func (e AttestationStateServiceInitializedResponseValidationError) Reason() string { return e.reason }

// Cause function returns cause value.
func (e AttestationStateServiceInitializedResponseValidationError) Cause() error { return e.cause }

// Key function returns key value.
func (e AttestationStateServiceInitializedResponseValidationError) Key() bool { return e.key }

// ErrorName returns error name.
func (e AttestationStateServiceInitializedResponseValidationError) ErrorName() string {
	return "AttestationStateServiceInitializedResponseValidationError"
}

// Error satisfies the builtin error interface
func (e AttestationStateServiceInitializedResponseValidationError) Error() string {
	cause := ""
	if e.cause != nil {
		cause = fmt.Sprintf(" | caused by: %v", e.cause)
	}

	key := ""
	if e.key {
		key = "key for "
	}

	return fmt.Sprintf(
		"invalid %sAttestationStateServiceInitializedResponse.%s: %s%s",
		key,
		e.field,
		e.reason,
		cause)
}

var _ error = AttestationStateServiceInitializedResponseValidationError{}

var _ interface {
	Field() string
	Reason() string
	Key() bool
	Cause() error
	ErrorName() string
} = AttestationStateServiceInitializedResponseValidationError{}

// Validate checks the field values on AttestationStateServiceSaveRequest with
// the rules defined in the proto definition for this message. If any rules
// are violated, the first error encountered is returned, or nil if there are
// no violations.
func (m *AttestationStateServiceSaveRequest) Validate() error {
	return m.validate(false)
}

// ValidateAll checks the field values on AttestationStateServiceSaveRequest
// with the rules defined in the proto definition for this message. If any
// rules are violated, the result is a list of violation errors wrapped in
// AttestationStateServiceSaveRequestMultiError, or nil if none found.
func (m *AttestationStateServiceSaveRequest) ValidateAll() error {
	return m.validate(true)
}

func (m *AttestationStateServiceSaveRequest) validate(all bool) error {
	if m == nil {
		return nil
	}

	var errors []error

	if utf8.RuneCountInString(m.GetWorkflowRunId()) < 1 {
		err := AttestationStateServiceSaveRequestValidationError{
			field:  "WorkflowRunId",
			reason: "value length must be at least 1 runes",
		}
		if !all {
			return err
		}
		errors = append(errors, err)
	}

	if m.GetAttestationState() == nil {
		err := AttestationStateServiceSaveRequestValidationError{
			field:  "AttestationState",
			reason: "value is required",
		}
		if !all {
			return err
		}
		errors = append(errors, err)
	}

	if all {
		switch v := interface{}(m.GetAttestationState()).(type) {
		case interface{ ValidateAll() error }:
			if err := v.ValidateAll(); err != nil {
				errors = append(errors, AttestationStateServiceSaveRequestValidationError{
					field:  "AttestationState",
					reason: "embedded message failed validation",
					cause:  err,
				})
			}
		case interface{ Validate() error }:
			if err := v.Validate(); err != nil {
				errors = append(errors, AttestationStateServiceSaveRequestValidationError{
					field:  "AttestationState",
					reason: "embedded message failed validation",
					cause:  err,
				})
			}
		}
	} else if v, ok := interface{}(m.GetAttestationState()).(interface{ Validate() error }); ok {
		if err := v.Validate(); err != nil {
			return AttestationStateServiceSaveRequestValidationError{
				field:  "AttestationState",
				reason: "embedded message failed validation",
				cause:  err,
			}
		}
	}

	if len(errors) > 0 {
		return AttestationStateServiceSaveRequestMultiError(errors)
	}

	return nil
}

// AttestationStateServiceSaveRequestMultiError is an error wrapping multiple
// validation errors returned by
// AttestationStateServiceSaveRequest.ValidateAll() if the designated
// constraints aren't met.
type AttestationStateServiceSaveRequestMultiError []error

// Error returns a concatenation of all the error messages it wraps.
func (m AttestationStateServiceSaveRequestMultiError) Error() string {
	var msgs []string
	for _, err := range m {
		msgs = append(msgs, err.Error())
	}
	return strings.Join(msgs, "; ")
}

// AllErrors returns a list of validation violation errors.
func (m AttestationStateServiceSaveRequestMultiError) AllErrors() []error { return m }

// AttestationStateServiceSaveRequestValidationError is the validation error
// returned by AttestationStateServiceSaveRequest.Validate if the designated
// constraints aren't met.
type AttestationStateServiceSaveRequestValidationError struct {
	field  string
	reason string
	cause  error
	key    bool
}

// Field function returns field value.
func (e AttestationStateServiceSaveRequestValidationError) Field() string { return e.field }

// Reason function returns reason value.
func (e AttestationStateServiceSaveRequestValidationError) Reason() string { return e.reason }

// Cause function returns cause value.
func (e AttestationStateServiceSaveRequestValidationError) Cause() error { return e.cause }

// Key function returns key value.
func (e AttestationStateServiceSaveRequestValidationError) Key() bool { return e.key }

// ErrorName returns error name.
func (e AttestationStateServiceSaveRequestValidationError) ErrorName() string {
	return "AttestationStateServiceSaveRequestValidationError"
}

// Error satisfies the builtin error interface
func (e AttestationStateServiceSaveRequestValidationError) Error() string {
	cause := ""
	if e.cause != nil {
		cause = fmt.Sprintf(" | caused by: %v", e.cause)
	}

	key := ""
	if e.key {
		key = "key for "
	}

	return fmt.Sprintf(
		"invalid %sAttestationStateServiceSaveRequest.%s: %s%s",
		key,
		e.field,
		e.reason,
		cause)
}

var _ error = AttestationStateServiceSaveRequestValidationError{}

var _ interface {
	Field() string
	Reason() string
	Key() bool
	Cause() error
	ErrorName() string
} = AttestationStateServiceSaveRequestValidationError{}

// Validate checks the field values on AttestationStateServiceSaveResponse with
// the rules defined in the proto definition for this message. If any rules
// are violated, the first error encountered is returned, or nil if there are
// no violations.
func (m *AttestationStateServiceSaveResponse) Validate() error {
	return m.validate(false)
}

// ValidateAll checks the field values on AttestationStateServiceSaveResponse
// with the rules defined in the proto definition for this message. If any
// rules are violated, the result is a list of violation errors wrapped in
// AttestationStateServiceSaveResponseMultiError, or nil if none found.
func (m *AttestationStateServiceSaveResponse) ValidateAll() error {
	return m.validate(true)
}

func (m *AttestationStateServiceSaveResponse) validate(all bool) error {
	if m == nil {
		return nil
	}

	var errors []error

	if len(errors) > 0 {
		return AttestationStateServiceSaveResponseMultiError(errors)
	}

	return nil
}

// AttestationStateServiceSaveResponseMultiError is an error wrapping multiple
// validation errors returned by
// AttestationStateServiceSaveResponse.ValidateAll() if the designated
// constraints aren't met.
type AttestationStateServiceSaveResponseMultiError []error

// Error returns a concatenation of all the error messages it wraps.
func (m AttestationStateServiceSaveResponseMultiError) Error() string {
	var msgs []string
	for _, err := range m {
		msgs = append(msgs, err.Error())
	}
	return strings.Join(msgs, "; ")
}

// AllErrors returns a list of validation violation errors.
func (m AttestationStateServiceSaveResponseMultiError) AllErrors() []error { return m }

// AttestationStateServiceSaveResponseValidationError is the validation error
// returned by AttestationStateServiceSaveResponse.Validate if the designated
// constraints aren't met.
type AttestationStateServiceSaveResponseValidationError struct {
	field  string
	reason string
	cause  error
	key    bool
}

// Field function returns field value.
func (e AttestationStateServiceSaveResponseValidationError) Field() string { return e.field }

// Reason function returns reason value.
func (e AttestationStateServiceSaveResponseValidationError) Reason() string { return e.reason }

// Cause function returns cause value.
func (e AttestationStateServiceSaveResponseValidationError) Cause() error { return e.cause }

// Key function returns key value.
func (e AttestationStateServiceSaveResponseValidationError) Key() bool { return e.key }

// ErrorName returns error name.
func (e AttestationStateServiceSaveResponseValidationError) ErrorName() string {
	return "AttestationStateServiceSaveResponseValidationError"
}

// Error satisfies the builtin error interface
func (e AttestationStateServiceSaveResponseValidationError) Error() string {
	cause := ""
	if e.cause != nil {
		cause = fmt.Sprintf(" | caused by: %v", e.cause)
	}

	key := ""
	if e.key {
		key = "key for "
	}

	return fmt.Sprintf(
		"invalid %sAttestationStateServiceSaveResponse.%s: %s%s",
		key,
		e.field,
		e.reason,
		cause)
}

var _ error = AttestationStateServiceSaveResponseValidationError{}

var _ interface {
	Field() string
	Reason() string
	Key() bool
	Cause() error
	ErrorName() string
} = AttestationStateServiceSaveResponseValidationError{}

// Validate checks the field values on AttestationStateServiceReadRequest with
// the rules defined in the proto definition for this message. If any rules
// are violated, the first error encountered is returned, or nil if there are
// no violations.
func (m *AttestationStateServiceReadRequest) Validate() error {
	return m.validate(false)
}

// ValidateAll checks the field values on AttestationStateServiceReadRequest
// with the rules defined in the proto definition for this message. If any
// rules are violated, the result is a list of violation errors wrapped in
// AttestationStateServiceReadRequestMultiError, or nil if none found.
func (m *AttestationStateServiceReadRequest) ValidateAll() error {
	return m.validate(true)
}

func (m *AttestationStateServiceReadRequest) validate(all bool) error {
	if m == nil {
		return nil
	}

	var errors []error

	if utf8.RuneCountInString(m.GetWorkflowRunId()) < 1 {
		err := AttestationStateServiceReadRequestValidationError{
			field:  "WorkflowRunId",
			reason: "value length must be at least 1 runes",
		}
		if !all {
			return err
		}
		errors = append(errors, err)
	}

	if len(errors) > 0 {
		return AttestationStateServiceReadRequestMultiError(errors)
	}

	return nil
}

// AttestationStateServiceReadRequestMultiError is an error wrapping multiple
// validation errors returned by
// AttestationStateServiceReadRequest.ValidateAll() if the designated
// constraints aren't met.
type AttestationStateServiceReadRequestMultiError []error

// Error returns a concatenation of all the error messages it wraps.
func (m AttestationStateServiceReadRequestMultiError) Error() string {
	var msgs []string
	for _, err := range m {
		msgs = append(msgs, err.Error())
	}
	return strings.Join(msgs, "; ")
}

// AllErrors returns a list of validation violation errors.
func (m AttestationStateServiceReadRequestMultiError) AllErrors() []error { return m }

// AttestationStateServiceReadRequestValidationError is the validation error
// returned by AttestationStateServiceReadRequest.Validate if the designated
// constraints aren't met.
type AttestationStateServiceReadRequestValidationError struct {
	field  string
	reason string
	cause  error
	key    bool
}

// Field function returns field value.
func (e AttestationStateServiceReadRequestValidationError) Field() string { return e.field }

// Reason function returns reason value.
func (e AttestationStateServiceReadRequestValidationError) Reason() string { return e.reason }

// Cause function returns cause value.
func (e AttestationStateServiceReadRequestValidationError) Cause() error { return e.cause }

// Key function returns key value.
func (e AttestationStateServiceReadRequestValidationError) Key() bool { return e.key }

// ErrorName returns error name.
func (e AttestationStateServiceReadRequestValidationError) ErrorName() string {
	return "AttestationStateServiceReadRequestValidationError"
}

// Error satisfies the builtin error interface
func (e AttestationStateServiceReadRequestValidationError) Error() string {
	cause := ""
	if e.cause != nil {
		cause = fmt.Sprintf(" | caused by: %v", e.cause)
	}

	key := ""
	if e.key {
		key = "key for "
	}

	return fmt.Sprintf(
		"invalid %sAttestationStateServiceReadRequest.%s: %s%s",
		key,
		e.field,
		e.reason,
		cause)
}

var _ error = AttestationStateServiceReadRequestValidationError{}

var _ interface {
	Field() string
	Reason() string
	Key() bool
	Cause() error
	ErrorName() string
} = AttestationStateServiceReadRequestValidationError{}

// Validate checks the field values on AttestationStateServiceReadResponse with
// the rules defined in the proto definition for this message. If any rules
// are violated, the first error encountered is returned, or nil if there are
// no violations.
func (m *AttestationStateServiceReadResponse) Validate() error {
	return m.validate(false)
}

// ValidateAll checks the field values on AttestationStateServiceReadResponse
// with the rules defined in the proto definition for this message. If any
// rules are violated, the result is a list of violation errors wrapped in
// AttestationStateServiceReadResponseMultiError, or nil if none found.
func (m *AttestationStateServiceReadResponse) ValidateAll() error {
	return m.validate(true)
}

func (m *AttestationStateServiceReadResponse) validate(all bool) error {
	if m == nil {
		return nil
	}

	var errors []error

	if all {
		switch v := interface{}(m.GetResult()).(type) {
		case interface{ ValidateAll() error }:
			if err := v.ValidateAll(); err != nil {
				errors = append(errors, AttestationStateServiceReadResponseValidationError{
					field:  "Result",
					reason: "embedded message failed validation",
					cause:  err,
				})
			}
		case interface{ Validate() error }:
			if err := v.Validate(); err != nil {
				errors = append(errors, AttestationStateServiceReadResponseValidationError{
					field:  "Result",
					reason: "embedded message failed validation",
					cause:  err,
				})
			}
		}
	} else if v, ok := interface{}(m.GetResult()).(interface{ Validate() error }); ok {
		if err := v.Validate(); err != nil {
			return AttestationStateServiceReadResponseValidationError{
				field:  "Result",
				reason: "embedded message failed validation",
				cause:  err,
			}
		}
	}

	if len(errors) > 0 {
		return AttestationStateServiceReadResponseMultiError(errors)
	}

	return nil
}

// AttestationStateServiceReadResponseMultiError is an error wrapping multiple
// validation errors returned by
// AttestationStateServiceReadResponse.ValidateAll() if the designated
// constraints aren't met.
type AttestationStateServiceReadResponseMultiError []error

// Error returns a concatenation of all the error messages it wraps.
func (m AttestationStateServiceReadResponseMultiError) Error() string {
	var msgs []string
	for _, err := range m {
		msgs = append(msgs, err.Error())
	}
	return strings.Join(msgs, "; ")
}

// AllErrors returns a list of validation violation errors.
func (m AttestationStateServiceReadResponseMultiError) AllErrors() []error { return m }

// AttestationStateServiceReadResponseValidationError is the validation error
// returned by AttestationStateServiceReadResponse.Validate if the designated
// constraints aren't met.
type AttestationStateServiceReadResponseValidationError struct {
	field  string
	reason string
	cause  error
	key    bool
}

// Field function returns field value.
func (e AttestationStateServiceReadResponseValidationError) Field() string { return e.field }

// Reason function returns reason value.
func (e AttestationStateServiceReadResponseValidationError) Reason() string { return e.reason }

// Cause function returns cause value.
func (e AttestationStateServiceReadResponseValidationError) Cause() error { return e.cause }

// Key function returns key value.
func (e AttestationStateServiceReadResponseValidationError) Key() bool { return e.key }

// ErrorName returns error name.
func (e AttestationStateServiceReadResponseValidationError) ErrorName() string {
	return "AttestationStateServiceReadResponseValidationError"
}

// Error satisfies the builtin error interface
func (e AttestationStateServiceReadResponseValidationError) Error() string {
	cause := ""
	if e.cause != nil {
		cause = fmt.Sprintf(" | caused by: %v", e.cause)
	}

	key := ""
	if e.key {
		key = "key for "
	}

	return fmt.Sprintf(
		"invalid %sAttestationStateServiceReadResponse.%s: %s%s",
		key,
		e.field,
		e.reason,
		cause)
}

var _ error = AttestationStateServiceReadResponseValidationError{}

var _ interface {
	Field() string
	Reason() string
	Key() bool
	Cause() error
	ErrorName() string
} = AttestationStateServiceReadResponseValidationError{}

// Validate checks the field values on AttestationStateServiceResetRequest with
// the rules defined in the proto definition for this message. If any rules
// are violated, the first error encountered is returned, or nil if there are
// no violations.
func (m *AttestationStateServiceResetRequest) Validate() error {
	return m.validate(false)
}

// ValidateAll checks the field values on AttestationStateServiceResetRequest
// with the rules defined in the proto definition for this message. If any
// rules are violated, the result is a list of violation errors wrapped in
// AttestationStateServiceResetRequestMultiError, or nil if none found.
func (m *AttestationStateServiceResetRequest) ValidateAll() error {
	return m.validate(true)
}

func (m *AttestationStateServiceResetRequest) validate(all bool) error {
	if m == nil {
		return nil
	}

	var errors []error

	if utf8.RuneCountInString(m.GetWorkflowRunId()) < 1 {
		err := AttestationStateServiceResetRequestValidationError{
			field:  "WorkflowRunId",
			reason: "value length must be at least 1 runes",
		}
		if !all {
			return err
		}
		errors = append(errors, err)
	}

	if len(errors) > 0 {
		return AttestationStateServiceResetRequestMultiError(errors)
	}

	return nil
}

// AttestationStateServiceResetRequestMultiError is an error wrapping multiple
// validation errors returned by
// AttestationStateServiceResetRequest.ValidateAll() if the designated
// constraints aren't met.
type AttestationStateServiceResetRequestMultiError []error

// Error returns a concatenation of all the error messages it wraps.
func (m AttestationStateServiceResetRequestMultiError) Error() string {
	var msgs []string
	for _, err := range m {
		msgs = append(msgs, err.Error())
	}
	return strings.Join(msgs, "; ")
}

// AllErrors returns a list of validation violation errors.
func (m AttestationStateServiceResetRequestMultiError) AllErrors() []error { return m }

// AttestationStateServiceResetRequestValidationError is the validation error
// returned by AttestationStateServiceResetRequest.Validate if the designated
// constraints aren't met.
type AttestationStateServiceResetRequestValidationError struct {
	field  string
	reason string
	cause  error
	key    bool
}

// Field function returns field value.
func (e AttestationStateServiceResetRequestValidationError) Field() string { return e.field }

// Reason function returns reason value.
func (e AttestationStateServiceResetRequestValidationError) Reason() string { return e.reason }

// Cause function returns cause value.
func (e AttestationStateServiceResetRequestValidationError) Cause() error { return e.cause }

// Key function returns key value.
func (e AttestationStateServiceResetRequestValidationError) Key() bool { return e.key }

// ErrorName returns error name.
func (e AttestationStateServiceResetRequestValidationError) ErrorName() string {
	return "AttestationStateServiceResetRequestValidationError"
}

// Error satisfies the builtin error interface
func (e AttestationStateServiceResetRequestValidationError) Error() string {
	cause := ""
	if e.cause != nil {
		cause = fmt.Sprintf(" | caused by: %v", e.cause)
	}

	key := ""
	if e.key {
		key = "key for "
	}

	return fmt.Sprintf(
		"invalid %sAttestationStateServiceResetRequest.%s: %s%s",
		key,
		e.field,
		e.reason,
		cause)
}

var _ error = AttestationStateServiceResetRequestValidationError{}

var _ interface {
	Field() string
	Reason() string
	Key() bool
	Cause() error
	ErrorName() string
} = AttestationStateServiceResetRequestValidationError{}

// Validate checks the field values on AttestationStateServiceResetResponse
// with the rules defined in the proto definition for this message. If any
// rules are violated, the first error encountered is returned, or nil if
// there are no violations.
func (m *AttestationStateServiceResetResponse) Validate() error {
	return m.validate(false)
}

// ValidateAll checks the field values on AttestationStateServiceResetResponse
// with the rules defined in the proto definition for this message. If any
// rules are violated, the result is a list of violation errors wrapped in
// AttestationStateServiceResetResponseMultiError, or nil if none found.
func (m *AttestationStateServiceResetResponse) ValidateAll() error {
	return m.validate(true)
}

func (m *AttestationStateServiceResetResponse) validate(all bool) error {
	if m == nil {
		return nil
	}

	var errors []error

	if len(errors) > 0 {
		return AttestationStateServiceResetResponseMultiError(errors)
	}

	return nil
}

// AttestationStateServiceResetResponseMultiError is an error wrapping multiple
// validation errors returned by
// AttestationStateServiceResetResponse.ValidateAll() if the designated
// constraints aren't met.
type AttestationStateServiceResetResponseMultiError []error

// Error returns a concatenation of all the error messages it wraps.
func (m AttestationStateServiceResetResponseMultiError) Error() string {
	var msgs []string
	for _, err := range m {
		msgs = append(msgs, err.Error())
	}
	return strings.Join(msgs, "; ")
}

// AllErrors returns a list of validation violation errors.
func (m AttestationStateServiceResetResponseMultiError) AllErrors() []error { return m }

// AttestationStateServiceResetResponseValidationError is the validation error
// returned by AttestationStateServiceResetResponse.Validate if the designated
// constraints aren't met.
type AttestationStateServiceResetResponseValidationError struct {
	field  string
	reason string
	cause  error
	key    bool
}

// Field function returns field value.
func (e AttestationStateServiceResetResponseValidationError) Field() string { return e.field }

// Reason function returns reason value.
func (e AttestationStateServiceResetResponseValidationError) Reason() string { return e.reason }

// Cause function returns cause value.
func (e AttestationStateServiceResetResponseValidationError) Cause() error { return e.cause }

// Key function returns key value.
func (e AttestationStateServiceResetResponseValidationError) Key() bool { return e.key }

// ErrorName returns error name.
func (e AttestationStateServiceResetResponseValidationError) ErrorName() string {
	return "AttestationStateServiceResetResponseValidationError"
}

// Error satisfies the builtin error interface
func (e AttestationStateServiceResetResponseValidationError) Error() string {
	cause := ""
	if e.cause != nil {
		cause = fmt.Sprintf(" | caused by: %v", e.cause)
	}

	key := ""
	if e.key {
		key = "key for "
	}

	return fmt.Sprintf(
		"invalid %sAttestationStateServiceResetResponse.%s: %s%s",
		key,
		e.field,
		e.reason,
		cause)
}

var _ error = AttestationStateServiceResetResponseValidationError{}

var _ interface {
	Field() string
	Reason() string
	Key() bool
	Cause() error
	ErrorName() string
} = AttestationStateServiceResetResponseValidationError{}

// Validate checks the field values on
// AttestationStateServiceInitializedResponse_Result with the rules defined in
// the proto definition for this message. If any rules are violated, the first
// error encountered is returned, or nil if there are no violations.
func (m *AttestationStateServiceInitializedResponse_Result) Validate() error {
	return m.validate(false)
}

// ValidateAll checks the field values on
// AttestationStateServiceInitializedResponse_Result with the rules defined in
// the proto definition for this message. If any rules are violated, the
// result is a list of violation errors wrapped in
// AttestationStateServiceInitializedResponse_ResultMultiError, or nil if none found.
func (m *AttestationStateServiceInitializedResponse_Result) ValidateAll() error {
	return m.validate(true)
}

func (m *AttestationStateServiceInitializedResponse_Result) validate(all bool) error {
	if m == nil {
		return nil
	}

	var errors []error

	// no validation rules for Initialized

	if len(errors) > 0 {
		return AttestationStateServiceInitializedResponse_ResultMultiError(errors)
	}

	return nil
}

// AttestationStateServiceInitializedResponse_ResultMultiError is an error
// wrapping multiple validation errors returned by
// AttestationStateServiceInitializedResponse_Result.ValidateAll() if the
// designated constraints aren't met.
type AttestationStateServiceInitializedResponse_ResultMultiError []error

// Error returns a concatenation of all the error messages it wraps.
func (m AttestationStateServiceInitializedResponse_ResultMultiError) Error() string {
	var msgs []string
	for _, err := range m {
		msgs = append(msgs, err.Error())
	}
	return strings.Join(msgs, "; ")
}

// AllErrors returns a list of validation violation errors.
func (m AttestationStateServiceInitializedResponse_ResultMultiError) AllErrors() []error { return m }

// AttestationStateServiceInitializedResponse_ResultValidationError is the
// validation error returned by
// AttestationStateServiceInitializedResponse_Result.Validate if the
// designated constraints aren't met.
type AttestationStateServiceInitializedResponse_ResultValidationError struct {
	field  string
	reason string
	cause  error
	key    bool
}

// Field function returns field value.
func (e AttestationStateServiceInitializedResponse_ResultValidationError) Field() string {
	return e.field
}

// Reason function returns reason value.
func (e AttestationStateServiceInitializedResponse_ResultValidationError) Reason() string {
	return e.reason
}

// Cause function returns cause value.
func (e AttestationStateServiceInitializedResponse_ResultValidationError) Cause() error {
	return e.cause
}

// Key function returns key value.
func (e AttestationStateServiceInitializedResponse_ResultValidationError) Key() bool { return e.key }

// ErrorName returns error name.
func (e AttestationStateServiceInitializedResponse_ResultValidationError) ErrorName() string {
	return "AttestationStateServiceInitializedResponse_ResultValidationError"
}

// Error satisfies the builtin error interface
func (e AttestationStateServiceInitializedResponse_ResultValidationError) Error() string {
	cause := ""
	if e.cause != nil {
		cause = fmt.Sprintf(" | caused by: %v", e.cause)
	}

	key := ""
	if e.key {
		key = "key for "
	}

	return fmt.Sprintf(
		"invalid %sAttestationStateServiceInitializedResponse_Result.%s: %s%s",
		key,
		e.field,
		e.reason,
		cause)
}

var _ error = AttestationStateServiceInitializedResponse_ResultValidationError{}

var _ interface {
	Field() string
	Reason() string
	Key() bool
	Cause() error
	ErrorName() string
} = AttestationStateServiceInitializedResponse_ResultValidationError{}

// Validate checks the field values on
// AttestationStateServiceReadResponse_Result with the rules defined in the
// proto definition for this message. If any rules are violated, the first
// error encountered is returned, or nil if there are no violations.
func (m *AttestationStateServiceReadResponse_Result) Validate() error {
	return m.validate(false)
}

// ValidateAll checks the field values on
// AttestationStateServiceReadResponse_Result with the rules defined in the
// proto definition for this message. If any rules are violated, the result is
// a list of violation errors wrapped in
// AttestationStateServiceReadResponse_ResultMultiError, or nil if none found.
func (m *AttestationStateServiceReadResponse_Result) ValidateAll() error {
	return m.validate(true)
}

func (m *AttestationStateServiceReadResponse_Result) validate(all bool) error {
	if m == nil {
		return nil
	}

	var errors []error

	if all {
		switch v := interface{}(m.GetAttestationState()).(type) {
		case interface{ ValidateAll() error }:
			if err := v.ValidateAll(); err != nil {
				errors = append(errors, AttestationStateServiceReadResponse_ResultValidationError{
					field:  "AttestationState",
					reason: "embedded message failed validation",
					cause:  err,
				})
			}
		case interface{ Validate() error }:
			if err := v.Validate(); err != nil {
				errors = append(errors, AttestationStateServiceReadResponse_ResultValidationError{
					field:  "AttestationState",
					reason: "embedded message failed validation",
					cause:  err,
				})
			}
		}
	} else if v, ok := interface{}(m.GetAttestationState()).(interface{ Validate() error }); ok {
		if err := v.Validate(); err != nil {
			return AttestationStateServiceReadResponse_ResultValidationError{
				field:  "AttestationState",
				reason: "embedded message failed validation",
				cause:  err,
			}
		}
	}

	if len(errors) > 0 {
		return AttestationStateServiceReadResponse_ResultMultiError(errors)
	}

	return nil
}

// AttestationStateServiceReadResponse_ResultMultiError is an error wrapping
// multiple validation errors returned by
// AttestationStateServiceReadResponse_Result.ValidateAll() if the designated
// constraints aren't met.
type AttestationStateServiceReadResponse_ResultMultiError []error

// Error returns a concatenation of all the error messages it wraps.
func (m AttestationStateServiceReadResponse_ResultMultiError) Error() string {
	var msgs []string
	for _, err := range m {
		msgs = append(msgs, err.Error())
	}
	return strings.Join(msgs, "; ")
}

// AllErrors returns a list of validation violation errors.
func (m AttestationStateServiceReadResponse_ResultMultiError) AllErrors() []error { return m }

// AttestationStateServiceReadResponse_ResultValidationError is the validation
// error returned by AttestationStateServiceReadResponse_Result.Validate if
// the designated constraints aren't met.
type AttestationStateServiceReadResponse_ResultValidationError struct {
	field  string
	reason string
	cause  error
	key    bool
}

// Field function returns field value.
func (e AttestationStateServiceReadResponse_ResultValidationError) Field() string { return e.field }

// Reason function returns reason value.
func (e AttestationStateServiceReadResponse_ResultValidationError) Reason() string { return e.reason }

// Cause function returns cause value.
func (e AttestationStateServiceReadResponse_ResultValidationError) Cause() error { return e.cause }

// Key function returns key value.
func (e AttestationStateServiceReadResponse_ResultValidationError) Key() bool { return e.key }

// ErrorName returns error name.
func (e AttestationStateServiceReadResponse_ResultValidationError) ErrorName() string {
	return "AttestationStateServiceReadResponse_ResultValidationError"
}

// Error satisfies the builtin error interface
func (e AttestationStateServiceReadResponse_ResultValidationError) Error() string {
	cause := ""
	if e.cause != nil {
		cause = fmt.Sprintf(" | caused by: %v", e.cause)
	}

	key := ""
	if e.key {
		key = "key for "
	}

	return fmt.Sprintf(
		"invalid %sAttestationStateServiceReadResponse_Result.%s: %s%s",
		key,
		e.field,
		e.reason,
		cause)
}

var _ error = AttestationStateServiceReadResponse_ResultValidationError{}

var _ interface {
	Field() string
	Reason() string
	Key() bool
	Cause() error
	ErrorName() string
} = AttestationStateServiceReadResponse_ResultValidationError{}