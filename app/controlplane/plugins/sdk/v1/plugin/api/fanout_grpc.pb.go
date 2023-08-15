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

// Code generated by protoc-gen-go-grpc. DO NOT EDIT.
// versions:
// - protoc-gen-go-grpc v1.3.0
// - protoc             (unknown)
// source: fanout.proto

package api

import (
	context "context"
	grpc "google.golang.org/grpc"
	codes "google.golang.org/grpc/codes"
	status "google.golang.org/grpc/status"
)

// This is a compile-time assertion to ensure that this generated file
// is compatible with the grpc package it is being compiled against.
// Requires gRPC-Go v1.32.0 or later.
const _ = grpc.SupportPackageIsVersion7

const (
	FanoutService_Describe_FullMethodName             = "/api.FanoutService/Describe"
	FanoutService_ValidateRegistration_FullMethodName = "/api.FanoutService/ValidateRegistration"
	FanoutService_ValidateAttachment_FullMethodName   = "/api.FanoutService/ValidateAttachment"
	FanoutService_String_FullMethodName               = "/api.FanoutService/String"
	FanoutService_IsSubscribedTo_FullMethodName       = "/api.FanoutService/IsSubscribedTo"
	FanoutService_Register_FullMethodName             = "/api.FanoutService/Register"
	FanoutService_Attach_FullMethodName               = "/api.FanoutService/Attach"
	FanoutService_Execute_FullMethodName              = "/api.FanoutService/Execute"
)

// FanoutServiceClient is the client API for FanoutService service.
//
// For semantics around ctx use and closing/ending streaming RPCs, please refer to https://pkg.go.dev/google.golang.org/grpc/?tab=doc#ClientConn.NewStream.
type FanoutServiceClient interface {
	// Core / Shared
	Describe(ctx context.Context, in *DescribeRequest, opts ...grpc.CallOption) (*DescribeResponse, error)
	ValidateRegistration(ctx context.Context, in *ValidateRegistrationRequest, opts ...grpc.CallOption) (*ValidateRegistrationResponse, error)
	ValidateAttachment(ctx context.Context, in *ValidateAttachmentRequest, opts ...grpc.CallOption) (*ValidateAttachmentResponse, error)
	String(ctx context.Context, in *StringRequest, opts ...grpc.CallOption) (*StringResponse, error)
	IsSubscribedTo(ctx context.Context, in *IsSubscribedToRequest, opts ...grpc.CallOption) (*IsSubscribedToResponse, error)
	// per-plugin
	Register(ctx context.Context, in *RegisterRequest, opts ...grpc.CallOption) (*RegisterResponse, error)
	Attach(ctx context.Context, in *AttachRequest, opts ...grpc.CallOption) (*AttachResponse, error)
	Execute(ctx context.Context, in *ExecuteRequest, opts ...grpc.CallOption) (*ExecuteResponse, error)
}

type fanoutServiceClient struct {
	cc grpc.ClientConnInterface
}

func NewFanoutServiceClient(cc grpc.ClientConnInterface) FanoutServiceClient {
	return &fanoutServiceClient{cc}
}

func (c *fanoutServiceClient) Describe(ctx context.Context, in *DescribeRequest, opts ...grpc.CallOption) (*DescribeResponse, error) {
	out := new(DescribeResponse)
	err := c.cc.Invoke(ctx, FanoutService_Describe_FullMethodName, in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *fanoutServiceClient) ValidateRegistration(ctx context.Context, in *ValidateRegistrationRequest, opts ...grpc.CallOption) (*ValidateRegistrationResponse, error) {
	out := new(ValidateRegistrationResponse)
	err := c.cc.Invoke(ctx, FanoutService_ValidateRegistration_FullMethodName, in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *fanoutServiceClient) ValidateAttachment(ctx context.Context, in *ValidateAttachmentRequest, opts ...grpc.CallOption) (*ValidateAttachmentResponse, error) {
	out := new(ValidateAttachmentResponse)
	err := c.cc.Invoke(ctx, FanoutService_ValidateAttachment_FullMethodName, in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *fanoutServiceClient) String(ctx context.Context, in *StringRequest, opts ...grpc.CallOption) (*StringResponse, error) {
	out := new(StringResponse)
	err := c.cc.Invoke(ctx, FanoutService_String_FullMethodName, in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *fanoutServiceClient) IsSubscribedTo(ctx context.Context, in *IsSubscribedToRequest, opts ...grpc.CallOption) (*IsSubscribedToResponse, error) {
	out := new(IsSubscribedToResponse)
	err := c.cc.Invoke(ctx, FanoutService_IsSubscribedTo_FullMethodName, in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *fanoutServiceClient) Register(ctx context.Context, in *RegisterRequest, opts ...grpc.CallOption) (*RegisterResponse, error) {
	out := new(RegisterResponse)
	err := c.cc.Invoke(ctx, FanoutService_Register_FullMethodName, in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *fanoutServiceClient) Attach(ctx context.Context, in *AttachRequest, opts ...grpc.CallOption) (*AttachResponse, error) {
	out := new(AttachResponse)
	err := c.cc.Invoke(ctx, FanoutService_Attach_FullMethodName, in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *fanoutServiceClient) Execute(ctx context.Context, in *ExecuteRequest, opts ...grpc.CallOption) (*ExecuteResponse, error) {
	out := new(ExecuteResponse)
	err := c.cc.Invoke(ctx, FanoutService_Execute_FullMethodName, in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// FanoutServiceServer is the server API for FanoutService service.
// All implementations must embed UnimplementedFanoutServiceServer
// for forward compatibility
type FanoutServiceServer interface {
	// Core / Shared
	Describe(context.Context, *DescribeRequest) (*DescribeResponse, error)
	ValidateRegistration(context.Context, *ValidateRegistrationRequest) (*ValidateRegistrationResponse, error)
	ValidateAttachment(context.Context, *ValidateAttachmentRequest) (*ValidateAttachmentResponse, error)
	String(context.Context, *StringRequest) (*StringResponse, error)
	IsSubscribedTo(context.Context, *IsSubscribedToRequest) (*IsSubscribedToResponse, error)
	// per-plugin
	Register(context.Context, *RegisterRequest) (*RegisterResponse, error)
	Attach(context.Context, *AttachRequest) (*AttachResponse, error)
	Execute(context.Context, *ExecuteRequest) (*ExecuteResponse, error)
	mustEmbedUnimplementedFanoutServiceServer()
}

// UnimplementedFanoutServiceServer must be embedded to have forward compatible implementations.
type UnimplementedFanoutServiceServer struct {
}

func (UnimplementedFanoutServiceServer) Describe(context.Context, *DescribeRequest) (*DescribeResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method Describe not implemented")
}
func (UnimplementedFanoutServiceServer) ValidateRegistration(context.Context, *ValidateRegistrationRequest) (*ValidateRegistrationResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method ValidateRegistration not implemented")
}
func (UnimplementedFanoutServiceServer) ValidateAttachment(context.Context, *ValidateAttachmentRequest) (*ValidateAttachmentResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method ValidateAttachment not implemented")
}
func (UnimplementedFanoutServiceServer) String(context.Context, *StringRequest) (*StringResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method String not implemented")
}
func (UnimplementedFanoutServiceServer) IsSubscribedTo(context.Context, *IsSubscribedToRequest) (*IsSubscribedToResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method IsSubscribedTo not implemented")
}
func (UnimplementedFanoutServiceServer) Register(context.Context, *RegisterRequest) (*RegisterResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method Register not implemented")
}
func (UnimplementedFanoutServiceServer) Attach(context.Context, *AttachRequest) (*AttachResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method Attach not implemented")
}
func (UnimplementedFanoutServiceServer) Execute(context.Context, *ExecuteRequest) (*ExecuteResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method Execute not implemented")
}
func (UnimplementedFanoutServiceServer) mustEmbedUnimplementedFanoutServiceServer() {}

// UnsafeFanoutServiceServer may be embedded to opt out of forward compatibility for this service.
// Use of this interface is not recommended, as added methods to FanoutServiceServer will
// result in compilation errors.
type UnsafeFanoutServiceServer interface {
	mustEmbedUnimplementedFanoutServiceServer()
}

func RegisterFanoutServiceServer(s grpc.ServiceRegistrar, srv FanoutServiceServer) {
	s.RegisterService(&FanoutService_ServiceDesc, srv)
}

func _FanoutService_Describe_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(DescribeRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(FanoutServiceServer).Describe(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: FanoutService_Describe_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(FanoutServiceServer).Describe(ctx, req.(*DescribeRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _FanoutService_ValidateRegistration_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(ValidateRegistrationRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(FanoutServiceServer).ValidateRegistration(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: FanoutService_ValidateRegistration_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(FanoutServiceServer).ValidateRegistration(ctx, req.(*ValidateRegistrationRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _FanoutService_ValidateAttachment_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(ValidateAttachmentRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(FanoutServiceServer).ValidateAttachment(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: FanoutService_ValidateAttachment_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(FanoutServiceServer).ValidateAttachment(ctx, req.(*ValidateAttachmentRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _FanoutService_String_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(StringRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(FanoutServiceServer).String(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: FanoutService_String_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(FanoutServiceServer).String(ctx, req.(*StringRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _FanoutService_IsSubscribedTo_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(IsSubscribedToRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(FanoutServiceServer).IsSubscribedTo(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: FanoutService_IsSubscribedTo_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(FanoutServiceServer).IsSubscribedTo(ctx, req.(*IsSubscribedToRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _FanoutService_Register_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(RegisterRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(FanoutServiceServer).Register(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: FanoutService_Register_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(FanoutServiceServer).Register(ctx, req.(*RegisterRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _FanoutService_Attach_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(AttachRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(FanoutServiceServer).Attach(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: FanoutService_Attach_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(FanoutServiceServer).Attach(ctx, req.(*AttachRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _FanoutService_Execute_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(ExecuteRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(FanoutServiceServer).Execute(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: FanoutService_Execute_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(FanoutServiceServer).Execute(ctx, req.(*ExecuteRequest))
	}
	return interceptor(ctx, in, info, handler)
}

// FanoutService_ServiceDesc is the grpc.ServiceDesc for FanoutService service.
// It's only intended for direct use with grpc.RegisterService,
// and not to be introspected or modified (even as a copy)
var FanoutService_ServiceDesc = grpc.ServiceDesc{
	ServiceName: "api.FanoutService",
	HandlerType: (*FanoutServiceServer)(nil),
	Methods: []grpc.MethodDesc{
		{
			MethodName: "Describe",
			Handler:    _FanoutService_Describe_Handler,
		},
		{
			MethodName: "ValidateRegistration",
			Handler:    _FanoutService_ValidateRegistration_Handler,
		},
		{
			MethodName: "ValidateAttachment",
			Handler:    _FanoutService_ValidateAttachment_Handler,
		},
		{
			MethodName: "String",
			Handler:    _FanoutService_String_Handler,
		},
		{
			MethodName: "IsSubscribedTo",
			Handler:    _FanoutService_IsSubscribedTo_Handler,
		},
		{
			MethodName: "Register",
			Handler:    _FanoutService_Register_Handler,
		},
		{
			MethodName: "Attach",
			Handler:    _FanoutService_Attach_Handler,
		},
		{
			MethodName: "Execute",
			Handler:    _FanoutService_Execute_Handler,
		},
	},
	Streams:  []grpc.StreamDesc{},
	Metadata: "fanout.proto",
}