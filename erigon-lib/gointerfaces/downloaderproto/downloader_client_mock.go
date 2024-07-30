// Code generated by MockGen. DO NOT EDIT.
// Source: github.com/erigontech/erigon-lib/gointerfaces/downloaderproto (interfaces: DownloaderClient)
//
// Generated by this command:
//
//	mockgen -typed=true -destination=./downloader_client_mock.go -package=downloaderproto . DownloaderClient
//

// Package downloaderproto is a generated GoMock package.
package downloaderproto

import (
	context "context"
	reflect "reflect"

	gomock "go.uber.org/mock/gomock"
	grpc "google.golang.org/grpc"
	emptypb "google.golang.org/protobuf/types/known/emptypb"
)

// MockDownloaderClient is a mock of DownloaderClient interface.
type MockDownloaderClient struct {
	ctrl     *gomock.Controller
	recorder *MockDownloaderClientMockRecorder
}

// MockDownloaderClientMockRecorder is the mock recorder for MockDownloaderClient.
type MockDownloaderClientMockRecorder struct {
	mock *MockDownloaderClient
}

// NewMockDownloaderClient creates a new mock instance.
func NewMockDownloaderClient(ctrl *gomock.Controller) *MockDownloaderClient {
	mock := &MockDownloaderClient{ctrl: ctrl}
	mock.recorder = &MockDownloaderClientMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockDownloaderClient) EXPECT() *MockDownloaderClientMockRecorder {
	return m.recorder
}

// Add mocks base method.
func (m *MockDownloaderClient) Add(arg0 context.Context, arg1 *AddRequest, arg2 ...grpc.CallOption) (*emptypb.Empty, error) {
	m.ctrl.T.Helper()
	varargs := []any{arg0, arg1}
	for _, a := range arg2 {
		varargs = append(varargs, a)
	}
	ret := m.ctrl.Call(m, "Add", varargs...)
	ret0, _ := ret[0].(*emptypb.Empty)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// Add indicates an expected call of Add.
func (mr *MockDownloaderClientMockRecorder) Add(arg0, arg1 any, arg2 ...any) *MockDownloaderClientAddCall {
	mr.mock.ctrl.T.Helper()
	varargs := append([]any{arg0, arg1}, arg2...)
	call := mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Add", reflect.TypeOf((*MockDownloaderClient)(nil).Add), varargs...)
	return &MockDownloaderClientAddCall{Call: call}
}

// MockDownloaderClientAddCall wrap *gomock.Call
type MockDownloaderClientAddCall struct {
	*gomock.Call
}

// Return rewrite *gomock.Call.Return
func (c *MockDownloaderClientAddCall) Return(arg0 *emptypb.Empty, arg1 error) *MockDownloaderClientAddCall {
	c.Call = c.Call.Return(arg0, arg1)
	return c
}

// Do rewrite *gomock.Call.Do
func (c *MockDownloaderClientAddCall) Do(f func(context.Context, *AddRequest, ...grpc.CallOption) (*emptypb.Empty, error)) *MockDownloaderClientAddCall {
	c.Call = c.Call.Do(f)
	return c
}

// DoAndReturn rewrite *gomock.Call.DoAndReturn
func (c *MockDownloaderClientAddCall) DoAndReturn(f func(context.Context, *AddRequest, ...grpc.CallOption) (*emptypb.Empty, error)) *MockDownloaderClientAddCall {
	c.Call = c.Call.DoAndReturn(f)
	return c
}

// Delete mocks base method.
func (m *MockDownloaderClient) Delete(arg0 context.Context, arg1 *DeleteRequest, arg2 ...grpc.CallOption) (*emptypb.Empty, error) {
	m.ctrl.T.Helper()
	varargs := []any{arg0, arg1}
	for _, a := range arg2 {
		varargs = append(varargs, a)
	}
	ret := m.ctrl.Call(m, "Delete", varargs...)
	ret0, _ := ret[0].(*emptypb.Empty)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// Delete indicates an expected call of Delete.
func (mr *MockDownloaderClientMockRecorder) Delete(arg0, arg1 any, arg2 ...any) *MockDownloaderClientDeleteCall {
	mr.mock.ctrl.T.Helper()
	varargs := append([]any{arg0, arg1}, arg2...)
	call := mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Delete", reflect.TypeOf((*MockDownloaderClient)(nil).Delete), varargs...)
	return &MockDownloaderClientDeleteCall{Call: call}
}

// MockDownloaderClientDeleteCall wrap *gomock.Call
type MockDownloaderClientDeleteCall struct {
	*gomock.Call
}

// Return rewrite *gomock.Call.Return
func (c *MockDownloaderClientDeleteCall) Return(arg0 *emptypb.Empty, arg1 error) *MockDownloaderClientDeleteCall {
	c.Call = c.Call.Return(arg0, arg1)
	return c
}

// Do rewrite *gomock.Call.Do
func (c *MockDownloaderClientDeleteCall) Do(f func(context.Context, *DeleteRequest, ...grpc.CallOption) (*emptypb.Empty, error)) *MockDownloaderClientDeleteCall {
	c.Call = c.Call.Do(f)
	return c
}

// DoAndReturn rewrite *gomock.Call.DoAndReturn
func (c *MockDownloaderClientDeleteCall) DoAndReturn(f func(context.Context, *DeleteRequest, ...grpc.CallOption) (*emptypb.Empty, error)) *MockDownloaderClientDeleteCall {
	c.Call = c.Call.DoAndReturn(f)
	return c
}

// ProhibitNewDownloads mocks base method.
func (m *MockDownloaderClient) ProhibitNewDownloads(arg0 context.Context, arg1 *ProhibitNewDownloadsRequest, arg2 ...grpc.CallOption) (*emptypb.Empty, error) {
	m.ctrl.T.Helper()
	varargs := []any{arg0, arg1}
	for _, a := range arg2 {
		varargs = append(varargs, a)
	}
	ret := m.ctrl.Call(m, "ProhibitNewDownloads", varargs...)
	ret0, _ := ret[0].(*emptypb.Empty)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// ProhibitNewDownloads indicates an expected call of ProhibitNewDownloads.
func (mr *MockDownloaderClientMockRecorder) ProhibitNewDownloads(arg0, arg1 any, arg2 ...any) *MockDownloaderClientProhibitNewDownloadsCall {
	mr.mock.ctrl.T.Helper()
	varargs := append([]any{arg0, arg1}, arg2...)
	call := mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "ProhibitNewDownloads", reflect.TypeOf((*MockDownloaderClient)(nil).ProhibitNewDownloads), varargs...)
	return &MockDownloaderClientProhibitNewDownloadsCall{Call: call}
}

// MockDownloaderClientProhibitNewDownloadsCall wrap *gomock.Call
type MockDownloaderClientProhibitNewDownloadsCall struct {
	*gomock.Call
}

// Return rewrite *gomock.Call.Return
func (c *MockDownloaderClientProhibitNewDownloadsCall) Return(arg0 *emptypb.Empty, arg1 error) *MockDownloaderClientProhibitNewDownloadsCall {
	c.Call = c.Call.Return(arg0, arg1)
	return c
}

// Do rewrite *gomock.Call.Do
func (c *MockDownloaderClientProhibitNewDownloadsCall) Do(f func(context.Context, *ProhibitNewDownloadsRequest, ...grpc.CallOption) (*emptypb.Empty, error)) *MockDownloaderClientProhibitNewDownloadsCall {
	c.Call = c.Call.Do(f)
	return c
}

// DoAndReturn rewrite *gomock.Call.DoAndReturn
func (c *MockDownloaderClientProhibitNewDownloadsCall) DoAndReturn(f func(context.Context, *ProhibitNewDownloadsRequest, ...grpc.CallOption) (*emptypb.Empty, error)) *MockDownloaderClientProhibitNewDownloadsCall {
	c.Call = c.Call.DoAndReturn(f)
	return c
}

// Stats mocks base method.
func (m *MockDownloaderClient) Stats(arg0 context.Context, arg1 *StatsRequest, arg2 ...grpc.CallOption) (*StatsReply, error) {
	m.ctrl.T.Helper()
	varargs := []any{arg0, arg1}
	for _, a := range arg2 {
		varargs = append(varargs, a)
	}
	ret := m.ctrl.Call(m, "Stats", varargs...)
	ret0, _ := ret[0].(*StatsReply)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// Stats indicates an expected call of Stats.
func (mr *MockDownloaderClientMockRecorder) Stats(arg0, arg1 any, arg2 ...any) *MockDownloaderClientStatsCall {
	mr.mock.ctrl.T.Helper()
	varargs := append([]any{arg0, arg1}, arg2...)
	call := mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Stats", reflect.TypeOf((*MockDownloaderClient)(nil).Stats), varargs...)
	return &MockDownloaderClientStatsCall{Call: call}
}

// MockDownloaderClientStatsCall wrap *gomock.Call
type MockDownloaderClientStatsCall struct {
	*gomock.Call
}

// Return rewrite *gomock.Call.Return
func (c *MockDownloaderClientStatsCall) Return(arg0 *StatsReply, arg1 error) *MockDownloaderClientStatsCall {
	c.Call = c.Call.Return(arg0, arg1)
	return c
}

// Do rewrite *gomock.Call.Do
func (c *MockDownloaderClientStatsCall) Do(f func(context.Context, *StatsRequest, ...grpc.CallOption) (*StatsReply, error)) *MockDownloaderClientStatsCall {
	c.Call = c.Call.Do(f)
	return c
}

// DoAndReturn rewrite *gomock.Call.DoAndReturn
func (c *MockDownloaderClientStatsCall) DoAndReturn(f func(context.Context, *StatsRequest, ...grpc.CallOption) (*StatsReply, error)) *MockDownloaderClientStatsCall {
	c.Call = c.Call.DoAndReturn(f)
	return c
}

// Verify mocks base method.
func (m *MockDownloaderClient) Verify(arg0 context.Context, arg1 *VerifyRequest, arg2 ...grpc.CallOption) (*emptypb.Empty, error) {
	m.ctrl.T.Helper()
	varargs := []any{arg0, arg1}
	for _, a := range arg2 {
		varargs = append(varargs, a)
	}
	ret := m.ctrl.Call(m, "Verify", varargs...)
	ret0, _ := ret[0].(*emptypb.Empty)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// Verify indicates an expected call of Verify.
func (mr *MockDownloaderClientMockRecorder) Verify(arg0, arg1 any, arg2 ...any) *MockDownloaderClientVerifyCall {
	mr.mock.ctrl.T.Helper()
	varargs := append([]any{arg0, arg1}, arg2...)
	call := mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Verify", reflect.TypeOf((*MockDownloaderClient)(nil).Verify), varargs...)
	return &MockDownloaderClientVerifyCall{Call: call}
}

// MockDownloaderClientVerifyCall wrap *gomock.Call
type MockDownloaderClientVerifyCall struct {
	*gomock.Call
}

// Return rewrite *gomock.Call.Return
func (c *MockDownloaderClientVerifyCall) Return(arg0 *emptypb.Empty, arg1 error) *MockDownloaderClientVerifyCall {
	c.Call = c.Call.Return(arg0, arg1)
	return c
}

// Do rewrite *gomock.Call.Do
func (c *MockDownloaderClientVerifyCall) Do(f func(context.Context, *VerifyRequest, ...grpc.CallOption) (*emptypb.Empty, error)) *MockDownloaderClientVerifyCall {
	c.Call = c.Call.Do(f)
	return c
}

// DoAndReturn rewrite *gomock.Call.DoAndReturn
func (c *MockDownloaderClientVerifyCall) DoAndReturn(f func(context.Context, *VerifyRequest, ...grpc.CallOption) (*emptypb.Empty, error)) *MockDownloaderClientVerifyCall {
	c.Call = c.Call.DoAndReturn(f)
	return c
}