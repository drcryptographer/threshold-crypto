package thresholdagent

import (
	"context"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type ThresholdAgentService struct {
	//dkg *schnorr.KeyGen
	//ceremony *schnorr.SigningCeremony
	//keyShare *schnorr.CloverShare
}

func NewThresholdAgentService() *ThresholdAgentService {
	return &ThresholdAgentService{}
}

func (tas *ThresholdAgentService) Authenticate(ctx context.Context, ar *AuthRequest) (*AuthResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method Authenticate not implemented")
}
func (tas *ThresholdAgentService) DkgSchnorrRound1(ctx context.Context, round0 *SchnorrRound0Msg) (*SchnorrRound1Msg, error) {
	return nil, status.Errorf(codes.Unimplemented, "method DkgSchnorrRound1 not implemented")
}
func (tas *ThresholdAgentService) DkgSchnorrRound2(ctx context.Context, round1s *SchnorrRound1MsgList) (*SchnorrRound2MsgList, error) {
	return nil, status.Errorf(codes.Unimplemented, "method DkgSchnorrRound2 not implemented")
}
func (tas *ThresholdAgentService) DkgSchnorrRound3(ctx context.Context, round2s *SchnorrRound2MsgList) (*SchnorrRound3Msg, error) {
	return nil, status.Errorf(codes.Unimplemented, "method DkgSchnorrRound3 not implemented")
}
func (tas *ThresholdAgentService) SchnorrSignRound1(ctx context.Context, round0 *SchnorrRound0Msg) (*SchnorrRound1Msg, error) {
	return nil, status.Errorf(codes.Unimplemented, "method SchnorrSignRound1 not implemented")
}
func (tas *ThresholdAgentService) SchnorrSignRound2(ctx context.Context, round1s *SchnorrRound1MsgList) (*SchnorrRound2MsgList, error) {
	return nil, status.Errorf(codes.Unimplemented, "method SchnorrSignRound2 not implemented")
}
func (tas *ThresholdAgentService) SchnorrSignRound3(ctx context.Context, round2s *SchnorrRound2MsgList) (*SchnorrRound3Msg, error) {
	return nil, status.Errorf(codes.Unimplemented, "method SchnorrSignRound3 not implemented")
}
func (tas *ThresholdAgentService) SchnorrSignRound4(ctx context.Context, round3s *SchnorrRound3MsgList) (*SchnorrSignature, error) {
	return nil, status.Errorf(codes.Unimplemented, "method SchnorrSignRound4 not implemented")
}
