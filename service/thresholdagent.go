package service

import (
	"context"
	"crypto/ecdsa"
	"crypto/x509"
	"github.com/clover-network/threshold-crypto/schnorr"
	"github.com/clover-network/threshold-crypto/thresholdagent"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type ThresholdAgentService struct {
	dkg        map[string]*schnorr.SchnorrKeyGen
	ceremony   map[string]*schnorr.SchnorrSigningCeremony
	keyShare   *schnorr.CloverSchnorrShare
	caCert     *x509.Certificate
	agentCerts map[int32]*x509.Certificate
	agentKey   *ecdsa.PrivateKey
}

func (tas *ThresholdAgentService) Id() int32 {
	return tas.keyShare.Id()
}

func NewThresholdAgentService(caCert *x509.Certificate, agentCerts map[int32]*x509.Certificate, agentKey *ecdsa.PrivateKey, keyShare *schnorr.CloverSchnorrShare) *ThresholdAgentService {
	return &ThresholdAgentService{
		dkg:        make(map[string]*schnorr.SchnorrKeyGen),
		ceremony:   make(map[string]*schnorr.SchnorrSigningCeremony),
		caCert:     caCert,
		agentKey:   agentKey,
		agentCerts: agentCerts,
		keyShare:   keyShare,
	}
}

func (tas *ThresholdAgentService) Authenticate(ctx context.Context, ar *thresholdagent.AuthRequest) (*thresholdagent.AuthResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method Authenticate not implemented")
}
func (tas *ThresholdAgentService) DkgSchnorrRound1(ctx context.Context, round0 *thresholdagent.SchnorrRound0Msg) (*thresholdagent.SchnorrRound1Msg, error) {
	return nil, status.Errorf(codes.Unimplemented, "method DkgSchnorrRound1 not implemented")
}
func (tas *ThresholdAgentService) DkgSchnorrRound2(ctx context.Context, round1s *thresholdagent.SchnorrRound1MsgList) (*thresholdagent.SchnorrRound2MsgList, error) {
	return nil, status.Errorf(codes.Unimplemented, "method DkgSchnorrRound2 not implemented")
}
func (tas *ThresholdAgentService) DkgSchnorrRoundFinal(ctx context.Context, round2s *thresholdagent.ResultMsg) (*thresholdagent.ResultMsg, error) {
	return nil, status.Errorf(codes.Unimplemented, "method DkgSchnorrRound3 not implemented")
}
func (tas *ThresholdAgentService) DkgSchnorrRound3(ctx context.Context, round2s *thresholdagent.SchnorrRound2MsgList) (*thresholdagent.SchnorrRound3Msg, error) {
	return nil, status.Errorf(codes.Unimplemented, "method DkgSchnorrRound3 not implemented")
}
func (tas *ThresholdAgentService) SchnorrSignRound1(ctx context.Context, round0 *thresholdagent.SchnorrRound0Msg) (*thresholdagent.SchnorrRound1Msg, error) {
	return nil, status.Errorf(codes.Unimplemented, "method SchnorrSignRound1 not implemented")
}
func (tas *ThresholdAgentService) SchnorrSignRound2(ctx context.Context, round1s *thresholdagent.SchnorrRound1MsgList) (*thresholdagent.SchnorrRound2MsgList, error) {
	return nil, status.Errorf(codes.Unimplemented, "method SchnorrSignRound2 not implemented")
}
func (tas *ThresholdAgentService) SchnorrSignRound3(ctx context.Context, round2s *thresholdagent.SchnorrRound2MsgList) (*thresholdagent.SchnorrRound3Msg, error) {
	return nil, status.Errorf(codes.Unimplemented, "method SchnorrSignRound3 not implemented")
}
func (tas *ThresholdAgentService) SchnorrSignRound4(ctx context.Context, round3s *thresholdagent.SchnorrRound3MsgList) (*thresholdagent.SchnorrSignature, error) {
	return nil, status.Errorf(codes.Unimplemented, "method SchnorrSignRound4 not implemented")
}
