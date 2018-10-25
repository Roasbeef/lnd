// Code generated by protoc-gen-go. DO NOT EDIT.
// source: signrpc/signer.proto

/*
Package signrpc is a generated protocol buffer package.

It is generated from these files:
	signrpc/signer.proto

It has these top-level messages:
	KeyLocator
	KeyDescriptor
	TxOut
	SignDescriptor
	SignReq
	SignResp
	InputScript
	InputScriptResp
*/
package signrpc

import proto "github.com/golang/protobuf/proto"
import fmt "fmt"
import math "math"

import (
	context "golang.org/x/net/context"
	grpc "google.golang.org/grpc"
)

// Reference imports to suppress errors if they are not otherwise used.
var _ = proto.Marshal
var _ = fmt.Errorf
var _ = math.Inf

// This is a compile-time assertion to ensure that this generated file
// is compatible with the proto package it is being compiled against.
// A compilation error at this line likely means your copy of the
// proto package needs to be updated.
const _ = proto.ProtoPackageIsVersion2 // please upgrade the proto package

type KeyLocator struct {
	// / The family of key being identified.
	KeyFamily int32 `protobuf:"varint,1,opt,name=key_family,json=keyFamily" json:"key_family,omitempty"`
	// / The precise index of the key being identified.
	KeyIndex int32 `protobuf:"varint,2,opt,name=key_index,json=keyIndex" json:"key_index,omitempty"`
}

func (m *KeyLocator) Reset()                    { *m = KeyLocator{} }
func (m *KeyLocator) String() string            { return proto.CompactTextString(m) }
func (*KeyLocator) ProtoMessage()               {}
func (*KeyLocator) Descriptor() ([]byte, []int) { return fileDescriptor0, []int{0} }

func (m *KeyLocator) GetKeyFamily() int32 {
	if m != nil {
		return m.KeyFamily
	}
	return 0
}

func (m *KeyLocator) GetKeyIndex() int32 {
	if m != nil {
		return m.KeyIndex
	}
	return 0
}

type KeyDescriptor struct {
	// Types that are valid to be assigned to Key:
	//	*KeyDescriptor_RawKeyBytes
	//	*KeyDescriptor_KeyLoc
	Key isKeyDescriptor_Key `protobuf_oneof:"key"`
}

func (m *KeyDescriptor) Reset()                    { *m = KeyDescriptor{} }
func (m *KeyDescriptor) String() string            { return proto.CompactTextString(m) }
func (*KeyDescriptor) ProtoMessage()               {}
func (*KeyDescriptor) Descriptor() ([]byte, []int) { return fileDescriptor0, []int{1} }

type isKeyDescriptor_Key interface {
	isKeyDescriptor_Key()
}

type KeyDescriptor_RawKeyBytes struct {
	RawKeyBytes []byte `protobuf:"bytes,1,opt,name=raw_key_bytes,json=rawKeyBytes,proto3,oneof"`
}
type KeyDescriptor_KeyLoc struct {
	KeyLoc *KeyLocator `protobuf:"bytes,2,opt,name=key_loc,json=keyLoc,oneof"`
}

func (*KeyDescriptor_RawKeyBytes) isKeyDescriptor_Key() {}
func (*KeyDescriptor_KeyLoc) isKeyDescriptor_Key()      {}

func (m *KeyDescriptor) GetKey() isKeyDescriptor_Key {
	if m != nil {
		return m.Key
	}
	return nil
}

func (m *KeyDescriptor) GetRawKeyBytes() []byte {
	if x, ok := m.GetKey().(*KeyDescriptor_RawKeyBytes); ok {
		return x.RawKeyBytes
	}
	return nil
}

func (m *KeyDescriptor) GetKeyLoc() *KeyLocator {
	if x, ok := m.GetKey().(*KeyDescriptor_KeyLoc); ok {
		return x.KeyLoc
	}
	return nil
}

// XXX_OneofFuncs is for the internal use of the proto package.
func (*KeyDescriptor) XXX_OneofFuncs() (func(msg proto.Message, b *proto.Buffer) error, func(msg proto.Message, tag, wire int, b *proto.Buffer) (bool, error), func(msg proto.Message) (n int), []interface{}) {
	return _KeyDescriptor_OneofMarshaler, _KeyDescriptor_OneofUnmarshaler, _KeyDescriptor_OneofSizer, []interface{}{
		(*KeyDescriptor_RawKeyBytes)(nil),
		(*KeyDescriptor_KeyLoc)(nil),
	}
}

func _KeyDescriptor_OneofMarshaler(msg proto.Message, b *proto.Buffer) error {
	m := msg.(*KeyDescriptor)
	// key
	switch x := m.Key.(type) {
	case *KeyDescriptor_RawKeyBytes:
		b.EncodeVarint(1<<3 | proto.WireBytes)
		b.EncodeRawBytes(x.RawKeyBytes)
	case *KeyDescriptor_KeyLoc:
		b.EncodeVarint(2<<3 | proto.WireBytes)
		if err := b.EncodeMessage(x.KeyLoc); err != nil {
			return err
		}
	case nil:
	default:
		return fmt.Errorf("KeyDescriptor.Key has unexpected type %T", x)
	}
	return nil
}

func _KeyDescriptor_OneofUnmarshaler(msg proto.Message, tag, wire int, b *proto.Buffer) (bool, error) {
	m := msg.(*KeyDescriptor)
	switch tag {
	case 1: // key.raw_key_bytes
		if wire != proto.WireBytes {
			return true, proto.ErrInternalBadWireType
		}
		x, err := b.DecodeRawBytes(true)
		m.Key = &KeyDescriptor_RawKeyBytes{x}
		return true, err
	case 2: // key.key_loc
		if wire != proto.WireBytes {
			return true, proto.ErrInternalBadWireType
		}
		msg := new(KeyLocator)
		err := b.DecodeMessage(msg)
		m.Key = &KeyDescriptor_KeyLoc{msg}
		return true, err
	default:
		return false, nil
	}
}

func _KeyDescriptor_OneofSizer(msg proto.Message) (n int) {
	m := msg.(*KeyDescriptor)
	// key
	switch x := m.Key.(type) {
	case *KeyDescriptor_RawKeyBytes:
		n += proto.SizeVarint(1<<3 | proto.WireBytes)
		n += proto.SizeVarint(uint64(len(x.RawKeyBytes)))
		n += len(x.RawKeyBytes)
	case *KeyDescriptor_KeyLoc:
		s := proto.Size(x.KeyLoc)
		n += proto.SizeVarint(2<<3 | proto.WireBytes)
		n += proto.SizeVarint(uint64(s))
		n += s
	case nil:
	default:
		panic(fmt.Sprintf("proto: unexpected type %T in oneof", x))
	}
	return n
}

type TxOut struct {
	// / The value of the output being spent.
	Value int64 `protobuf:"varint,1,opt,name=value" json:"value,omitempty"`
	// / The script of the output being spent.
	PkScript []byte `protobuf:"bytes,2,opt,name=pk_script,json=pkScript,proto3" json:"pk_script,omitempty"`
}

func (m *TxOut) Reset()                    { *m = TxOut{} }
func (m *TxOut) String() string            { return proto.CompactTextString(m) }
func (*TxOut) ProtoMessage()               {}
func (*TxOut) Descriptor() ([]byte, []int) { return fileDescriptor0, []int{2} }

func (m *TxOut) GetValue() int64 {
	if m != nil {
		return m.Value
	}
	return 0
}

func (m *TxOut) GetPkScript() []byte {
	if m != nil {
		return m.PkScript
	}
	return nil
}

type SignDescriptor struct {
	// *
	// A descriptor that precisely describes *which* key to use for signing. This
	// may provide the raw public key directly, or require the Signer to re-derive
	// the key according to the populated derivation path.
	KeyDesc *KeyDescriptor `protobuf:"bytes,1,opt,name=key_desc,json=keyDesc" json:"key_desc,omitempty"`
	// *
	// A scalar value that will be added to the private key corresponding to the
	// above public key to obtain the private key to be used to sign this input.
	// This value is typically derived via the following computation:
	//
	// derivedKey = privkey + sha256(perCommitmentPoint || pubKey) mod N
	SingleTweak []byte `protobuf:"bytes,2,opt,name=single_tweak,json=singleTweak,proto3" json:"single_tweak,omitempty"`
	// *
	// A private key that will be used in combination with its corresponding
	// private key to derive the private key that is to be used to sign the target
	// input. Within the Lightning protocol, this value is typically the
	// commitment secret from a previously revoked commitment transaction. This
	// value is in combination with two hash values, and the original private key
	// to derive the private key to be used when signing.
	//
	// k = (privKey*sha256(pubKey || tweakPub) +
	// tweakPriv*sha256(tweakPub || pubKey)) mod N
	DoubleTweak []byte `protobuf:"bytes,3,opt,name=double_tweak,json=doubleTweak,proto3" json:"double_tweak,omitempty"`
	// *
	// The full script required to properly redeem the output.  This field will
	// only be populated if a p2wsh or a p2sh output is being signed.
	WitnessScript []byte `protobuf:"bytes,4,opt,name=witness_script,json=witnessScript,proto3" json:"witness_script,omitempty"`
	// *
	// A description of the output being spent. The value and script MUST be provided.
	Output *TxOut `protobuf:"bytes,5,opt,name=output" json:"output,omitempty"`
	// *
	// The target sighash type that should be used when generating the final
	// sighash, and signature.
	Sighash uint32 `protobuf:"varint,7,opt,name=sighash" json:"sighash,omitempty"`
	// *
	// The target input within the transaction that should be signed.
	InputIndex int32 `protobuf:"varint,8,opt,name=input_index,json=inputIndex" json:"input_index,omitempty"`
}

func (m *SignDescriptor) Reset()                    { *m = SignDescriptor{} }
func (m *SignDescriptor) String() string            { return proto.CompactTextString(m) }
func (*SignDescriptor) ProtoMessage()               {}
func (*SignDescriptor) Descriptor() ([]byte, []int) { return fileDescriptor0, []int{3} }

func (m *SignDescriptor) GetKeyDesc() *KeyDescriptor {
	if m != nil {
		return m.KeyDesc
	}
	return nil
}

func (m *SignDescriptor) GetSingleTweak() []byte {
	if m != nil {
		return m.SingleTweak
	}
	return nil
}

func (m *SignDescriptor) GetDoubleTweak() []byte {
	if m != nil {
		return m.DoubleTweak
	}
	return nil
}

func (m *SignDescriptor) GetWitnessScript() []byte {
	if m != nil {
		return m.WitnessScript
	}
	return nil
}

func (m *SignDescriptor) GetOutput() *TxOut {
	if m != nil {
		return m.Output
	}
	return nil
}

func (m *SignDescriptor) GetSighash() uint32 {
	if m != nil {
		return m.Sighash
	}
	return 0
}

func (m *SignDescriptor) GetInputIndex() int32 {
	if m != nil {
		return m.InputIndex
	}
	return 0
}

type SignReq struct {
	// / The raw bytes of the transaction to be signed.
	RawTxBytes []byte `protobuf:"bytes,1,opt,name=raw_tx_bytes,json=rawTxBytes,proto3" json:"raw_tx_bytes,omitempty"`
	// / A set of sign descriptors, for each input to be signed.
	SignDescs []*SignDescriptor `protobuf:"bytes,2,rep,name=sign_descs,json=signDescs" json:"sign_descs,omitempty"`
}

func (m *SignReq) Reset()                    { *m = SignReq{} }
func (m *SignReq) String() string            { return proto.CompactTextString(m) }
func (*SignReq) ProtoMessage()               {}
func (*SignReq) Descriptor() ([]byte, []int) { return fileDescriptor0, []int{4} }

func (m *SignReq) GetRawTxBytes() []byte {
	if m != nil {
		return m.RawTxBytes
	}
	return nil
}

func (m *SignReq) GetSignDescs() []*SignDescriptor {
	if m != nil {
		return m.SignDescs
	}
	return nil
}

type SignResp struct {
	// *
	// A set of signatures realized in a fixed 64-byte format ordered in ascending
	// input order.
	RawSigs [][]byte `protobuf:"bytes,1,rep,name=raw_sigs,json=rawSigs,proto3" json:"raw_sigs,omitempty"`
}

func (m *SignResp) Reset()                    { *m = SignResp{} }
func (m *SignResp) String() string            { return proto.CompactTextString(m) }
func (*SignResp) ProtoMessage()               {}
func (*SignResp) Descriptor() ([]byte, []int) { return fileDescriptor0, []int{5} }

func (m *SignResp) GetRawSigs() [][]byte {
	if m != nil {
		return m.RawSigs
	}
	return nil
}

type InputScript struct {
	// / The serializes witness stack for the specified input.
	Witness [][]byte `protobuf:"bytes,1,rep,name=witness,proto3" json:"witness,omitempty"`
	// **
	// The optional sig script for the specified witness that will only be set if
	// the input specified is a nested p2sh witness program.
	SigScript []byte `protobuf:"bytes,2,opt,name=sig_script,json=sigScript,proto3" json:"sig_script,omitempty"`
}

func (m *InputScript) Reset()                    { *m = InputScript{} }
func (m *InputScript) String() string            { return proto.CompactTextString(m) }
func (*InputScript) ProtoMessage()               {}
func (*InputScript) Descriptor() ([]byte, []int) { return fileDescriptor0, []int{6} }

func (m *InputScript) GetWitness() [][]byte {
	if m != nil {
		return m.Witness
	}
	return nil
}

func (m *InputScript) GetSigScript() []byte {
	if m != nil {
		return m.SigScript
	}
	return nil
}

type InputScriptResp struct {
	// / The set of fully valid input scripts requested.
	InputScripts []*InputScript `protobuf:"bytes,1,rep,name=input_scripts,json=inputScripts" json:"input_scripts,omitempty"`
}

func (m *InputScriptResp) Reset()                    { *m = InputScriptResp{} }
func (m *InputScriptResp) String() string            { return proto.CompactTextString(m) }
func (*InputScriptResp) ProtoMessage()               {}
func (*InputScriptResp) Descriptor() ([]byte, []int) { return fileDescriptor0, []int{7} }

func (m *InputScriptResp) GetInputScripts() []*InputScript {
	if m != nil {
		return m.InputScripts
	}
	return nil
}

func init() {
	proto.RegisterType((*KeyLocator)(nil), "signrpc.KeyLocator")
	proto.RegisterType((*KeyDescriptor)(nil), "signrpc.KeyDescriptor")
	proto.RegisterType((*TxOut)(nil), "signrpc.TxOut")
	proto.RegisterType((*SignDescriptor)(nil), "signrpc.SignDescriptor")
	proto.RegisterType((*SignReq)(nil), "signrpc.SignReq")
	proto.RegisterType((*SignResp)(nil), "signrpc.SignResp")
	proto.RegisterType((*InputScript)(nil), "signrpc.InputScript")
	proto.RegisterType((*InputScriptResp)(nil), "signrpc.InputScriptResp")
}

// Reference imports to suppress errors if they are not otherwise used.
var _ context.Context
var _ grpc.ClientConn

// This is a compile-time assertion to ensure that this generated file
// is compatible with the grpc package it is being compiled against.
const _ = grpc.SupportPackageIsVersion4

// Client API for Signer service

type SignerClient interface {
	// *
	// SignOutputRaw is a method that can be used to generated a signature for a
	// set of inputs/outputs to a transaction. Each request specifies details
	// concerning how the outputs should be signed, which keys they should be
	// signed with, and also any optional tweaks. The return value is a fixed
	// 64-byte signature (the same format as we use on the wire in Lightning).
	//
	// If we are  unable to sign using the specified keys, then an error will be
	// returned.
	SignOutputRaw(ctx context.Context, in *SignReq, opts ...grpc.CallOption) (*SignResp, error)
	// *
	// ComputeInputScript generates a complete InputIndex for the passed
	// transaction with the signature as defined within the passed SignDescriptor.
	// This method should be capable of generating the proper input script for
	// both regular p2wkh output and p2wkh outputs nested within a regular p2sh
	// output.
	//
	// Note that when using this method to sign inputs belonging to the wallet,
	// the only items of the SignDescriptor that need to be populated are pkScript
	// in the TxOut field, the value in that same field, and finally the input
	// index.
	ComputeInputScript(ctx context.Context, in *SignReq, opts ...grpc.CallOption) (*InputScriptResp, error)
}

type signerClient struct {
	cc *grpc.ClientConn
}

func NewSignerClient(cc *grpc.ClientConn) SignerClient {
	return &signerClient{cc}
}

func (c *signerClient) SignOutputRaw(ctx context.Context, in *SignReq, opts ...grpc.CallOption) (*SignResp, error) {
	out := new(SignResp)
	err := grpc.Invoke(ctx, "/signrpc.Signer/SignOutputRaw", in, out, c.cc, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *signerClient) ComputeInputScript(ctx context.Context, in *SignReq, opts ...grpc.CallOption) (*InputScriptResp, error) {
	out := new(InputScriptResp)
	err := grpc.Invoke(ctx, "/signrpc.Signer/ComputeInputScript", in, out, c.cc, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// Server API for Signer service

type SignerServer interface {
	// *
	// SignOutputRaw is a method that can be used to generated a signature for a
	// set of inputs/outputs to a transaction. Each request specifies details
	// concerning how the outputs should be signed, which keys they should be
	// signed with, and also any optional tweaks. The return value is a fixed
	// 64-byte signature (the same format as we use on the wire in Lightning).
	//
	// If we are  unable to sign using the specified keys, then an error will be
	// returned.
	SignOutputRaw(context.Context, *SignReq) (*SignResp, error)
	// *
	// ComputeInputScript generates a complete InputIndex for the passed
	// transaction with the signature as defined within the passed SignDescriptor.
	// This method should be capable of generating the proper input script for
	// both regular p2wkh output and p2wkh outputs nested within a regular p2sh
	// output.
	//
	// Note that when using this method to sign inputs belonging to the wallet,
	// the only items of the SignDescriptor that need to be populated are pkScript
	// in the TxOut field, the value in that same field, and finally the input
	// index.
	ComputeInputScript(context.Context, *SignReq) (*InputScriptResp, error)
}

func RegisterSignerServer(s *grpc.Server, srv SignerServer) {
	s.RegisterService(&_Signer_serviceDesc, srv)
}

func _Signer_SignOutputRaw_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(SignReq)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(SignerServer).SignOutputRaw(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/signrpc.Signer/SignOutputRaw",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(SignerServer).SignOutputRaw(ctx, req.(*SignReq))
	}
	return interceptor(ctx, in, info, handler)
}

func _Signer_ComputeInputScript_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(SignReq)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(SignerServer).ComputeInputScript(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/signrpc.Signer/ComputeInputScript",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(SignerServer).ComputeInputScript(ctx, req.(*SignReq))
	}
	return interceptor(ctx, in, info, handler)
}

var _Signer_serviceDesc = grpc.ServiceDesc{
	ServiceName: "signrpc.Signer",
	HandlerType: (*SignerServer)(nil),
	Methods: []grpc.MethodDesc{
		{
			MethodName: "SignOutputRaw",
			Handler:    _Signer_SignOutputRaw_Handler,
		},
		{
			MethodName: "ComputeInputScript",
			Handler:    _Signer_ComputeInputScript_Handler,
		},
	},
	Streams:  []grpc.StreamDesc{},
	Metadata: "signrpc/signer.proto",
}

func init() { proto.RegisterFile("signrpc/signer.proto", fileDescriptor0) }

var fileDescriptor0 = []byte{
	// 536 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0x6c, 0x93, 0xd1, 0x8f, 0xd2, 0x40,
	0x10, 0xc6, 0x0f, 0x10, 0xca, 0x4d, 0x5b, 0xd4, 0x95, 0x68, 0xd5, 0x18, 0xb1, 0xf1, 0x0c, 0x4f,
	0x18, 0xd1, 0x98, 0xe8, 0x93, 0x39, 0xcd, 0x85, 0x0b, 0x97, 0x5c, 0xb2, 0xf0, 0xde, 0x94, 0xb2,
	0xf6, 0x36, 0xe5, 0xda, 0x5e, 0x77, 0x6b, 0xe9, 0x9b, 0xff, 0x83, 0xff, 0xb0, 0x99, 0xdd, 0x05,
	0x8a, 0xde, 0x13, 0x7c, 0x5f, 0x67, 0x67, 0x7e, 0x3b, 0x5f, 0x0b, 0x43, 0xc1, 0xe3, 0xb4, 0xc8,
	0xa3, 0xf7, 0xf8, 0xcb, 0x8a, 0x49, 0x5e, 0x64, 0x32, 0x23, 0x96, 0x71, 0xfd, 0x19, 0xc0, 0x9c,
	0xd5, 0x57, 0x59, 0x14, 0xca, 0xac, 0x20, 0xaf, 0x00, 0x12, 0x56, 0x07, 0x3f, 0xc3, 0x5b, 0xbe,
	0xa9, 0xbd, 0xd6, 0xa8, 0x35, 0xee, 0xd2, 0xd3, 0x84, 0xd5, 0x17, 0xca, 0x20, 0x2f, 0x01, 0x45,
	0xc0, 0xd3, 0x35, 0xdb, 0x7a, 0x6d, 0xf5, 0xb4, 0x9f, 0xb0, 0xfa, 0x12, 0xb5, 0xbf, 0x01, 0x77,
	0xce, 0xea, 0x1f, 0x4c, 0x44, 0x05, 0xcf, 0xb1, 0xd9, 0x5b, 0x70, 0x8b, 0xb0, 0x0a, 0xf0, 0xc4,
	0xaa, 0x96, 0x4c, 0xa8, 0x7e, 0xce, 0xec, 0x84, 0xda, 0x45, 0x58, 0xcd, 0x59, 0x7d, 0x8e, 0x26,
	0x99, 0x80, 0x85, 0x15, 0x9b, 0x2c, 0x52, 0x1d, 0xed, 0xe9, 0x93, 0x89, 0x61, 0x9b, 0x1c, 0xc0,
	0x66, 0x27, 0xb4, 0x97, 0x28, 0x75, 0xde, 0x85, 0x4e, 0xc2, 0x6a, 0xff, 0x2b, 0x74, 0x97, 0xdb,
	0xeb, 0x52, 0x92, 0x21, 0x74, 0x7f, 0x85, 0x9b, 0x92, 0xa9, 0xee, 0x1d, 0xaa, 0x05, 0x92, 0xe6,
	0x49, 0xa0, 0x51, 0x54, 0x5f, 0x87, 0xf6, 0xf3, 0x64, 0xa1, 0xb4, 0xff, 0xa7, 0x0d, 0x83, 0x05,
	0x8f, 0xd3, 0x06, 0xeb, 0x07, 0xc0, 0x8b, 0x04, 0x6b, 0x26, 0x22, 0xd5, 0xc8, 0x9e, 0x3e, 0x6d,
	0x62, 0x1c, 0x2a, 0x29, 0xd2, 0xa2, 0x24, 0x6f, 0xc0, 0x11, 0x3c, 0x8d, 0x37, 0x2c, 0x90, 0x15,
	0x0b, 0x13, 0x33, 0xc5, 0xd6, 0xde, 0x12, 0x2d, 0x2c, 0x59, 0x67, 0xe5, 0x6a, 0x5f, 0xd2, 0xd1,
	0x25, 0xda, 0xd3, 0x25, 0x67, 0x30, 0xa8, 0xb8, 0x4c, 0x99, 0x10, 0x3b, 0xda, 0x07, 0xaa, 0xc8,
	0x35, 0xae, 0x46, 0x26, 0xef, 0xa0, 0x97, 0x95, 0x32, 0x2f, 0xa5, 0xd7, 0x55, 0x74, 0x83, 0x3d,
	0x9d, 0xda, 0x02, 0x35, 0x4f, 0x89, 0x07, 0x98, 0xec, 0x4d, 0x28, 0x6e, 0x3c, 0x6b, 0xd4, 0x1a,
	0xbb, 0x74, 0x27, 0xc9, 0x6b, 0xb0, 0x79, 0x9a, 0x97, 0xd2, 0xa4, 0xd7, 0x57, 0xe9, 0x81, 0xb2,
	0x74, 0x7e, 0x11, 0x58, 0xb8, 0x14, 0xca, 0xee, 0xc8, 0x08, 0x1c, 0x4c, 0x4e, 0x6e, 0x9b, 0xc1,
	0x51, 0x28, 0xc2, 0x6a, 0xb9, 0xd5, 0xa9, 0x7d, 0x06, 0x40, 0x00, 0xb5, 0x30, 0xe1, 0xb5, 0x47,
	0x9d, 0xb1, 0x3d, 0x7d, 0xb6, 0x67, 0x3a, 0x5e, 0x2e, 0x3d, 0x15, 0x46, 0x0b, 0xff, 0x0c, 0xfa,
	0x7a, 0x88, 0xc8, 0xc9, 0x73, 0xe8, 0xe3, 0x14, 0xc1, 0x63, 0x9c, 0xd0, 0x19, 0x3b, 0xd4, 0x2a,
	0xc2, 0x6a, 0xc1, 0x63, 0xe1, 0x5f, 0x80, 0x7d, 0x89, 0x64, 0xe6, 0xf6, 0x1e, 0x58, 0x66, 0x1d,
	0xbb, 0x42, 0x23, 0xf1, 0x85, 0x15, 0x3c, 0x3e, 0x0e, 0x1a, 0xc7, 0x99, 0xa4, 0xaf, 0xe0, 0x61,
	0xa3, 0x8f, 0x9a, 0xfa, 0x05, 0x5c, 0xbd, 0x07, 0x7d, 0x46, 0x77, 0xb4, 0xa7, 0xc3, 0x3d, 0x7c,
	0xf3, 0x80, 0xc3, 0x0f, 0x42, 0x4c, 0x7f, 0xb7, 0xa0, 0xb7, 0x50, 0x5f, 0x11, 0xf9, 0x04, 0x2e,
	0xfe, 0xbb, 0x56, 0x5b, 0xa7, 0x61, 0x45, 0x1e, 0x1d, 0x5d, 0x9e, 0xb2, 0xbb, 0x17, 0x8f, 0xff,
	0x71, 0x44, 0x4e, 0xbe, 0x01, 0xf9, 0x9e, 0xdd, 0xe6, 0xa5, 0x64, 0xcd, 0xdb, 0xfd, 0x7f, 0xd4,
	0xbb, 0x17, 0x86, 0x89, 0x7c, 0xd5, 0x53, 0x9f, 0xef, 0xc7, 0xbf, 0x01, 0x00, 0x00, 0xff, 0xff,
	0x7b, 0x48, 0x93, 0x2a, 0xd6, 0x03, 0x00, 0x00,
}