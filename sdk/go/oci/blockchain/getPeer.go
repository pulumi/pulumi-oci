// Code generated by the Pulumi Terraform Bridge (tfgen) Tool DO NOT EDIT.
// *** WARNING: Do not edit by hand unless you're certain you know what you are doing! ***

package blockchain

import (
	"context"
	"reflect"

	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This data source provides details about a specific Peer resource in Oracle Cloud Infrastructure Blockchain service.
//
// # Gets information about a peer identified by the specific id
//
// ## Example Usage
//
// ```go
// package main
//
// import (
//
//	"github.com/pulumi/pulumi-oci/sdk/go/oci/Blockchain"
//	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
//
// )
//
//	func main() {
//		pulumi.Run(func(ctx *pulumi.Context) error {
//			_, err := Blockchain.GetPeer(ctx, &blockchain.GetPeerArgs{
//				BlockchainPlatformId: oci_blockchain_blockchain_platform.Test_blockchain_platform.Id,
//				PeerId:               oci_blockchain_peer.Test_peer.Id,
//			}, nil)
//			if err != nil {
//				return err
//			}
//			return nil
//		})
//	}
//
// ```
func LookupPeer(ctx *pulumi.Context, args *LookupPeerArgs, opts ...pulumi.InvokeOption) (*LookupPeerResult, error) {
	var rv LookupPeerResult
	err := ctx.Invoke("oci:Blockchain/getPeer:getPeer", args, &rv, opts...)
	if err != nil {
		return nil, err
	}
	return &rv, nil
}

// A collection of arguments for invoking getPeer.
type LookupPeerArgs struct {
	// Unique service identifier.
	BlockchainPlatformId string `pulumi:"blockchainPlatformId"`
	// Peer identifier.
	PeerId string `pulumi:"peerId"`
}

// A collection of values returned by getPeer.
type LookupPeerResult struct {
	// Availability Domain of peer
	Ad string `pulumi:"ad"`
	// peer alias
	Alias                string `pulumi:"alias"`
	BlockchainPlatformId string `pulumi:"blockchainPlatformId"`
	// Host on which the Peer exists
	Host string `pulumi:"host"`
	Id   string `pulumi:"id"`
	// OCPU allocation parameter
	OcpuAllocationParams []GetPeerOcpuAllocationParam `pulumi:"ocpuAllocationParams"`
	PeerId               string                       `pulumi:"peerId"`
	// peer identifier
	PeerKey string `pulumi:"peerKey"`
	// Peer role
	Role string `pulumi:"role"`
	// The current state of the peer.
	State string `pulumi:"state"`
}

func LookupPeerOutput(ctx *pulumi.Context, args LookupPeerOutputArgs, opts ...pulumi.InvokeOption) LookupPeerResultOutput {
	return pulumi.ToOutputWithContext(context.Background(), args).
		ApplyT(func(v interface{}) (LookupPeerResult, error) {
			args := v.(LookupPeerArgs)
			r, err := LookupPeer(ctx, &args, opts...)
			var s LookupPeerResult
			if r != nil {
				s = *r
			}
			return s, err
		}).(LookupPeerResultOutput)
}

// A collection of arguments for invoking getPeer.
type LookupPeerOutputArgs struct {
	// Unique service identifier.
	BlockchainPlatformId pulumi.StringInput `pulumi:"blockchainPlatformId"`
	// Peer identifier.
	PeerId pulumi.StringInput `pulumi:"peerId"`
}

func (LookupPeerOutputArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*LookupPeerArgs)(nil)).Elem()
}

// A collection of values returned by getPeer.
type LookupPeerResultOutput struct{ *pulumi.OutputState }

func (LookupPeerResultOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*LookupPeerResult)(nil)).Elem()
}

func (o LookupPeerResultOutput) ToLookupPeerResultOutput() LookupPeerResultOutput {
	return o
}

func (o LookupPeerResultOutput) ToLookupPeerResultOutputWithContext(ctx context.Context) LookupPeerResultOutput {
	return o
}

// Availability Domain of peer
func (o LookupPeerResultOutput) Ad() pulumi.StringOutput {
	return o.ApplyT(func(v LookupPeerResult) string { return v.Ad }).(pulumi.StringOutput)
}

// peer alias
func (o LookupPeerResultOutput) Alias() pulumi.StringOutput {
	return o.ApplyT(func(v LookupPeerResult) string { return v.Alias }).(pulumi.StringOutput)
}

func (o LookupPeerResultOutput) BlockchainPlatformId() pulumi.StringOutput {
	return o.ApplyT(func(v LookupPeerResult) string { return v.BlockchainPlatformId }).(pulumi.StringOutput)
}

// Host on which the Peer exists
func (o LookupPeerResultOutput) Host() pulumi.StringOutput {
	return o.ApplyT(func(v LookupPeerResult) string { return v.Host }).(pulumi.StringOutput)
}

func (o LookupPeerResultOutput) Id() pulumi.StringOutput {
	return o.ApplyT(func(v LookupPeerResult) string { return v.Id }).(pulumi.StringOutput)
}

// OCPU allocation parameter
func (o LookupPeerResultOutput) OcpuAllocationParams() GetPeerOcpuAllocationParamArrayOutput {
	return o.ApplyT(func(v LookupPeerResult) []GetPeerOcpuAllocationParam { return v.OcpuAllocationParams }).(GetPeerOcpuAllocationParamArrayOutput)
}

func (o LookupPeerResultOutput) PeerId() pulumi.StringOutput {
	return o.ApplyT(func(v LookupPeerResult) string { return v.PeerId }).(pulumi.StringOutput)
}

// peer identifier
func (o LookupPeerResultOutput) PeerKey() pulumi.StringOutput {
	return o.ApplyT(func(v LookupPeerResult) string { return v.PeerKey }).(pulumi.StringOutput)
}

// Peer role
func (o LookupPeerResultOutput) Role() pulumi.StringOutput {
	return o.ApplyT(func(v LookupPeerResult) string { return v.Role }).(pulumi.StringOutput)
}

// The current state of the peer.
func (o LookupPeerResultOutput) State() pulumi.StringOutput {
	return o.ApplyT(func(v LookupPeerResult) string { return v.State }).(pulumi.StringOutput)
}

func init() {
	pulumi.RegisterOutputType(LookupPeerResultOutput{})
}