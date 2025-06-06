// Code generated by pulumi-language-go DO NOT EDIT.
// *** WARNING: Do not edit by hand unless you're certain you know what you are doing! ***

package blockchain

import (
	"context"
	"reflect"

	"errors"
	"github.com/pulumi/pulumi-oci/sdk/v3/go/oci/internal"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This resource provides the Peer resource in Oracle Cloud Infrastructure Blockchain service.
//
// # Create Blockchain Platform Peer
//
// ## Example Usage
//
// ```go
// package main
//
// import (
//
//	"github.com/pulumi/pulumi-oci/sdk/v3/go/oci/blockchain"
//	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
//
// )
//
//	func main() {
//		pulumi.Run(func(ctx *pulumi.Context) error {
//			_, err := blockchain.NewPeer(ctx, "test_peer", &blockchain.PeerArgs{
//				Ad:                   pulumi.Any(peerAd),
//				BlockchainPlatformId: pulumi.Any(testBlockchainPlatform.Id),
//				OcpuAllocationParam: &blockchain.PeerOcpuAllocationParamArgs{
//					OcpuAllocationNumber: pulumi.Any(peerOcpuAllocationParamOcpuAllocationNumber),
//				},
//				Role:  pulumi.Any(peerRole),
//				Alias: pulumi.Any(peerAlias),
//			})
//			if err != nil {
//				return err
//			}
//			return nil
//		})
//	}
//
// ```
//
// ## Import
//
// Peers can be imported using the `id`, e.g.
//
// ```sh
// $ pulumi import oci:Blockchain/peer:Peer test_peer "blockchainPlatforms/{blockchainPlatformId}/peers/{peerId}"
// ```
type Peer struct {
	pulumi.CustomResourceState

	// Availability Domain to place new peer
	Ad pulumi.StringOutput `pulumi:"ad"`
	// peer alias
	Alias pulumi.StringOutput `pulumi:"alias"`
	// Unique service identifier.
	BlockchainPlatformId pulumi.StringOutput `pulumi:"blockchainPlatformId"`
	// Host on which the Peer exists
	Host pulumi.StringOutput `pulumi:"host"`
	// (Updatable) OCPU allocation parameter
	OcpuAllocationParam PeerOcpuAllocationParamOutput `pulumi:"ocpuAllocationParam"`
	// peer identifier
	PeerKey pulumi.StringOutput `pulumi:"peerKey"`
	// Peer role
	//
	// ** IMPORTANT **
	// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
	Role pulumi.StringOutput `pulumi:"role"`
	// The current state of the peer.
	State pulumi.StringOutput `pulumi:"state"`
}

// NewPeer registers a new resource with the given unique name, arguments, and options.
func NewPeer(ctx *pulumi.Context,
	name string, args *PeerArgs, opts ...pulumi.ResourceOption) (*Peer, error) {
	if args == nil {
		return nil, errors.New("missing one or more required arguments")
	}

	if args.Ad == nil {
		return nil, errors.New("invalid value for required argument 'Ad'")
	}
	if args.BlockchainPlatformId == nil {
		return nil, errors.New("invalid value for required argument 'BlockchainPlatformId'")
	}
	if args.OcpuAllocationParam == nil {
		return nil, errors.New("invalid value for required argument 'OcpuAllocationParam'")
	}
	if args.Role == nil {
		return nil, errors.New("invalid value for required argument 'Role'")
	}
	opts = internal.PkgResourceDefaultOpts(opts)
	var resource Peer
	err := ctx.RegisterResource("oci:Blockchain/peer:Peer", name, args, &resource, opts...)
	if err != nil {
		return nil, err
	}
	return &resource, nil
}

// GetPeer gets an existing Peer resource's state with the given name, ID, and optional
// state properties that are used to uniquely qualify the lookup (nil if not required).
func GetPeer(ctx *pulumi.Context,
	name string, id pulumi.IDInput, state *PeerState, opts ...pulumi.ResourceOption) (*Peer, error) {
	var resource Peer
	err := ctx.ReadResource("oci:Blockchain/peer:Peer", name, id, state, &resource, opts...)
	if err != nil {
		return nil, err
	}
	return &resource, nil
}

// Input properties used for looking up and filtering Peer resources.
type peerState struct {
	// Availability Domain to place new peer
	Ad *string `pulumi:"ad"`
	// peer alias
	Alias *string `pulumi:"alias"`
	// Unique service identifier.
	BlockchainPlatformId *string `pulumi:"blockchainPlatformId"`
	// Host on which the Peer exists
	Host *string `pulumi:"host"`
	// (Updatable) OCPU allocation parameter
	OcpuAllocationParam *PeerOcpuAllocationParam `pulumi:"ocpuAllocationParam"`
	// peer identifier
	PeerKey *string `pulumi:"peerKey"`
	// Peer role
	//
	// ** IMPORTANT **
	// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
	Role *string `pulumi:"role"`
	// The current state of the peer.
	State *string `pulumi:"state"`
}

type PeerState struct {
	// Availability Domain to place new peer
	Ad pulumi.StringPtrInput
	// peer alias
	Alias pulumi.StringPtrInput
	// Unique service identifier.
	BlockchainPlatformId pulumi.StringPtrInput
	// Host on which the Peer exists
	Host pulumi.StringPtrInput
	// (Updatable) OCPU allocation parameter
	OcpuAllocationParam PeerOcpuAllocationParamPtrInput
	// peer identifier
	PeerKey pulumi.StringPtrInput
	// Peer role
	//
	// ** IMPORTANT **
	// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
	Role pulumi.StringPtrInput
	// The current state of the peer.
	State pulumi.StringPtrInput
}

func (PeerState) ElementType() reflect.Type {
	return reflect.TypeOf((*peerState)(nil)).Elem()
}

type peerArgs struct {
	// Availability Domain to place new peer
	Ad string `pulumi:"ad"`
	// peer alias
	Alias *string `pulumi:"alias"`
	// Unique service identifier.
	BlockchainPlatformId string `pulumi:"blockchainPlatformId"`
	// (Updatable) OCPU allocation parameter
	OcpuAllocationParam PeerOcpuAllocationParam `pulumi:"ocpuAllocationParam"`
	// Peer role
	//
	// ** IMPORTANT **
	// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
	Role string `pulumi:"role"`
}

// The set of arguments for constructing a Peer resource.
type PeerArgs struct {
	// Availability Domain to place new peer
	Ad pulumi.StringInput
	// peer alias
	Alias pulumi.StringPtrInput
	// Unique service identifier.
	BlockchainPlatformId pulumi.StringInput
	// (Updatable) OCPU allocation parameter
	OcpuAllocationParam PeerOcpuAllocationParamInput
	// Peer role
	//
	// ** IMPORTANT **
	// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
	Role pulumi.StringInput
}

func (PeerArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*peerArgs)(nil)).Elem()
}

type PeerInput interface {
	pulumi.Input

	ToPeerOutput() PeerOutput
	ToPeerOutputWithContext(ctx context.Context) PeerOutput
}

func (*Peer) ElementType() reflect.Type {
	return reflect.TypeOf((**Peer)(nil)).Elem()
}

func (i *Peer) ToPeerOutput() PeerOutput {
	return i.ToPeerOutputWithContext(context.Background())
}

func (i *Peer) ToPeerOutputWithContext(ctx context.Context) PeerOutput {
	return pulumi.ToOutputWithContext(ctx, i).(PeerOutput)
}

// PeerArrayInput is an input type that accepts PeerArray and PeerArrayOutput values.
// You can construct a concrete instance of `PeerArrayInput` via:
//
//	PeerArray{ PeerArgs{...} }
type PeerArrayInput interface {
	pulumi.Input

	ToPeerArrayOutput() PeerArrayOutput
	ToPeerArrayOutputWithContext(context.Context) PeerArrayOutput
}

type PeerArray []PeerInput

func (PeerArray) ElementType() reflect.Type {
	return reflect.TypeOf((*[]*Peer)(nil)).Elem()
}

func (i PeerArray) ToPeerArrayOutput() PeerArrayOutput {
	return i.ToPeerArrayOutputWithContext(context.Background())
}

func (i PeerArray) ToPeerArrayOutputWithContext(ctx context.Context) PeerArrayOutput {
	return pulumi.ToOutputWithContext(ctx, i).(PeerArrayOutput)
}

// PeerMapInput is an input type that accepts PeerMap and PeerMapOutput values.
// You can construct a concrete instance of `PeerMapInput` via:
//
//	PeerMap{ "key": PeerArgs{...} }
type PeerMapInput interface {
	pulumi.Input

	ToPeerMapOutput() PeerMapOutput
	ToPeerMapOutputWithContext(context.Context) PeerMapOutput
}

type PeerMap map[string]PeerInput

func (PeerMap) ElementType() reflect.Type {
	return reflect.TypeOf((*map[string]*Peer)(nil)).Elem()
}

func (i PeerMap) ToPeerMapOutput() PeerMapOutput {
	return i.ToPeerMapOutputWithContext(context.Background())
}

func (i PeerMap) ToPeerMapOutputWithContext(ctx context.Context) PeerMapOutput {
	return pulumi.ToOutputWithContext(ctx, i).(PeerMapOutput)
}

type PeerOutput struct{ *pulumi.OutputState }

func (PeerOutput) ElementType() reflect.Type {
	return reflect.TypeOf((**Peer)(nil)).Elem()
}

func (o PeerOutput) ToPeerOutput() PeerOutput {
	return o
}

func (o PeerOutput) ToPeerOutputWithContext(ctx context.Context) PeerOutput {
	return o
}

// Availability Domain to place new peer
func (o PeerOutput) Ad() pulumi.StringOutput {
	return o.ApplyT(func(v *Peer) pulumi.StringOutput { return v.Ad }).(pulumi.StringOutput)
}

// peer alias
func (o PeerOutput) Alias() pulumi.StringOutput {
	return o.ApplyT(func(v *Peer) pulumi.StringOutput { return v.Alias }).(pulumi.StringOutput)
}

// Unique service identifier.
func (o PeerOutput) BlockchainPlatformId() pulumi.StringOutput {
	return o.ApplyT(func(v *Peer) pulumi.StringOutput { return v.BlockchainPlatformId }).(pulumi.StringOutput)
}

// Host on which the Peer exists
func (o PeerOutput) Host() pulumi.StringOutput {
	return o.ApplyT(func(v *Peer) pulumi.StringOutput { return v.Host }).(pulumi.StringOutput)
}

// (Updatable) OCPU allocation parameter
func (o PeerOutput) OcpuAllocationParam() PeerOcpuAllocationParamOutput {
	return o.ApplyT(func(v *Peer) PeerOcpuAllocationParamOutput { return v.OcpuAllocationParam }).(PeerOcpuAllocationParamOutput)
}

// peer identifier
func (o PeerOutput) PeerKey() pulumi.StringOutput {
	return o.ApplyT(func(v *Peer) pulumi.StringOutput { return v.PeerKey }).(pulumi.StringOutput)
}

// Peer role
//
// ** IMPORTANT **
// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
func (o PeerOutput) Role() pulumi.StringOutput {
	return o.ApplyT(func(v *Peer) pulumi.StringOutput { return v.Role }).(pulumi.StringOutput)
}

// The current state of the peer.
func (o PeerOutput) State() pulumi.StringOutput {
	return o.ApplyT(func(v *Peer) pulumi.StringOutput { return v.State }).(pulumi.StringOutput)
}

type PeerArrayOutput struct{ *pulumi.OutputState }

func (PeerArrayOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*[]*Peer)(nil)).Elem()
}

func (o PeerArrayOutput) ToPeerArrayOutput() PeerArrayOutput {
	return o
}

func (o PeerArrayOutput) ToPeerArrayOutputWithContext(ctx context.Context) PeerArrayOutput {
	return o
}

func (o PeerArrayOutput) Index(i pulumi.IntInput) PeerOutput {
	return pulumi.All(o, i).ApplyT(func(vs []interface{}) *Peer {
		return vs[0].([]*Peer)[vs[1].(int)]
	}).(PeerOutput)
}

type PeerMapOutput struct{ *pulumi.OutputState }

func (PeerMapOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*map[string]*Peer)(nil)).Elem()
}

func (o PeerMapOutput) ToPeerMapOutput() PeerMapOutput {
	return o
}

func (o PeerMapOutput) ToPeerMapOutputWithContext(ctx context.Context) PeerMapOutput {
	return o
}

func (o PeerMapOutput) MapIndex(k pulumi.StringInput) PeerOutput {
	return pulumi.All(o, k).ApplyT(func(vs []interface{}) *Peer {
		return vs[0].(map[string]*Peer)[vs[1].(string)]
	}).(PeerOutput)
}

func init() {
	pulumi.RegisterInputType(reflect.TypeOf((*PeerInput)(nil)).Elem(), &Peer{})
	pulumi.RegisterInputType(reflect.TypeOf((*PeerArrayInput)(nil)).Elem(), PeerArray{})
	pulumi.RegisterInputType(reflect.TypeOf((*PeerMapInput)(nil)).Elem(), PeerMap{})
	pulumi.RegisterOutputType(PeerOutput{})
	pulumi.RegisterOutputType(PeerArrayOutput{})
	pulumi.RegisterOutputType(PeerMapOutput{})
}
