// Code generated by the Pulumi Terraform Bridge (tfgen) Tool DO NOT EDIT.
// *** WARNING: Do not edit by hand unless you're certain you know what you are doing! ***

package kms

import (
	"context"
	"reflect"

	"github.com/pkg/errors"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This source triggers action to create, update and delete replica for a vault in Oracle Cloud Infrastructure Kms service.
//
// A vault replica is a mirror of that vault in a different region in the same realm.
// The vault replica and all the resources have same OCID with corresponding original ones.
//
// This only supports virtual private vault for now.
// This supports only one replica in a region for a vault. Multiple replica will be supported in the future.
//
// ## Example Usage
//
// ```go
// package main
//
// import (
//
//	"github.com/pulumi/pulumi-oci/sdk/go/oci/Kms"
//	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
//
// )
//
//	func main() {
//		pulumi.Run(func(ctx *pulumi.Context) error {
//			_, err := Kms.NewVaultVerification(ctx, "testReplication", &Kms.VaultVerificationArgs{
//				VaultId:       pulumi.Any(oci_kms_vault.Test_vault.Id),
//				ReplicaRegion: pulumi.Any(_var.Replica_region),
//			})
//			if err != nil {
//				return err
//			}
//			return nil
//		})
//	}
//
// ```
type VaultVerification struct {
	pulumi.CustomResourceState

	// (Updatable) The region to be created replica to. When updated,
	// replica will be deleted from old region, and created to updated region.
	ReplicaRegion pulumi.StringOutput `pulumi:"replicaRegion"`
	// The OCID of the primary vault to create replica from.
	VaultId pulumi.StringOutput `pulumi:"vaultId"`
}

// NewVaultVerification registers a new resource with the given unique name, arguments, and options.
func NewVaultVerification(ctx *pulumi.Context,
	name string, args *VaultVerificationArgs, opts ...pulumi.ResourceOption) (*VaultVerification, error) {
	if args == nil {
		return nil, errors.New("missing one or more required arguments")
	}

	if args.ReplicaRegion == nil {
		return nil, errors.New("invalid value for required argument 'ReplicaRegion'")
	}
	if args.VaultId == nil {
		return nil, errors.New("invalid value for required argument 'VaultId'")
	}
	var resource VaultVerification
	err := ctx.RegisterResource("oci:Kms/vaultVerification:VaultVerification", name, args, &resource, opts...)
	if err != nil {
		return nil, err
	}
	return &resource, nil
}

// GetVaultVerification gets an existing VaultVerification resource's state with the given name, ID, and optional
// state properties that are used to uniquely qualify the lookup (nil if not required).
func GetVaultVerification(ctx *pulumi.Context,
	name string, id pulumi.IDInput, state *VaultVerificationState, opts ...pulumi.ResourceOption) (*VaultVerification, error) {
	var resource VaultVerification
	err := ctx.ReadResource("oci:Kms/vaultVerification:VaultVerification", name, id, state, &resource, opts...)
	if err != nil {
		return nil, err
	}
	return &resource, nil
}

// Input properties used for looking up and filtering VaultVerification resources.
type vaultVerificationState struct {
	// (Updatable) The region to be created replica to. When updated,
	// replica will be deleted from old region, and created to updated region.
	ReplicaRegion *string `pulumi:"replicaRegion"`
	// The OCID of the primary vault to create replica from.
	VaultId *string `pulumi:"vaultId"`
}

type VaultVerificationState struct {
	// (Updatable) The region to be created replica to. When updated,
	// replica will be deleted from old region, and created to updated region.
	ReplicaRegion pulumi.StringPtrInput
	// The OCID of the primary vault to create replica from.
	VaultId pulumi.StringPtrInput
}

func (VaultVerificationState) ElementType() reflect.Type {
	return reflect.TypeOf((*vaultVerificationState)(nil)).Elem()
}

type vaultVerificationArgs struct {
	// (Updatable) The region to be created replica to. When updated,
	// replica will be deleted from old region, and created to updated region.
	ReplicaRegion string `pulumi:"replicaRegion"`
	// The OCID of the primary vault to create replica from.
	VaultId string `pulumi:"vaultId"`
}

// The set of arguments for constructing a VaultVerification resource.
type VaultVerificationArgs struct {
	// (Updatable) The region to be created replica to. When updated,
	// replica will be deleted from old region, and created to updated region.
	ReplicaRegion pulumi.StringInput
	// The OCID of the primary vault to create replica from.
	VaultId pulumi.StringInput
}

func (VaultVerificationArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*vaultVerificationArgs)(nil)).Elem()
}

type VaultVerificationInput interface {
	pulumi.Input

	ToVaultVerificationOutput() VaultVerificationOutput
	ToVaultVerificationOutputWithContext(ctx context.Context) VaultVerificationOutput
}

func (*VaultVerification) ElementType() reflect.Type {
	return reflect.TypeOf((**VaultVerification)(nil)).Elem()
}

func (i *VaultVerification) ToVaultVerificationOutput() VaultVerificationOutput {
	return i.ToVaultVerificationOutputWithContext(context.Background())
}

func (i *VaultVerification) ToVaultVerificationOutputWithContext(ctx context.Context) VaultVerificationOutput {
	return pulumi.ToOutputWithContext(ctx, i).(VaultVerificationOutput)
}

// VaultVerificationArrayInput is an input type that accepts VaultVerificationArray and VaultVerificationArrayOutput values.
// You can construct a concrete instance of `VaultVerificationArrayInput` via:
//
//	VaultVerificationArray{ VaultVerificationArgs{...} }
type VaultVerificationArrayInput interface {
	pulumi.Input

	ToVaultVerificationArrayOutput() VaultVerificationArrayOutput
	ToVaultVerificationArrayOutputWithContext(context.Context) VaultVerificationArrayOutput
}

type VaultVerificationArray []VaultVerificationInput

func (VaultVerificationArray) ElementType() reflect.Type {
	return reflect.TypeOf((*[]*VaultVerification)(nil)).Elem()
}

func (i VaultVerificationArray) ToVaultVerificationArrayOutput() VaultVerificationArrayOutput {
	return i.ToVaultVerificationArrayOutputWithContext(context.Background())
}

func (i VaultVerificationArray) ToVaultVerificationArrayOutputWithContext(ctx context.Context) VaultVerificationArrayOutput {
	return pulumi.ToOutputWithContext(ctx, i).(VaultVerificationArrayOutput)
}

// VaultVerificationMapInput is an input type that accepts VaultVerificationMap and VaultVerificationMapOutput values.
// You can construct a concrete instance of `VaultVerificationMapInput` via:
//
//	VaultVerificationMap{ "key": VaultVerificationArgs{...} }
type VaultVerificationMapInput interface {
	pulumi.Input

	ToVaultVerificationMapOutput() VaultVerificationMapOutput
	ToVaultVerificationMapOutputWithContext(context.Context) VaultVerificationMapOutput
}

type VaultVerificationMap map[string]VaultVerificationInput

func (VaultVerificationMap) ElementType() reflect.Type {
	return reflect.TypeOf((*map[string]*VaultVerification)(nil)).Elem()
}

func (i VaultVerificationMap) ToVaultVerificationMapOutput() VaultVerificationMapOutput {
	return i.ToVaultVerificationMapOutputWithContext(context.Background())
}

func (i VaultVerificationMap) ToVaultVerificationMapOutputWithContext(ctx context.Context) VaultVerificationMapOutput {
	return pulumi.ToOutputWithContext(ctx, i).(VaultVerificationMapOutput)
}

type VaultVerificationOutput struct{ *pulumi.OutputState }

func (VaultVerificationOutput) ElementType() reflect.Type {
	return reflect.TypeOf((**VaultVerification)(nil)).Elem()
}

func (o VaultVerificationOutput) ToVaultVerificationOutput() VaultVerificationOutput {
	return o
}

func (o VaultVerificationOutput) ToVaultVerificationOutputWithContext(ctx context.Context) VaultVerificationOutput {
	return o
}

// (Updatable) The region to be created replica to. When updated,
// replica will be deleted from old region, and created to updated region.
func (o VaultVerificationOutput) ReplicaRegion() pulumi.StringOutput {
	return o.ApplyT(func(v *VaultVerification) pulumi.StringOutput { return v.ReplicaRegion }).(pulumi.StringOutput)
}

// The OCID of the primary vault to create replica from.
func (o VaultVerificationOutput) VaultId() pulumi.StringOutput {
	return o.ApplyT(func(v *VaultVerification) pulumi.StringOutput { return v.VaultId }).(pulumi.StringOutput)
}

type VaultVerificationArrayOutput struct{ *pulumi.OutputState }

func (VaultVerificationArrayOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*[]*VaultVerification)(nil)).Elem()
}

func (o VaultVerificationArrayOutput) ToVaultVerificationArrayOutput() VaultVerificationArrayOutput {
	return o
}

func (o VaultVerificationArrayOutput) ToVaultVerificationArrayOutputWithContext(ctx context.Context) VaultVerificationArrayOutput {
	return o
}

func (o VaultVerificationArrayOutput) Index(i pulumi.IntInput) VaultVerificationOutput {
	return pulumi.All(o, i).ApplyT(func(vs []interface{}) *VaultVerification {
		return vs[0].([]*VaultVerification)[vs[1].(int)]
	}).(VaultVerificationOutput)
}

type VaultVerificationMapOutput struct{ *pulumi.OutputState }

func (VaultVerificationMapOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*map[string]*VaultVerification)(nil)).Elem()
}

func (o VaultVerificationMapOutput) ToVaultVerificationMapOutput() VaultVerificationMapOutput {
	return o
}

func (o VaultVerificationMapOutput) ToVaultVerificationMapOutputWithContext(ctx context.Context) VaultVerificationMapOutput {
	return o
}

func (o VaultVerificationMapOutput) MapIndex(k pulumi.StringInput) VaultVerificationOutput {
	return pulumi.All(o, k).ApplyT(func(vs []interface{}) *VaultVerification {
		return vs[0].(map[string]*VaultVerification)[vs[1].(string)]
	}).(VaultVerificationOutput)
}

func init() {
	pulumi.RegisterInputType(reflect.TypeOf((*VaultVerificationInput)(nil)).Elem(), &VaultVerification{})
	pulumi.RegisterInputType(reflect.TypeOf((*VaultVerificationArrayInput)(nil)).Elem(), VaultVerificationArray{})
	pulumi.RegisterInputType(reflect.TypeOf((*VaultVerificationMapInput)(nil)).Elem(), VaultVerificationMap{})
	pulumi.RegisterOutputType(VaultVerificationOutput{})
	pulumi.RegisterOutputType(VaultVerificationArrayOutput{})
	pulumi.RegisterOutputType(VaultVerificationMapOutput{})
}