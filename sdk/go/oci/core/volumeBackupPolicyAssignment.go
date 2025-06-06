// Code generated by pulumi-language-go DO NOT EDIT.
// *** WARNING: Do not edit by hand unless you're certain you know what you are doing! ***

package core

import (
	"context"
	"reflect"

	"errors"
	"github.com/pulumi/pulumi-oci/sdk/v3/go/oci/internal"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This resource provides the Volume Backup Policy Assignment resource in Oracle Cloud Infrastructure Core service.
//
// Assigns a volume backup policy to the specified volume or volume group. Note that a given volume or volume group can
// only have one backup policy assigned to it. If this operation is used for a volume or volume group that already
// has a different backup policy assigned, the prior backup policy will be silently unassigned.
//
// ## Example Usage
//
// ```go
// package main
//
// import (
//
//	"github.com/pulumi/pulumi-oci/sdk/v3/go/oci/core"
//	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
//
// )
//
//	func main() {
//		pulumi.Run(func(ctx *pulumi.Context) error {
//			_, err := core.NewVolumeBackupPolicyAssignment(ctx, "test_volume_backup_policy_assignment", &core.VolumeBackupPolicyAssignmentArgs{
//				AssetId:     pulumi.Any(testVolume.Id),
//				PolicyId:    pulumi.Any(testVolumeBackupPolicy.Id),
//				XrcKmsKeyId: pulumi.Any(testKey.Id),
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
// VolumeBackupPolicyAssignments can be imported using the `id`, e.g.
//
// ```sh
// $ pulumi import oci:Core/volumeBackupPolicyAssignment:VolumeBackupPolicyAssignment test_volume_backup_policy_assignment "id"
// ```
type VolumeBackupPolicyAssignment struct {
	pulumi.CustomResourceState

	// The OCID of the volume or volume group to assign the policy to.
	AssetId pulumi.StringOutput `pulumi:"assetId"`
	// The OCID of the volume backup policy to assign to the volume.
	PolicyId pulumi.StringOutput `pulumi:"policyId"`
	// The date and time the volume backup policy was assigned to the volume. The format is defined by [RFC3339](https://tools.ietf.org/html/rfc3339).
	TimeCreated pulumi.StringOutput `pulumi:"timeCreated"`
	// The OCID of the Vault service key which is the master encryption key for the block / boot volume cross region backups, which will be used in the destination region to encrypt the backup's encryption keys. For more information about the Vault service and encryption keys, see [Overview of Vault service](https://docs.cloud.oracle.com/iaas/Content/KeyManagement/Concepts/keyoverview.htm) and [Using Keys](https://docs.cloud.oracle.com/iaas/Content/KeyManagement/Tasks/usingkeys.htm).
	//
	// ** IMPORTANT **
	// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
	XrcKmsKeyId pulumi.StringOutput `pulumi:"xrcKmsKeyId"`
}

// NewVolumeBackupPolicyAssignment registers a new resource with the given unique name, arguments, and options.
func NewVolumeBackupPolicyAssignment(ctx *pulumi.Context,
	name string, args *VolumeBackupPolicyAssignmentArgs, opts ...pulumi.ResourceOption) (*VolumeBackupPolicyAssignment, error) {
	if args == nil {
		return nil, errors.New("missing one or more required arguments")
	}

	if args.AssetId == nil {
		return nil, errors.New("invalid value for required argument 'AssetId'")
	}
	if args.PolicyId == nil {
		return nil, errors.New("invalid value for required argument 'PolicyId'")
	}
	opts = internal.PkgResourceDefaultOpts(opts)
	var resource VolumeBackupPolicyAssignment
	err := ctx.RegisterResource("oci:Core/volumeBackupPolicyAssignment:VolumeBackupPolicyAssignment", name, args, &resource, opts...)
	if err != nil {
		return nil, err
	}
	return &resource, nil
}

// GetVolumeBackupPolicyAssignment gets an existing VolumeBackupPolicyAssignment resource's state with the given name, ID, and optional
// state properties that are used to uniquely qualify the lookup (nil if not required).
func GetVolumeBackupPolicyAssignment(ctx *pulumi.Context,
	name string, id pulumi.IDInput, state *VolumeBackupPolicyAssignmentState, opts ...pulumi.ResourceOption) (*VolumeBackupPolicyAssignment, error) {
	var resource VolumeBackupPolicyAssignment
	err := ctx.ReadResource("oci:Core/volumeBackupPolicyAssignment:VolumeBackupPolicyAssignment", name, id, state, &resource, opts...)
	if err != nil {
		return nil, err
	}
	return &resource, nil
}

// Input properties used for looking up and filtering VolumeBackupPolicyAssignment resources.
type volumeBackupPolicyAssignmentState struct {
	// The OCID of the volume or volume group to assign the policy to.
	AssetId *string `pulumi:"assetId"`
	// The OCID of the volume backup policy to assign to the volume.
	PolicyId *string `pulumi:"policyId"`
	// The date and time the volume backup policy was assigned to the volume. The format is defined by [RFC3339](https://tools.ietf.org/html/rfc3339).
	TimeCreated *string `pulumi:"timeCreated"`
	// The OCID of the Vault service key which is the master encryption key for the block / boot volume cross region backups, which will be used in the destination region to encrypt the backup's encryption keys. For more information about the Vault service and encryption keys, see [Overview of Vault service](https://docs.cloud.oracle.com/iaas/Content/KeyManagement/Concepts/keyoverview.htm) and [Using Keys](https://docs.cloud.oracle.com/iaas/Content/KeyManagement/Tasks/usingkeys.htm).
	//
	// ** IMPORTANT **
	// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
	XrcKmsKeyId *string `pulumi:"xrcKmsKeyId"`
}

type VolumeBackupPolicyAssignmentState struct {
	// The OCID of the volume or volume group to assign the policy to.
	AssetId pulumi.StringPtrInput
	// The OCID of the volume backup policy to assign to the volume.
	PolicyId pulumi.StringPtrInput
	// The date and time the volume backup policy was assigned to the volume. The format is defined by [RFC3339](https://tools.ietf.org/html/rfc3339).
	TimeCreated pulumi.StringPtrInput
	// The OCID of the Vault service key which is the master encryption key for the block / boot volume cross region backups, which will be used in the destination region to encrypt the backup's encryption keys. For more information about the Vault service and encryption keys, see [Overview of Vault service](https://docs.cloud.oracle.com/iaas/Content/KeyManagement/Concepts/keyoverview.htm) and [Using Keys](https://docs.cloud.oracle.com/iaas/Content/KeyManagement/Tasks/usingkeys.htm).
	//
	// ** IMPORTANT **
	// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
	XrcKmsKeyId pulumi.StringPtrInput
}

func (VolumeBackupPolicyAssignmentState) ElementType() reflect.Type {
	return reflect.TypeOf((*volumeBackupPolicyAssignmentState)(nil)).Elem()
}

type volumeBackupPolicyAssignmentArgs struct {
	// The OCID of the volume or volume group to assign the policy to.
	AssetId string `pulumi:"assetId"`
	// The OCID of the volume backup policy to assign to the volume.
	PolicyId string `pulumi:"policyId"`
	// The OCID of the Vault service key which is the master encryption key for the block / boot volume cross region backups, which will be used in the destination region to encrypt the backup's encryption keys. For more information about the Vault service and encryption keys, see [Overview of Vault service](https://docs.cloud.oracle.com/iaas/Content/KeyManagement/Concepts/keyoverview.htm) and [Using Keys](https://docs.cloud.oracle.com/iaas/Content/KeyManagement/Tasks/usingkeys.htm).
	//
	// ** IMPORTANT **
	// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
	XrcKmsKeyId *string `pulumi:"xrcKmsKeyId"`
}

// The set of arguments for constructing a VolumeBackupPolicyAssignment resource.
type VolumeBackupPolicyAssignmentArgs struct {
	// The OCID of the volume or volume group to assign the policy to.
	AssetId pulumi.StringInput
	// The OCID of the volume backup policy to assign to the volume.
	PolicyId pulumi.StringInput
	// The OCID of the Vault service key which is the master encryption key for the block / boot volume cross region backups, which will be used in the destination region to encrypt the backup's encryption keys. For more information about the Vault service and encryption keys, see [Overview of Vault service](https://docs.cloud.oracle.com/iaas/Content/KeyManagement/Concepts/keyoverview.htm) and [Using Keys](https://docs.cloud.oracle.com/iaas/Content/KeyManagement/Tasks/usingkeys.htm).
	//
	// ** IMPORTANT **
	// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
	XrcKmsKeyId pulumi.StringPtrInput
}

func (VolumeBackupPolicyAssignmentArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*volumeBackupPolicyAssignmentArgs)(nil)).Elem()
}

type VolumeBackupPolicyAssignmentInput interface {
	pulumi.Input

	ToVolumeBackupPolicyAssignmentOutput() VolumeBackupPolicyAssignmentOutput
	ToVolumeBackupPolicyAssignmentOutputWithContext(ctx context.Context) VolumeBackupPolicyAssignmentOutput
}

func (*VolumeBackupPolicyAssignment) ElementType() reflect.Type {
	return reflect.TypeOf((**VolumeBackupPolicyAssignment)(nil)).Elem()
}

func (i *VolumeBackupPolicyAssignment) ToVolumeBackupPolicyAssignmentOutput() VolumeBackupPolicyAssignmentOutput {
	return i.ToVolumeBackupPolicyAssignmentOutputWithContext(context.Background())
}

func (i *VolumeBackupPolicyAssignment) ToVolumeBackupPolicyAssignmentOutputWithContext(ctx context.Context) VolumeBackupPolicyAssignmentOutput {
	return pulumi.ToOutputWithContext(ctx, i).(VolumeBackupPolicyAssignmentOutput)
}

// VolumeBackupPolicyAssignmentArrayInput is an input type that accepts VolumeBackupPolicyAssignmentArray and VolumeBackupPolicyAssignmentArrayOutput values.
// You can construct a concrete instance of `VolumeBackupPolicyAssignmentArrayInput` via:
//
//	VolumeBackupPolicyAssignmentArray{ VolumeBackupPolicyAssignmentArgs{...} }
type VolumeBackupPolicyAssignmentArrayInput interface {
	pulumi.Input

	ToVolumeBackupPolicyAssignmentArrayOutput() VolumeBackupPolicyAssignmentArrayOutput
	ToVolumeBackupPolicyAssignmentArrayOutputWithContext(context.Context) VolumeBackupPolicyAssignmentArrayOutput
}

type VolumeBackupPolicyAssignmentArray []VolumeBackupPolicyAssignmentInput

func (VolumeBackupPolicyAssignmentArray) ElementType() reflect.Type {
	return reflect.TypeOf((*[]*VolumeBackupPolicyAssignment)(nil)).Elem()
}

func (i VolumeBackupPolicyAssignmentArray) ToVolumeBackupPolicyAssignmentArrayOutput() VolumeBackupPolicyAssignmentArrayOutput {
	return i.ToVolumeBackupPolicyAssignmentArrayOutputWithContext(context.Background())
}

func (i VolumeBackupPolicyAssignmentArray) ToVolumeBackupPolicyAssignmentArrayOutputWithContext(ctx context.Context) VolumeBackupPolicyAssignmentArrayOutput {
	return pulumi.ToOutputWithContext(ctx, i).(VolumeBackupPolicyAssignmentArrayOutput)
}

// VolumeBackupPolicyAssignmentMapInput is an input type that accepts VolumeBackupPolicyAssignmentMap and VolumeBackupPolicyAssignmentMapOutput values.
// You can construct a concrete instance of `VolumeBackupPolicyAssignmentMapInput` via:
//
//	VolumeBackupPolicyAssignmentMap{ "key": VolumeBackupPolicyAssignmentArgs{...} }
type VolumeBackupPolicyAssignmentMapInput interface {
	pulumi.Input

	ToVolumeBackupPolicyAssignmentMapOutput() VolumeBackupPolicyAssignmentMapOutput
	ToVolumeBackupPolicyAssignmentMapOutputWithContext(context.Context) VolumeBackupPolicyAssignmentMapOutput
}

type VolumeBackupPolicyAssignmentMap map[string]VolumeBackupPolicyAssignmentInput

func (VolumeBackupPolicyAssignmentMap) ElementType() reflect.Type {
	return reflect.TypeOf((*map[string]*VolumeBackupPolicyAssignment)(nil)).Elem()
}

func (i VolumeBackupPolicyAssignmentMap) ToVolumeBackupPolicyAssignmentMapOutput() VolumeBackupPolicyAssignmentMapOutput {
	return i.ToVolumeBackupPolicyAssignmentMapOutputWithContext(context.Background())
}

func (i VolumeBackupPolicyAssignmentMap) ToVolumeBackupPolicyAssignmentMapOutputWithContext(ctx context.Context) VolumeBackupPolicyAssignmentMapOutput {
	return pulumi.ToOutputWithContext(ctx, i).(VolumeBackupPolicyAssignmentMapOutput)
}

type VolumeBackupPolicyAssignmentOutput struct{ *pulumi.OutputState }

func (VolumeBackupPolicyAssignmentOutput) ElementType() reflect.Type {
	return reflect.TypeOf((**VolumeBackupPolicyAssignment)(nil)).Elem()
}

func (o VolumeBackupPolicyAssignmentOutput) ToVolumeBackupPolicyAssignmentOutput() VolumeBackupPolicyAssignmentOutput {
	return o
}

func (o VolumeBackupPolicyAssignmentOutput) ToVolumeBackupPolicyAssignmentOutputWithContext(ctx context.Context) VolumeBackupPolicyAssignmentOutput {
	return o
}

// The OCID of the volume or volume group to assign the policy to.
func (o VolumeBackupPolicyAssignmentOutput) AssetId() pulumi.StringOutput {
	return o.ApplyT(func(v *VolumeBackupPolicyAssignment) pulumi.StringOutput { return v.AssetId }).(pulumi.StringOutput)
}

// The OCID of the volume backup policy to assign to the volume.
func (o VolumeBackupPolicyAssignmentOutput) PolicyId() pulumi.StringOutput {
	return o.ApplyT(func(v *VolumeBackupPolicyAssignment) pulumi.StringOutput { return v.PolicyId }).(pulumi.StringOutput)
}

// The date and time the volume backup policy was assigned to the volume. The format is defined by [RFC3339](https://tools.ietf.org/html/rfc3339).
func (o VolumeBackupPolicyAssignmentOutput) TimeCreated() pulumi.StringOutput {
	return o.ApplyT(func(v *VolumeBackupPolicyAssignment) pulumi.StringOutput { return v.TimeCreated }).(pulumi.StringOutput)
}

// The OCID of the Vault service key which is the master encryption key for the block / boot volume cross region backups, which will be used in the destination region to encrypt the backup's encryption keys. For more information about the Vault service and encryption keys, see [Overview of Vault service](https://docs.cloud.oracle.com/iaas/Content/KeyManagement/Concepts/keyoverview.htm) and [Using Keys](https://docs.cloud.oracle.com/iaas/Content/KeyManagement/Tasks/usingkeys.htm).
//
// ** IMPORTANT **
// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
func (o VolumeBackupPolicyAssignmentOutput) XrcKmsKeyId() pulumi.StringOutput {
	return o.ApplyT(func(v *VolumeBackupPolicyAssignment) pulumi.StringOutput { return v.XrcKmsKeyId }).(pulumi.StringOutput)
}

type VolumeBackupPolicyAssignmentArrayOutput struct{ *pulumi.OutputState }

func (VolumeBackupPolicyAssignmentArrayOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*[]*VolumeBackupPolicyAssignment)(nil)).Elem()
}

func (o VolumeBackupPolicyAssignmentArrayOutput) ToVolumeBackupPolicyAssignmentArrayOutput() VolumeBackupPolicyAssignmentArrayOutput {
	return o
}

func (o VolumeBackupPolicyAssignmentArrayOutput) ToVolumeBackupPolicyAssignmentArrayOutputWithContext(ctx context.Context) VolumeBackupPolicyAssignmentArrayOutput {
	return o
}

func (o VolumeBackupPolicyAssignmentArrayOutput) Index(i pulumi.IntInput) VolumeBackupPolicyAssignmentOutput {
	return pulumi.All(o, i).ApplyT(func(vs []interface{}) *VolumeBackupPolicyAssignment {
		return vs[0].([]*VolumeBackupPolicyAssignment)[vs[1].(int)]
	}).(VolumeBackupPolicyAssignmentOutput)
}

type VolumeBackupPolicyAssignmentMapOutput struct{ *pulumi.OutputState }

func (VolumeBackupPolicyAssignmentMapOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*map[string]*VolumeBackupPolicyAssignment)(nil)).Elem()
}

func (o VolumeBackupPolicyAssignmentMapOutput) ToVolumeBackupPolicyAssignmentMapOutput() VolumeBackupPolicyAssignmentMapOutput {
	return o
}

func (o VolumeBackupPolicyAssignmentMapOutput) ToVolumeBackupPolicyAssignmentMapOutputWithContext(ctx context.Context) VolumeBackupPolicyAssignmentMapOutput {
	return o
}

func (o VolumeBackupPolicyAssignmentMapOutput) MapIndex(k pulumi.StringInput) VolumeBackupPolicyAssignmentOutput {
	return pulumi.All(o, k).ApplyT(func(vs []interface{}) *VolumeBackupPolicyAssignment {
		return vs[0].(map[string]*VolumeBackupPolicyAssignment)[vs[1].(string)]
	}).(VolumeBackupPolicyAssignmentOutput)
}

func init() {
	pulumi.RegisterInputType(reflect.TypeOf((*VolumeBackupPolicyAssignmentInput)(nil)).Elem(), &VolumeBackupPolicyAssignment{})
	pulumi.RegisterInputType(reflect.TypeOf((*VolumeBackupPolicyAssignmentArrayInput)(nil)).Elem(), VolumeBackupPolicyAssignmentArray{})
	pulumi.RegisterInputType(reflect.TypeOf((*VolumeBackupPolicyAssignmentMapInput)(nil)).Elem(), VolumeBackupPolicyAssignmentMap{})
	pulumi.RegisterOutputType(VolumeBackupPolicyAssignmentOutput{})
	pulumi.RegisterOutputType(VolumeBackupPolicyAssignmentArrayOutput{})
	pulumi.RegisterOutputType(VolumeBackupPolicyAssignmentMapOutput{})
}
