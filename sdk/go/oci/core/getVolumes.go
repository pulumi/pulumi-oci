// Code generated by the Pulumi Terraform Bridge (tfgen) Tool DO NOT EDIT.
// *** WARNING: Do not edit by hand unless you're certain you know what you are doing! ***

package core

import (
	"context"
	"reflect"

	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This data source provides the list of Volumes in Oracle Cloud Infrastructure Core service.
//
// Lists the volumes in the specified compartment and availability domain.
//
// ## Example Usage
//
// ```go
// package main
//
// import (
//
//	"github.com/pulumi/pulumi-oci/sdk/go/oci/Core"
//	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
//
// )
//
//	func main() {
//		pulumi.Run(func(ctx *pulumi.Context) error {
//			_, err := Core.GetVolumes(ctx, &core.GetVolumesArgs{
//				AvailabilityDomain: pulumi.StringRef(_var.Volume_availability_domain),
//				CompartmentId:      pulumi.StringRef(_var.Compartment_id),
//				DisplayName:        pulumi.StringRef(_var.Volume_display_name),
//				State:              pulumi.StringRef(_var.Volume_state),
//				VolumeGroupId:      pulumi.StringRef(oci_core_volume_group.Test_volume_group.Id),
//			}, nil)
//			if err != nil {
//				return err
//			}
//			return nil
//		})
//	}
//
// ```
func GetVolumes(ctx *pulumi.Context, args *GetVolumesArgs, opts ...pulumi.InvokeOption) (*GetVolumesResult, error) {
	var rv GetVolumesResult
	err := ctx.Invoke("oci:Core/getVolumes:getVolumes", args, &rv, opts...)
	if err != nil {
		return nil, err
	}
	return &rv, nil
}

// A collection of arguments for invoking getVolumes.
type GetVolumesArgs struct {
	// The name of the availability domain.  Example: `Uocm:PHX-AD-1`
	AvailabilityDomain *string `pulumi:"availabilityDomain"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
	CompartmentId *string `pulumi:"compartmentId"`
	// A filter to return only resources that match the given display name exactly.
	DisplayName *string            `pulumi:"displayName"`
	Filters     []GetVolumesFilter `pulumi:"filters"`
	// A filter to only return resources that match the given lifecycle state. The state value is case-insensitive.
	State *string `pulumi:"state"`
	// The OCID of the volume group.
	VolumeGroupId *string `pulumi:"volumeGroupId"`
}

// A collection of values returned by getVolumes.
type GetVolumesResult struct {
	// The availability domain of the block volume replica.  Example: `Uocm:PHX-AD-1`
	AvailabilityDomain *string `pulumi:"availabilityDomain"`
	// The OCID of the compartment that contains the volume.
	CompartmentId *string `pulumi:"compartmentId"`
	// A user-friendly name. Does not have to be unique, and it's changeable. Avoid entering confidential information.
	DisplayName *string            `pulumi:"displayName"`
	Filters     []GetVolumesFilter `pulumi:"filters"`
	// The provider-assigned unique ID for this managed resource.
	Id string `pulumi:"id"`
	// The current state of a volume.
	State *string `pulumi:"state"`
	// The OCID of the source volume group.
	VolumeGroupId *string `pulumi:"volumeGroupId"`
	// The list of volumes.
	Volumes []GetVolumesVolume `pulumi:"volumes"`
}

func GetVolumesOutput(ctx *pulumi.Context, args GetVolumesOutputArgs, opts ...pulumi.InvokeOption) GetVolumesResultOutput {
	return pulumi.ToOutputWithContext(context.Background(), args).
		ApplyT(func(v interface{}) (GetVolumesResult, error) {
			args := v.(GetVolumesArgs)
			r, err := GetVolumes(ctx, &args, opts...)
			var s GetVolumesResult
			if r != nil {
				s = *r
			}
			return s, err
		}).(GetVolumesResultOutput)
}

// A collection of arguments for invoking getVolumes.
type GetVolumesOutputArgs struct {
	// The name of the availability domain.  Example: `Uocm:PHX-AD-1`
	AvailabilityDomain pulumi.StringPtrInput `pulumi:"availabilityDomain"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
	CompartmentId pulumi.StringPtrInput `pulumi:"compartmentId"`
	// A filter to return only resources that match the given display name exactly.
	DisplayName pulumi.StringPtrInput      `pulumi:"displayName"`
	Filters     GetVolumesFilterArrayInput `pulumi:"filters"`
	// A filter to only return resources that match the given lifecycle state. The state value is case-insensitive.
	State pulumi.StringPtrInput `pulumi:"state"`
	// The OCID of the volume group.
	VolumeGroupId pulumi.StringPtrInput `pulumi:"volumeGroupId"`
}

func (GetVolumesOutputArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*GetVolumesArgs)(nil)).Elem()
}

// A collection of values returned by getVolumes.
type GetVolumesResultOutput struct{ *pulumi.OutputState }

func (GetVolumesResultOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*GetVolumesResult)(nil)).Elem()
}

func (o GetVolumesResultOutput) ToGetVolumesResultOutput() GetVolumesResultOutput {
	return o
}

func (o GetVolumesResultOutput) ToGetVolumesResultOutputWithContext(ctx context.Context) GetVolumesResultOutput {
	return o
}

// The availability domain of the block volume replica.  Example: `Uocm:PHX-AD-1`
func (o GetVolumesResultOutput) AvailabilityDomain() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetVolumesResult) *string { return v.AvailabilityDomain }).(pulumi.StringPtrOutput)
}

// The OCID of the compartment that contains the volume.
func (o GetVolumesResultOutput) CompartmentId() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetVolumesResult) *string { return v.CompartmentId }).(pulumi.StringPtrOutput)
}

// A user-friendly name. Does not have to be unique, and it's changeable. Avoid entering confidential information.
func (o GetVolumesResultOutput) DisplayName() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetVolumesResult) *string { return v.DisplayName }).(pulumi.StringPtrOutput)
}

func (o GetVolumesResultOutput) Filters() GetVolumesFilterArrayOutput {
	return o.ApplyT(func(v GetVolumesResult) []GetVolumesFilter { return v.Filters }).(GetVolumesFilterArrayOutput)
}

// The provider-assigned unique ID for this managed resource.
func (o GetVolumesResultOutput) Id() pulumi.StringOutput {
	return o.ApplyT(func(v GetVolumesResult) string { return v.Id }).(pulumi.StringOutput)
}

// The current state of a volume.
func (o GetVolumesResultOutput) State() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetVolumesResult) *string { return v.State }).(pulumi.StringPtrOutput)
}

// The OCID of the source volume group.
func (o GetVolumesResultOutput) VolumeGroupId() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetVolumesResult) *string { return v.VolumeGroupId }).(pulumi.StringPtrOutput)
}

// The list of volumes.
func (o GetVolumesResultOutput) Volumes() GetVolumesVolumeArrayOutput {
	return o.ApplyT(func(v GetVolumesResult) []GetVolumesVolume { return v.Volumes }).(GetVolumesVolumeArrayOutput)
}

func init() {
	pulumi.RegisterOutputType(GetVolumesResultOutput{})
}