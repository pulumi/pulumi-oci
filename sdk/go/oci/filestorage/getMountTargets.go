// Code generated by the Pulumi Terraform Bridge (tfgen) Tool DO NOT EDIT.
// *** WARNING: Do not edit by hand unless you're certain you know what you are doing! ***

package filestorage

import (
	"context"
	"reflect"

	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This data source provides the list of Mount Targets in Oracle Cloud Infrastructure File Storage service.
//
// Lists the mount target resources in the specified compartment.
//
// ## Example Usage
//
// ```go
// package main
//
// import (
//
//	"github.com/pulumi/pulumi-oci/sdk/go/oci/FileStorage"
//	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
//
// )
//
//	func main() {
//		pulumi.Run(func(ctx *pulumi.Context) error {
//			_, err := FileStorage.GetMountTargets(ctx, &filestorage.GetMountTargetsArgs{
//				AvailabilityDomain: _var.Mount_target_availability_domain,
//				CompartmentId:      _var.Compartment_id,
//				DisplayName:        pulumi.StringRef(_var.Mount_target_display_name),
//				ExportSetId:        pulumi.StringRef(oci_file_storage_export_set.Test_export_set.Id),
//				Id:                 pulumi.StringRef(_var.Mount_target_id),
//				State:              pulumi.StringRef(_var.Mount_target_state),
//			}, nil)
//			if err != nil {
//				return err
//			}
//			return nil
//		})
//	}
//
// ```
func GetMountTargets(ctx *pulumi.Context, args *GetMountTargetsArgs, opts ...pulumi.InvokeOption) (*GetMountTargetsResult, error) {
	var rv GetMountTargetsResult
	err := ctx.Invoke("oci:FileStorage/getMountTargets:getMountTargets", args, &rv, opts...)
	if err != nil {
		return nil, err
	}
	return &rv, nil
}

// A collection of arguments for invoking getMountTargets.
type GetMountTargetsArgs struct {
	// The name of the availability domain.  Example: `Uocm:PHX-AD-1`
	AvailabilityDomain string `pulumi:"availabilityDomain"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
	CompartmentId string `pulumi:"compartmentId"`
	// A user-friendly name. It does not have to be unique, and it is changeable.  Example: `My resource`
	DisplayName *string `pulumi:"displayName"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the export set.
	ExportSetId *string                 `pulumi:"exportSetId"`
	Filters     []GetMountTargetsFilter `pulumi:"filters"`
	// Filter results by [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm). Must be an OCID of the correct type for the resouce type.
	Id *string `pulumi:"id"`
	// Filter results by the specified lifecycle state. Must be a valid state for the resource type.
	State *string `pulumi:"state"`
}

// A collection of values returned by getMountTargets.
type GetMountTargetsResult struct {
	// The availability domain the mount target is in. May be unset as a blank or NULL value.  Example: `Uocm:PHX-AD-1`
	AvailabilityDomain string `pulumi:"availabilityDomain"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment that contains the mount target.
	CompartmentId string `pulumi:"compartmentId"`
	// A user-friendly name. It does not have to be unique, and it is changeable. Avoid entering confidential information.  Example: `My mount target`
	DisplayName *string `pulumi:"displayName"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the associated export set. Controls what file systems will be exported through Network File System (NFS) protocol on this mount target.
	ExportSetId *string                 `pulumi:"exportSetId"`
	Filters     []GetMountTargetsFilter `pulumi:"filters"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the mount target.
	Id *string `pulumi:"id"`
	// The list of mount_targets.
	MountTargets []GetMountTargetsMountTarget `pulumi:"mountTargets"`
	// The current state of the mount target.
	State *string `pulumi:"state"`
}

func GetMountTargetsOutput(ctx *pulumi.Context, args GetMountTargetsOutputArgs, opts ...pulumi.InvokeOption) GetMountTargetsResultOutput {
	return pulumi.ToOutputWithContext(context.Background(), args).
		ApplyT(func(v interface{}) (GetMountTargetsResult, error) {
			args := v.(GetMountTargetsArgs)
			r, err := GetMountTargets(ctx, &args, opts...)
			var s GetMountTargetsResult
			if r != nil {
				s = *r
			}
			return s, err
		}).(GetMountTargetsResultOutput)
}

// A collection of arguments for invoking getMountTargets.
type GetMountTargetsOutputArgs struct {
	// The name of the availability domain.  Example: `Uocm:PHX-AD-1`
	AvailabilityDomain pulumi.StringInput `pulumi:"availabilityDomain"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
	CompartmentId pulumi.StringInput `pulumi:"compartmentId"`
	// A user-friendly name. It does not have to be unique, and it is changeable.  Example: `My resource`
	DisplayName pulumi.StringPtrInput `pulumi:"displayName"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the export set.
	ExportSetId pulumi.StringPtrInput           `pulumi:"exportSetId"`
	Filters     GetMountTargetsFilterArrayInput `pulumi:"filters"`
	// Filter results by [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm). Must be an OCID of the correct type for the resouce type.
	Id pulumi.StringPtrInput `pulumi:"id"`
	// Filter results by the specified lifecycle state. Must be a valid state for the resource type.
	State pulumi.StringPtrInput `pulumi:"state"`
}

func (GetMountTargetsOutputArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*GetMountTargetsArgs)(nil)).Elem()
}

// A collection of values returned by getMountTargets.
type GetMountTargetsResultOutput struct{ *pulumi.OutputState }

func (GetMountTargetsResultOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*GetMountTargetsResult)(nil)).Elem()
}

func (o GetMountTargetsResultOutput) ToGetMountTargetsResultOutput() GetMountTargetsResultOutput {
	return o
}

func (o GetMountTargetsResultOutput) ToGetMountTargetsResultOutputWithContext(ctx context.Context) GetMountTargetsResultOutput {
	return o
}

// The availability domain the mount target is in. May be unset as a blank or NULL value.  Example: `Uocm:PHX-AD-1`
func (o GetMountTargetsResultOutput) AvailabilityDomain() pulumi.StringOutput {
	return o.ApplyT(func(v GetMountTargetsResult) string { return v.AvailabilityDomain }).(pulumi.StringOutput)
}

// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment that contains the mount target.
func (o GetMountTargetsResultOutput) CompartmentId() pulumi.StringOutput {
	return o.ApplyT(func(v GetMountTargetsResult) string { return v.CompartmentId }).(pulumi.StringOutput)
}

// A user-friendly name. It does not have to be unique, and it is changeable. Avoid entering confidential information.  Example: `My mount target`
func (o GetMountTargetsResultOutput) DisplayName() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetMountTargetsResult) *string { return v.DisplayName }).(pulumi.StringPtrOutput)
}

// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the associated export set. Controls what file systems will be exported through Network File System (NFS) protocol on this mount target.
func (o GetMountTargetsResultOutput) ExportSetId() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetMountTargetsResult) *string { return v.ExportSetId }).(pulumi.StringPtrOutput)
}

func (o GetMountTargetsResultOutput) Filters() GetMountTargetsFilterArrayOutput {
	return o.ApplyT(func(v GetMountTargetsResult) []GetMountTargetsFilter { return v.Filters }).(GetMountTargetsFilterArrayOutput)
}

// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the mount target.
func (o GetMountTargetsResultOutput) Id() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetMountTargetsResult) *string { return v.Id }).(pulumi.StringPtrOutput)
}

// The list of mount_targets.
func (o GetMountTargetsResultOutput) MountTargets() GetMountTargetsMountTargetArrayOutput {
	return o.ApplyT(func(v GetMountTargetsResult) []GetMountTargetsMountTarget { return v.MountTargets }).(GetMountTargetsMountTargetArrayOutput)
}

// The current state of the mount target.
func (o GetMountTargetsResultOutput) State() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetMountTargetsResult) *string { return v.State }).(pulumi.StringPtrOutput)
}

func init() {
	pulumi.RegisterOutputType(GetMountTargetsResultOutput{})
}