// Code generated by the Pulumi Terraform Bridge (tfgen) Tool DO NOT EDIT.
// *** WARNING: Do not edit by hand unless you're certain you know what you are doing! ***

package filestorage

import (
	"context"
	"reflect"

	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This data source provides the list of Filesystem Snapshot Policies in Oracle Cloud Infrastructure File Storage service.
//
// Lists file system snapshot policies in the specified compartment.
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
//			_, err := FileStorage.GetFilesystemSnapshotPolicies(ctx, &filestorage.GetFilesystemSnapshotPoliciesArgs{
//				AvailabilityDomain: _var.Filesystem_snapshot_policy_availability_domain,
//				CompartmentId:      _var.Compartment_id,
//				DisplayName:        pulumi.StringRef(_var.Filesystem_snapshot_policy_display_name),
//				Id:                 pulumi.StringRef(_var.Filesystem_snapshot_policy_id),
//				State:              pulumi.StringRef(_var.Filesystem_snapshot_policy_state),
//			}, nil)
//			if err != nil {
//				return err
//			}
//			return nil
//		})
//	}
//
// ```
func GetFilesystemSnapshotPolicies(ctx *pulumi.Context, args *GetFilesystemSnapshotPoliciesArgs, opts ...pulumi.InvokeOption) (*GetFilesystemSnapshotPoliciesResult, error) {
	var rv GetFilesystemSnapshotPoliciesResult
	err := ctx.Invoke("oci:FileStorage/getFilesystemSnapshotPolicies:getFilesystemSnapshotPolicies", args, &rv, opts...)
	if err != nil {
		return nil, err
	}
	return &rv, nil
}

// A collection of arguments for invoking getFilesystemSnapshotPolicies.
type GetFilesystemSnapshotPoliciesArgs struct {
	// The name of the availability domain.  Example: `Uocm:PHX-AD-1`
	AvailabilityDomain string `pulumi:"availabilityDomain"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
	CompartmentId string `pulumi:"compartmentId"`
	// A user-friendly name. It does not have to be unique, and it is changeable.  Example: `My resource`
	DisplayName *string                               `pulumi:"displayName"`
	Filters     []GetFilesystemSnapshotPoliciesFilter `pulumi:"filters"`
	// Filter results by [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm). Must be an OCID of the correct type for the resouce type.
	Id *string `pulumi:"id"`
	// Filter results by the specified lifecycle state. Must be a valid state for the resource type.
	State *string `pulumi:"state"`
}

// A collection of values returned by getFilesystemSnapshotPolicies.
type GetFilesystemSnapshotPoliciesResult struct {
	// The availability domain that the file system snapshot policy is in. May be unset using a blank or NULL value.  Example: `Uocm:PHX-AD-2`
	AvailabilityDomain string `pulumi:"availabilityDomain"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment that contains the file system snapshot policy.
	CompartmentId string `pulumi:"compartmentId"`
	// A user-friendly name. It does not have to be unique, and it is changeable. Avoid entering confidential information.  Example: `My Filesystem Snapshot Policy`
	DisplayName *string `pulumi:"displayName"`
	// The list of filesystem_snapshot_policies.
	FilesystemSnapshotPolicies []GetFilesystemSnapshotPoliciesFilesystemSnapshotPolicy `pulumi:"filesystemSnapshotPolicies"`
	Filters                    []GetFilesystemSnapshotPoliciesFilter                   `pulumi:"filters"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the file system snapshot policy.
	Id *string `pulumi:"id"`
	// The current state of this file system snapshot policy.
	State *string `pulumi:"state"`
}

func GetFilesystemSnapshotPoliciesOutput(ctx *pulumi.Context, args GetFilesystemSnapshotPoliciesOutputArgs, opts ...pulumi.InvokeOption) GetFilesystemSnapshotPoliciesResultOutput {
	return pulumi.ToOutputWithContext(context.Background(), args).
		ApplyT(func(v interface{}) (GetFilesystemSnapshotPoliciesResult, error) {
			args := v.(GetFilesystemSnapshotPoliciesArgs)
			r, err := GetFilesystemSnapshotPolicies(ctx, &args, opts...)
			var s GetFilesystemSnapshotPoliciesResult
			if r != nil {
				s = *r
			}
			return s, err
		}).(GetFilesystemSnapshotPoliciesResultOutput)
}

// A collection of arguments for invoking getFilesystemSnapshotPolicies.
type GetFilesystemSnapshotPoliciesOutputArgs struct {
	// The name of the availability domain.  Example: `Uocm:PHX-AD-1`
	AvailabilityDomain pulumi.StringInput `pulumi:"availabilityDomain"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
	CompartmentId pulumi.StringInput `pulumi:"compartmentId"`
	// A user-friendly name. It does not have to be unique, and it is changeable.  Example: `My resource`
	DisplayName pulumi.StringPtrInput                         `pulumi:"displayName"`
	Filters     GetFilesystemSnapshotPoliciesFilterArrayInput `pulumi:"filters"`
	// Filter results by [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm). Must be an OCID of the correct type for the resouce type.
	Id pulumi.StringPtrInput `pulumi:"id"`
	// Filter results by the specified lifecycle state. Must be a valid state for the resource type.
	State pulumi.StringPtrInput `pulumi:"state"`
}

func (GetFilesystemSnapshotPoliciesOutputArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*GetFilesystemSnapshotPoliciesArgs)(nil)).Elem()
}

// A collection of values returned by getFilesystemSnapshotPolicies.
type GetFilesystemSnapshotPoliciesResultOutput struct{ *pulumi.OutputState }

func (GetFilesystemSnapshotPoliciesResultOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*GetFilesystemSnapshotPoliciesResult)(nil)).Elem()
}

func (o GetFilesystemSnapshotPoliciesResultOutput) ToGetFilesystemSnapshotPoliciesResultOutput() GetFilesystemSnapshotPoliciesResultOutput {
	return o
}

func (o GetFilesystemSnapshotPoliciesResultOutput) ToGetFilesystemSnapshotPoliciesResultOutputWithContext(ctx context.Context) GetFilesystemSnapshotPoliciesResultOutput {
	return o
}

// The availability domain that the file system snapshot policy is in. May be unset using a blank or NULL value.  Example: `Uocm:PHX-AD-2`
func (o GetFilesystemSnapshotPoliciesResultOutput) AvailabilityDomain() pulumi.StringOutput {
	return o.ApplyT(func(v GetFilesystemSnapshotPoliciesResult) string { return v.AvailabilityDomain }).(pulumi.StringOutput)
}

// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment that contains the file system snapshot policy.
func (o GetFilesystemSnapshotPoliciesResultOutput) CompartmentId() pulumi.StringOutput {
	return o.ApplyT(func(v GetFilesystemSnapshotPoliciesResult) string { return v.CompartmentId }).(pulumi.StringOutput)
}

// A user-friendly name. It does not have to be unique, and it is changeable. Avoid entering confidential information.  Example: `My Filesystem Snapshot Policy`
func (o GetFilesystemSnapshotPoliciesResultOutput) DisplayName() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetFilesystemSnapshotPoliciesResult) *string { return v.DisplayName }).(pulumi.StringPtrOutput)
}

// The list of filesystem_snapshot_policies.
func (o GetFilesystemSnapshotPoliciesResultOutput) FilesystemSnapshotPolicies() GetFilesystemSnapshotPoliciesFilesystemSnapshotPolicyArrayOutput {
	return o.ApplyT(func(v GetFilesystemSnapshotPoliciesResult) []GetFilesystemSnapshotPoliciesFilesystemSnapshotPolicy {
		return v.FilesystemSnapshotPolicies
	}).(GetFilesystemSnapshotPoliciesFilesystemSnapshotPolicyArrayOutput)
}

func (o GetFilesystemSnapshotPoliciesResultOutput) Filters() GetFilesystemSnapshotPoliciesFilterArrayOutput {
	return o.ApplyT(func(v GetFilesystemSnapshotPoliciesResult) []GetFilesystemSnapshotPoliciesFilter { return v.Filters }).(GetFilesystemSnapshotPoliciesFilterArrayOutput)
}

// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the file system snapshot policy.
func (o GetFilesystemSnapshotPoliciesResultOutput) Id() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetFilesystemSnapshotPoliciesResult) *string { return v.Id }).(pulumi.StringPtrOutput)
}

// The current state of this file system snapshot policy.
func (o GetFilesystemSnapshotPoliciesResultOutput) State() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetFilesystemSnapshotPoliciesResult) *string { return v.State }).(pulumi.StringPtrOutput)
}

func init() {
	pulumi.RegisterOutputType(GetFilesystemSnapshotPoliciesResultOutput{})
}