// Code generated by the Pulumi Terraform Bridge (tfgen) Tool DO NOT EDIT.
// *** WARNING: Do not edit by hand unless you're certain you know what you are doing! ***

package osmanagement

import (
	"context"
	"reflect"

	"github.com/pulumi/pulumi-oci/sdk/v2/go/oci/internal"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This data source provides details about a specific Managed Instance Group resource in Oracle Cloud Infrastructure OS Management service.
//
// Returns a specific Managed Instance Group.
//
// ## Example Usage
//
// ```go
// package main
//
// import (
//
//	"github.com/pulumi/pulumi-oci/sdk/v2/go/oci/osmanagement"
//	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
//
// )
//
//	func main() {
//		pulumi.Run(func(ctx *pulumi.Context) error {
//			_, err := osmanagement.GetManagedInstanceGroup(ctx, &osmanagement.GetManagedInstanceGroupArgs{
//				ManagedInstanceGroupId: testManagedInstanceGroupOciOsmanagementManagedInstanceGroup.Id,
//			}, nil)
//			if err != nil {
//				return err
//			}
//			return nil
//		})
//	}
//
// ```
func LookupManagedInstanceGroup(ctx *pulumi.Context, args *LookupManagedInstanceGroupArgs, opts ...pulumi.InvokeOption) (*LookupManagedInstanceGroupResult, error) {
	opts = internal.PkgInvokeDefaultOpts(opts)
	var rv LookupManagedInstanceGroupResult
	err := ctx.Invoke("oci:OsManagement/getManagedInstanceGroup:getManagedInstanceGroup", args, &rv, opts...)
	if err != nil {
		return nil, err
	}
	return &rv, nil
}

// A collection of arguments for invoking getManagedInstanceGroup.
type LookupManagedInstanceGroupArgs struct {
	// OCID for the managed instance group
	ManagedInstanceGroupId string `pulumi:"managedInstanceGroupId"`
}

// A collection of values returned by getManagedInstanceGroup.
type LookupManagedInstanceGroupResult struct {
	// OCID for the Compartment
	CompartmentId string `pulumi:"compartmentId"`
	// Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
	DefinedTags map[string]string `pulumi:"definedTags"`
	// Information specified by the user about the managed instance group
	Description string `pulumi:"description"`
	// User friendly name
	DisplayName string `pulumi:"displayName"`
	// Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
	FreeformTags map[string]string `pulumi:"freeformTags"`
	// unique identifier that is immutable on creation
	Id                     string   `pulumi:"id"`
	ManagedInstanceCount   int      `pulumi:"managedInstanceCount"`
	ManagedInstanceGroupId string   `pulumi:"managedInstanceGroupId"`
	ManagedInstanceIds     []string `pulumi:"managedInstanceIds"`
	// list of Managed Instances in the group
	ManagedInstances []GetManagedInstanceGroupManagedInstance `pulumi:"managedInstances"`
	// The Operating System type of the managed instance.
	OsFamily string `pulumi:"osFamily"`
	// The current state of the Software Source.
	State string `pulumi:"state"`
}

func LookupManagedInstanceGroupOutput(ctx *pulumi.Context, args LookupManagedInstanceGroupOutputArgs, opts ...pulumi.InvokeOption) LookupManagedInstanceGroupResultOutput {
	return pulumi.ToOutputWithContext(ctx.Context(), args).
		ApplyT(func(v interface{}) (LookupManagedInstanceGroupResultOutput, error) {
			args := v.(LookupManagedInstanceGroupArgs)
			options := pulumi.InvokeOutputOptions{InvokeOptions: internal.PkgInvokeDefaultOpts(opts)}
			return ctx.InvokeOutput("oci:OsManagement/getManagedInstanceGroup:getManagedInstanceGroup", args, LookupManagedInstanceGroupResultOutput{}, options).(LookupManagedInstanceGroupResultOutput), nil
		}).(LookupManagedInstanceGroupResultOutput)
}

// A collection of arguments for invoking getManagedInstanceGroup.
type LookupManagedInstanceGroupOutputArgs struct {
	// OCID for the managed instance group
	ManagedInstanceGroupId pulumi.StringInput `pulumi:"managedInstanceGroupId"`
}

func (LookupManagedInstanceGroupOutputArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*LookupManagedInstanceGroupArgs)(nil)).Elem()
}

// A collection of values returned by getManagedInstanceGroup.
type LookupManagedInstanceGroupResultOutput struct{ *pulumi.OutputState }

func (LookupManagedInstanceGroupResultOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*LookupManagedInstanceGroupResult)(nil)).Elem()
}

func (o LookupManagedInstanceGroupResultOutput) ToLookupManagedInstanceGroupResultOutput() LookupManagedInstanceGroupResultOutput {
	return o
}

func (o LookupManagedInstanceGroupResultOutput) ToLookupManagedInstanceGroupResultOutputWithContext(ctx context.Context) LookupManagedInstanceGroupResultOutput {
	return o
}

// OCID for the Compartment
func (o LookupManagedInstanceGroupResultOutput) CompartmentId() pulumi.StringOutput {
	return o.ApplyT(func(v LookupManagedInstanceGroupResult) string { return v.CompartmentId }).(pulumi.StringOutput)
}

// Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
func (o LookupManagedInstanceGroupResultOutput) DefinedTags() pulumi.StringMapOutput {
	return o.ApplyT(func(v LookupManagedInstanceGroupResult) map[string]string { return v.DefinedTags }).(pulumi.StringMapOutput)
}

// Information specified by the user about the managed instance group
func (o LookupManagedInstanceGroupResultOutput) Description() pulumi.StringOutput {
	return o.ApplyT(func(v LookupManagedInstanceGroupResult) string { return v.Description }).(pulumi.StringOutput)
}

// User friendly name
func (o LookupManagedInstanceGroupResultOutput) DisplayName() pulumi.StringOutput {
	return o.ApplyT(func(v LookupManagedInstanceGroupResult) string { return v.DisplayName }).(pulumi.StringOutput)
}

// Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
func (o LookupManagedInstanceGroupResultOutput) FreeformTags() pulumi.StringMapOutput {
	return o.ApplyT(func(v LookupManagedInstanceGroupResult) map[string]string { return v.FreeformTags }).(pulumi.StringMapOutput)
}

// unique identifier that is immutable on creation
func (o LookupManagedInstanceGroupResultOutput) Id() pulumi.StringOutput {
	return o.ApplyT(func(v LookupManagedInstanceGroupResult) string { return v.Id }).(pulumi.StringOutput)
}

func (o LookupManagedInstanceGroupResultOutput) ManagedInstanceCount() pulumi.IntOutput {
	return o.ApplyT(func(v LookupManagedInstanceGroupResult) int { return v.ManagedInstanceCount }).(pulumi.IntOutput)
}

func (o LookupManagedInstanceGroupResultOutput) ManagedInstanceGroupId() pulumi.StringOutput {
	return o.ApplyT(func(v LookupManagedInstanceGroupResult) string { return v.ManagedInstanceGroupId }).(pulumi.StringOutput)
}

func (o LookupManagedInstanceGroupResultOutput) ManagedInstanceIds() pulumi.StringArrayOutput {
	return o.ApplyT(func(v LookupManagedInstanceGroupResult) []string { return v.ManagedInstanceIds }).(pulumi.StringArrayOutput)
}

// list of Managed Instances in the group
func (o LookupManagedInstanceGroupResultOutput) ManagedInstances() GetManagedInstanceGroupManagedInstanceArrayOutput {
	return o.ApplyT(func(v LookupManagedInstanceGroupResult) []GetManagedInstanceGroupManagedInstance {
		return v.ManagedInstances
	}).(GetManagedInstanceGroupManagedInstanceArrayOutput)
}

// The Operating System type of the managed instance.
func (o LookupManagedInstanceGroupResultOutput) OsFamily() pulumi.StringOutput {
	return o.ApplyT(func(v LookupManagedInstanceGroupResult) string { return v.OsFamily }).(pulumi.StringOutput)
}

// The current state of the Software Source.
func (o LookupManagedInstanceGroupResultOutput) State() pulumi.StringOutput {
	return o.ApplyT(func(v LookupManagedInstanceGroupResult) string { return v.State }).(pulumi.StringOutput)
}

func init() {
	pulumi.RegisterOutputType(LookupManagedInstanceGroupResultOutput{})
}
