// Code generated by pulumi-language-go DO NOT EDIT.
// *** WARNING: Do not edit by hand unless you're certain you know what you are doing! ***

package resourcemanager

import (
	"context"
	"reflect"

	"github.com/pulumi/pulumi-oci/sdk/v3/go/oci/internal"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This data source provides the list of Stacks in Oracle Cloud Infrastructure Resource Manager service.
//
// Returns a list of stacks.
// - If called using the compartment ID, returns all stacks in the specified compartment.
// - If called using the stack ID, returns the specified stack.
//
// ## Example Usage
//
// ```go
// package main
//
// import (
//
//	"github.com/pulumi/pulumi-oci/sdk/v3/go/oci/resourcemanager"
//	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
//
// )
//
//	func main() {
//		pulumi.Run(func(ctx *pulumi.Context) error {
//			_, err := resourcemanager.GetStacks(ctx, &resourcemanager.GetStacksArgs{
//				CompartmentId: compartmentId,
//				DisplayName:   pulumi.StringRef(stackDisplayName),
//				Id:            pulumi.StringRef(stackId),
//				State:         pulumi.StringRef(stackState),
//			}, nil)
//			if err != nil {
//				return err
//			}
//			return nil
//		})
//	}
//
// ```
func GetStacks(ctx *pulumi.Context, args *GetStacksArgs, opts ...pulumi.InvokeOption) (*GetStacksResult, error) {
	opts = internal.PkgInvokeDefaultOpts(opts)
	var rv GetStacksResult
	err := ctx.Invoke("oci:ResourceManager/getStacks:getStacks", args, &rv, opts...)
	if err != nil {
		return nil, err
	}
	return &rv, nil
}

// A collection of arguments for invoking getStacks.
type GetStacksArgs struct {
	// The compartment [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) on which to filter.
	CompartmentId string `pulumi:"compartmentId"`
	// Display name on which to query.
	DisplayName *string           `pulumi:"displayName"`
	Filters     []GetStacksFilter `pulumi:"filters"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) on which to query for a stack.
	Id *string `pulumi:"id"`
	// A filter that returns only those resources that match the specified lifecycle state. The state value is case-insensitive.
	//
	// Allowable values:
	// * CREATING
	// * ACTIVE
	// * DELETING
	// * DELETED
	State *string `pulumi:"state"`
}

// A collection of values returned by getStacks.
type GetStacksResult struct {
	// Unique identifier ([OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm)) for the compartment where the stack is located.
	CompartmentId string `pulumi:"compartmentId"`
	// Human-readable display name for the stack.
	DisplayName *string           `pulumi:"displayName"`
	Filters     []GetStacksFilter `pulumi:"filters"`
	// Unique identifier ([OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm)) for the stack.
	Id *string `pulumi:"id"`
	// The list of stacks.
	Stacks []GetStacksStack `pulumi:"stacks"`
	// The current lifecycle state of the stack.
	State *string `pulumi:"state"`
}

func GetStacksOutput(ctx *pulumi.Context, args GetStacksOutputArgs, opts ...pulumi.InvokeOption) GetStacksResultOutput {
	return pulumi.ToOutputWithContext(ctx.Context(), args).
		ApplyT(func(v interface{}) (GetStacksResultOutput, error) {
			args := v.(GetStacksArgs)
			options := pulumi.InvokeOutputOptions{InvokeOptions: internal.PkgInvokeDefaultOpts(opts)}
			return ctx.InvokeOutput("oci:ResourceManager/getStacks:getStacks", args, GetStacksResultOutput{}, options).(GetStacksResultOutput), nil
		}).(GetStacksResultOutput)
}

// A collection of arguments for invoking getStacks.
type GetStacksOutputArgs struct {
	// The compartment [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) on which to filter.
	CompartmentId pulumi.StringInput `pulumi:"compartmentId"`
	// Display name on which to query.
	DisplayName pulumi.StringPtrInput     `pulumi:"displayName"`
	Filters     GetStacksFilterArrayInput `pulumi:"filters"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) on which to query for a stack.
	Id pulumi.StringPtrInput `pulumi:"id"`
	// A filter that returns only those resources that match the specified lifecycle state. The state value is case-insensitive.
	//
	// Allowable values:
	// * CREATING
	// * ACTIVE
	// * DELETING
	// * DELETED
	State pulumi.StringPtrInput `pulumi:"state"`
}

func (GetStacksOutputArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*GetStacksArgs)(nil)).Elem()
}

// A collection of values returned by getStacks.
type GetStacksResultOutput struct{ *pulumi.OutputState }

func (GetStacksResultOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*GetStacksResult)(nil)).Elem()
}

func (o GetStacksResultOutput) ToGetStacksResultOutput() GetStacksResultOutput {
	return o
}

func (o GetStacksResultOutput) ToGetStacksResultOutputWithContext(ctx context.Context) GetStacksResultOutput {
	return o
}

// Unique identifier ([OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm)) for the compartment where the stack is located.
func (o GetStacksResultOutput) CompartmentId() pulumi.StringOutput {
	return o.ApplyT(func(v GetStacksResult) string { return v.CompartmentId }).(pulumi.StringOutput)
}

// Human-readable display name for the stack.
func (o GetStacksResultOutput) DisplayName() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetStacksResult) *string { return v.DisplayName }).(pulumi.StringPtrOutput)
}

func (o GetStacksResultOutput) Filters() GetStacksFilterArrayOutput {
	return o.ApplyT(func(v GetStacksResult) []GetStacksFilter { return v.Filters }).(GetStacksFilterArrayOutput)
}

// Unique identifier ([OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm)) for the stack.
func (o GetStacksResultOutput) Id() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetStacksResult) *string { return v.Id }).(pulumi.StringPtrOutput)
}

// The list of stacks.
func (o GetStacksResultOutput) Stacks() GetStacksStackArrayOutput {
	return o.ApplyT(func(v GetStacksResult) []GetStacksStack { return v.Stacks }).(GetStacksStackArrayOutput)
}

// The current lifecycle state of the stack.
func (o GetStacksResultOutput) State() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetStacksResult) *string { return v.State }).(pulumi.StringPtrOutput)
}

func init() {
	pulumi.RegisterOutputType(GetStacksResultOutput{})
}
