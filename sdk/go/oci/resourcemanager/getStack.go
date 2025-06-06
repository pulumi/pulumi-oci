// Code generated by pulumi-language-go DO NOT EDIT.
// *** WARNING: Do not edit by hand unless you're certain you know what you are doing! ***

package resourcemanager

import (
	"context"
	"reflect"

	"github.com/pulumi/pulumi-oci/sdk/v3/go/oci/internal"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This data source provides details about a specific Stack resource in Oracle Cloud Infrastructure Resource Manager service.
//
// Gets a stack using the stack ID.
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
//			_, err := resourcemanager.GetStack(ctx, &resourcemanager.GetStackArgs{
//				StackId: testStackOciResourcemanagerStack.Id,
//			}, nil)
//			if err != nil {
//				return err
//			}
//			return nil
//		})
//	}
//
// ```
func GetStack(ctx *pulumi.Context, args *GetStackArgs, opts ...pulumi.InvokeOption) (*GetStackResult, error) {
	opts = internal.PkgInvokeDefaultOpts(opts)
	var rv GetStackResult
	err := ctx.Invoke("oci:ResourceManager/getStack:getStack", args, &rv, opts...)
	if err != nil {
		return nil, err
	}
	return &rv, nil
}

// A collection of arguments for invoking getStack.
type GetStackArgs struct {
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the stack.
	StackId string `pulumi:"stackId"`
}

// A collection of values returned by getStack.
type GetStackResult struct {
	// Unique identifier ([OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm)) for the compartment where the stack is located.
	CompartmentId string                 `pulumi:"compartmentId"`
	ConfigSources []GetStackConfigSource `pulumi:"configSources"`
	// Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Operations.CostCenter": "42"}`
	DefinedTags map[string]string `pulumi:"definedTags"`
	// General description of the stack.
	Description string `pulumi:"description"`
	// Human-readable display name for the stack.
	DisplayName string `pulumi:"displayName"`
	// Free-form tags associated with this resource. Each tag is a key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Department": "Finance"}`
	FreeformTags map[string]string `pulumi:"freeformTags"`
	// The provider-assigned unique ID for this managed resource.
	Id      string `pulumi:"id"`
	StackId string `pulumi:"stackId"`
	// The current lifecycle state of the stack.
	State string `pulumi:"state"`
	// The date and time at which the stack was created.
	TimeCreated string            `pulumi:"timeCreated"`
	Variables   map[string]string `pulumi:"variables"`
}

func GetStackOutput(ctx *pulumi.Context, args GetStackOutputArgs, opts ...pulumi.InvokeOption) GetStackResultOutput {
	return pulumi.ToOutputWithContext(ctx.Context(), args).
		ApplyT(func(v interface{}) (GetStackResultOutput, error) {
			args := v.(GetStackArgs)
			options := pulumi.InvokeOutputOptions{InvokeOptions: internal.PkgInvokeDefaultOpts(opts)}
			return ctx.InvokeOutput("oci:ResourceManager/getStack:getStack", args, GetStackResultOutput{}, options).(GetStackResultOutput), nil
		}).(GetStackResultOutput)
}

// A collection of arguments for invoking getStack.
type GetStackOutputArgs struct {
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the stack.
	StackId pulumi.StringInput `pulumi:"stackId"`
}

func (GetStackOutputArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*GetStackArgs)(nil)).Elem()
}

// A collection of values returned by getStack.
type GetStackResultOutput struct{ *pulumi.OutputState }

func (GetStackResultOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*GetStackResult)(nil)).Elem()
}

func (o GetStackResultOutput) ToGetStackResultOutput() GetStackResultOutput {
	return o
}

func (o GetStackResultOutput) ToGetStackResultOutputWithContext(ctx context.Context) GetStackResultOutput {
	return o
}

// Unique identifier ([OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm)) for the compartment where the stack is located.
func (o GetStackResultOutput) CompartmentId() pulumi.StringOutput {
	return o.ApplyT(func(v GetStackResult) string { return v.CompartmentId }).(pulumi.StringOutput)
}

func (o GetStackResultOutput) ConfigSources() GetStackConfigSourceArrayOutput {
	return o.ApplyT(func(v GetStackResult) []GetStackConfigSource { return v.ConfigSources }).(GetStackConfigSourceArrayOutput)
}

// Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Operations.CostCenter": "42"}`
func (o GetStackResultOutput) DefinedTags() pulumi.StringMapOutput {
	return o.ApplyT(func(v GetStackResult) map[string]string { return v.DefinedTags }).(pulumi.StringMapOutput)
}

// General description of the stack.
func (o GetStackResultOutput) Description() pulumi.StringOutput {
	return o.ApplyT(func(v GetStackResult) string { return v.Description }).(pulumi.StringOutput)
}

// Human-readable display name for the stack.
func (o GetStackResultOutput) DisplayName() pulumi.StringOutput {
	return o.ApplyT(func(v GetStackResult) string { return v.DisplayName }).(pulumi.StringOutput)
}

// Free-form tags associated with this resource. Each tag is a key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Department": "Finance"}`
func (o GetStackResultOutput) FreeformTags() pulumi.StringMapOutput {
	return o.ApplyT(func(v GetStackResult) map[string]string { return v.FreeformTags }).(pulumi.StringMapOutput)
}

// The provider-assigned unique ID for this managed resource.
func (o GetStackResultOutput) Id() pulumi.StringOutput {
	return o.ApplyT(func(v GetStackResult) string { return v.Id }).(pulumi.StringOutput)
}

func (o GetStackResultOutput) StackId() pulumi.StringOutput {
	return o.ApplyT(func(v GetStackResult) string { return v.StackId }).(pulumi.StringOutput)
}

// The current lifecycle state of the stack.
func (o GetStackResultOutput) State() pulumi.StringOutput {
	return o.ApplyT(func(v GetStackResult) string { return v.State }).(pulumi.StringOutput)
}

// The date and time at which the stack was created.
func (o GetStackResultOutput) TimeCreated() pulumi.StringOutput {
	return o.ApplyT(func(v GetStackResult) string { return v.TimeCreated }).(pulumi.StringOutput)
}

func (o GetStackResultOutput) Variables() pulumi.StringMapOutput {
	return o.ApplyT(func(v GetStackResult) map[string]string { return v.Variables }).(pulumi.StringMapOutput)
}

func init() {
	pulumi.RegisterOutputType(GetStackResultOutput{})
}
