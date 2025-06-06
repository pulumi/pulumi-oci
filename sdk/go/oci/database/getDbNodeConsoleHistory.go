// Code generated by pulumi-language-go DO NOT EDIT.
// *** WARNING: Do not edit by hand unless you're certain you know what you are doing! ***

package database

import (
	"context"
	"reflect"

	"github.com/pulumi/pulumi-oci/sdk/v3/go/oci/internal"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This data source provides details about a specific Db Node Console History resource in Oracle Cloud Infrastructure Database service.
//
// Gets information about the specified database node console history.
//
// ## Example Usage
//
// ```go
// package main
//
// import (
//
//	"github.com/pulumi/pulumi-oci/sdk/v3/go/oci/database"
//	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
//
// )
//
//	func main() {
//		pulumi.Run(func(ctx *pulumi.Context) error {
//			_, err := database.GetDbNodeConsoleHistory(ctx, &database.GetDbNodeConsoleHistoryArgs{
//				ConsoleHistoryId: testConsoleHistory.Id,
//				DbNodeId:         testDbNode.Id,
//			}, nil)
//			if err != nil {
//				return err
//			}
//			return nil
//		})
//	}
//
// ```
func LookupDbNodeConsoleHistory(ctx *pulumi.Context, args *LookupDbNodeConsoleHistoryArgs, opts ...pulumi.InvokeOption) (*LookupDbNodeConsoleHistoryResult, error) {
	opts = internal.PkgInvokeDefaultOpts(opts)
	var rv LookupDbNodeConsoleHistoryResult
	err := ctx.Invoke("oci:Database/getDbNodeConsoleHistory:getDbNodeConsoleHistory", args, &rv, opts...)
	if err != nil {
		return nil, err
	}
	return &rv, nil
}

// A collection of arguments for invoking getDbNodeConsoleHistory.
type LookupDbNodeConsoleHistoryArgs struct {
	// The OCID of the console history.
	ConsoleHistoryId string `pulumi:"consoleHistoryId"`
	// The database node [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
	DbNodeId string `pulumi:"dbNodeId"`
}

// A collection of values returned by getDbNodeConsoleHistory.
type LookupDbNodeConsoleHistoryResult struct {
	// The OCID of the compartment containing the console history.
	CompartmentId    string `pulumi:"compartmentId"`
	ConsoleHistoryId string `pulumi:"consoleHistoryId"`
	// The OCID of the database node.
	DbNodeId string `pulumi:"dbNodeId"`
	// Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).
	DefinedTags map[string]string `pulumi:"definedTags"`
	// The user-friendly name for the console history. The name does not need to be unique.
	DisplayName string `pulumi:"displayName"`
	// Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
	FreeformTags map[string]string `pulumi:"freeformTags"`
	// The OCID of the console history.
	Id string `pulumi:"id"`
	// Additional information about the current lifecycle state.
	LifecycleDetails string `pulumi:"lifecycleDetails"`
	// The current state of the console history.
	State string `pulumi:"state"`
	// The date and time the console history was created.
	TimeCreated string `pulumi:"timeCreated"`
}

func LookupDbNodeConsoleHistoryOutput(ctx *pulumi.Context, args LookupDbNodeConsoleHistoryOutputArgs, opts ...pulumi.InvokeOption) LookupDbNodeConsoleHistoryResultOutput {
	return pulumi.ToOutputWithContext(ctx.Context(), args).
		ApplyT(func(v interface{}) (LookupDbNodeConsoleHistoryResultOutput, error) {
			args := v.(LookupDbNodeConsoleHistoryArgs)
			options := pulumi.InvokeOutputOptions{InvokeOptions: internal.PkgInvokeDefaultOpts(opts)}
			return ctx.InvokeOutput("oci:Database/getDbNodeConsoleHistory:getDbNodeConsoleHistory", args, LookupDbNodeConsoleHistoryResultOutput{}, options).(LookupDbNodeConsoleHistoryResultOutput), nil
		}).(LookupDbNodeConsoleHistoryResultOutput)
}

// A collection of arguments for invoking getDbNodeConsoleHistory.
type LookupDbNodeConsoleHistoryOutputArgs struct {
	// The OCID of the console history.
	ConsoleHistoryId pulumi.StringInput `pulumi:"consoleHistoryId"`
	// The database node [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
	DbNodeId pulumi.StringInput `pulumi:"dbNodeId"`
}

func (LookupDbNodeConsoleHistoryOutputArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*LookupDbNodeConsoleHistoryArgs)(nil)).Elem()
}

// A collection of values returned by getDbNodeConsoleHistory.
type LookupDbNodeConsoleHistoryResultOutput struct{ *pulumi.OutputState }

func (LookupDbNodeConsoleHistoryResultOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*LookupDbNodeConsoleHistoryResult)(nil)).Elem()
}

func (o LookupDbNodeConsoleHistoryResultOutput) ToLookupDbNodeConsoleHistoryResultOutput() LookupDbNodeConsoleHistoryResultOutput {
	return o
}

func (o LookupDbNodeConsoleHistoryResultOutput) ToLookupDbNodeConsoleHistoryResultOutputWithContext(ctx context.Context) LookupDbNodeConsoleHistoryResultOutput {
	return o
}

// The OCID of the compartment containing the console history.
func (o LookupDbNodeConsoleHistoryResultOutput) CompartmentId() pulumi.StringOutput {
	return o.ApplyT(func(v LookupDbNodeConsoleHistoryResult) string { return v.CompartmentId }).(pulumi.StringOutput)
}

func (o LookupDbNodeConsoleHistoryResultOutput) ConsoleHistoryId() pulumi.StringOutput {
	return o.ApplyT(func(v LookupDbNodeConsoleHistoryResult) string { return v.ConsoleHistoryId }).(pulumi.StringOutput)
}

// The OCID of the database node.
func (o LookupDbNodeConsoleHistoryResultOutput) DbNodeId() pulumi.StringOutput {
	return o.ApplyT(func(v LookupDbNodeConsoleHistoryResult) string { return v.DbNodeId }).(pulumi.StringOutput)
}

// Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).
func (o LookupDbNodeConsoleHistoryResultOutput) DefinedTags() pulumi.StringMapOutput {
	return o.ApplyT(func(v LookupDbNodeConsoleHistoryResult) map[string]string { return v.DefinedTags }).(pulumi.StringMapOutput)
}

// The user-friendly name for the console history. The name does not need to be unique.
func (o LookupDbNodeConsoleHistoryResultOutput) DisplayName() pulumi.StringOutput {
	return o.ApplyT(func(v LookupDbNodeConsoleHistoryResult) string { return v.DisplayName }).(pulumi.StringOutput)
}

// Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
func (o LookupDbNodeConsoleHistoryResultOutput) FreeformTags() pulumi.StringMapOutput {
	return o.ApplyT(func(v LookupDbNodeConsoleHistoryResult) map[string]string { return v.FreeformTags }).(pulumi.StringMapOutput)
}

// The OCID of the console history.
func (o LookupDbNodeConsoleHistoryResultOutput) Id() pulumi.StringOutput {
	return o.ApplyT(func(v LookupDbNodeConsoleHistoryResult) string { return v.Id }).(pulumi.StringOutput)
}

// Additional information about the current lifecycle state.
func (o LookupDbNodeConsoleHistoryResultOutput) LifecycleDetails() pulumi.StringOutput {
	return o.ApplyT(func(v LookupDbNodeConsoleHistoryResult) string { return v.LifecycleDetails }).(pulumi.StringOutput)
}

// The current state of the console history.
func (o LookupDbNodeConsoleHistoryResultOutput) State() pulumi.StringOutput {
	return o.ApplyT(func(v LookupDbNodeConsoleHistoryResult) string { return v.State }).(pulumi.StringOutput)
}

// The date and time the console history was created.
func (o LookupDbNodeConsoleHistoryResultOutput) TimeCreated() pulumi.StringOutput {
	return o.ApplyT(func(v LookupDbNodeConsoleHistoryResult) string { return v.TimeCreated }).(pulumi.StringOutput)
}

func init() {
	pulumi.RegisterOutputType(LookupDbNodeConsoleHistoryResultOutput{})
}
