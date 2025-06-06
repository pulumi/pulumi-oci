// Code generated by pulumi-language-go DO NOT EDIT.
// *** WARNING: Do not edit by hand unless you're certain you know what you are doing! ***

package database

import (
	"context"
	"reflect"

	"github.com/pulumi/pulumi-oci/sdk/v3/go/oci/internal"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This data source provides details about a specific Db Node Console History Content resource in Oracle Cloud Infrastructure Database service.
//
// Retrieves the specified database node console history contents upto a megabyte.
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
//			_, err := database.GetDbNodeConsoleHistoryContent(ctx, &database.GetDbNodeConsoleHistoryContentArgs{
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
func GetDbNodeConsoleHistoryContent(ctx *pulumi.Context, args *GetDbNodeConsoleHistoryContentArgs, opts ...pulumi.InvokeOption) (*GetDbNodeConsoleHistoryContentResult, error) {
	opts = internal.PkgInvokeDefaultOpts(opts)
	var rv GetDbNodeConsoleHistoryContentResult
	err := ctx.Invoke("oci:Database/getDbNodeConsoleHistoryContent:getDbNodeConsoleHistoryContent", args, &rv, opts...)
	if err != nil {
		return nil, err
	}
	return &rv, nil
}

// A collection of arguments for invoking getDbNodeConsoleHistoryContent.
type GetDbNodeConsoleHistoryContentArgs struct {
	// The OCID of the console history.
	ConsoleHistoryId string `pulumi:"consoleHistoryId"`
	// The database node [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
	DbNodeId string `pulumi:"dbNodeId"`
}

// A collection of values returned by getDbNodeConsoleHistoryContent.
type GetDbNodeConsoleHistoryContentResult struct {
	ConsoleHistoryId string `pulumi:"consoleHistoryId"`
	DbNodeId         string `pulumi:"dbNodeId"`
	// The provider-assigned unique ID for this managed resource.
	Id string `pulumi:"id"`
}

func GetDbNodeConsoleHistoryContentOutput(ctx *pulumi.Context, args GetDbNodeConsoleHistoryContentOutputArgs, opts ...pulumi.InvokeOption) GetDbNodeConsoleHistoryContentResultOutput {
	return pulumi.ToOutputWithContext(ctx.Context(), args).
		ApplyT(func(v interface{}) (GetDbNodeConsoleHistoryContentResultOutput, error) {
			args := v.(GetDbNodeConsoleHistoryContentArgs)
			options := pulumi.InvokeOutputOptions{InvokeOptions: internal.PkgInvokeDefaultOpts(opts)}
			return ctx.InvokeOutput("oci:Database/getDbNodeConsoleHistoryContent:getDbNodeConsoleHistoryContent", args, GetDbNodeConsoleHistoryContentResultOutput{}, options).(GetDbNodeConsoleHistoryContentResultOutput), nil
		}).(GetDbNodeConsoleHistoryContentResultOutput)
}

// A collection of arguments for invoking getDbNodeConsoleHistoryContent.
type GetDbNodeConsoleHistoryContentOutputArgs struct {
	// The OCID of the console history.
	ConsoleHistoryId pulumi.StringInput `pulumi:"consoleHistoryId"`
	// The database node [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
	DbNodeId pulumi.StringInput `pulumi:"dbNodeId"`
}

func (GetDbNodeConsoleHistoryContentOutputArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*GetDbNodeConsoleHistoryContentArgs)(nil)).Elem()
}

// A collection of values returned by getDbNodeConsoleHistoryContent.
type GetDbNodeConsoleHistoryContentResultOutput struct{ *pulumi.OutputState }

func (GetDbNodeConsoleHistoryContentResultOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*GetDbNodeConsoleHistoryContentResult)(nil)).Elem()
}

func (o GetDbNodeConsoleHistoryContentResultOutput) ToGetDbNodeConsoleHistoryContentResultOutput() GetDbNodeConsoleHistoryContentResultOutput {
	return o
}

func (o GetDbNodeConsoleHistoryContentResultOutput) ToGetDbNodeConsoleHistoryContentResultOutputWithContext(ctx context.Context) GetDbNodeConsoleHistoryContentResultOutput {
	return o
}

func (o GetDbNodeConsoleHistoryContentResultOutput) ConsoleHistoryId() pulumi.StringOutput {
	return o.ApplyT(func(v GetDbNodeConsoleHistoryContentResult) string { return v.ConsoleHistoryId }).(pulumi.StringOutput)
}

func (o GetDbNodeConsoleHistoryContentResultOutput) DbNodeId() pulumi.StringOutput {
	return o.ApplyT(func(v GetDbNodeConsoleHistoryContentResult) string { return v.DbNodeId }).(pulumi.StringOutput)
}

// The provider-assigned unique ID for this managed resource.
func (o GetDbNodeConsoleHistoryContentResultOutput) Id() pulumi.StringOutput {
	return o.ApplyT(func(v GetDbNodeConsoleHistoryContentResult) string { return v.Id }).(pulumi.StringOutput)
}

func init() {
	pulumi.RegisterOutputType(GetDbNodeConsoleHistoryContentResultOutput{})
}
