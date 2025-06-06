// Code generated by pulumi-language-go DO NOT EDIT.
// *** WARNING: Do not edit by hand unless you're certain you know what you are doing! ***

package database

import (
	"context"
	"reflect"

	"github.com/pulumi/pulumi-oci/sdk/v3/go/oci/internal"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This data source provides the list of Db Node Console Connections in Oracle Cloud Infrastructure Database service.
//
// Lists the console connections for the specified database node.
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
//			_, err := database.GetDbNodeConsoleConnections(ctx, &database.GetDbNodeConsoleConnectionsArgs{
//				DbNodeId: testDbNode.Id,
//			}, nil)
//			if err != nil {
//				return err
//			}
//			return nil
//		})
//	}
//
// ```
func GetDbNodeConsoleConnections(ctx *pulumi.Context, args *GetDbNodeConsoleConnectionsArgs, opts ...pulumi.InvokeOption) (*GetDbNodeConsoleConnectionsResult, error) {
	opts = internal.PkgInvokeDefaultOpts(opts)
	var rv GetDbNodeConsoleConnectionsResult
	err := ctx.Invoke("oci:Database/getDbNodeConsoleConnections:getDbNodeConsoleConnections", args, &rv, opts...)
	if err != nil {
		return nil, err
	}
	return &rv, nil
}

// A collection of arguments for invoking getDbNodeConsoleConnections.
type GetDbNodeConsoleConnectionsArgs struct {
	// The database node [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
	DbNodeId string                              `pulumi:"dbNodeId"`
	Filters  []GetDbNodeConsoleConnectionsFilter `pulumi:"filters"`
}

// A collection of values returned by getDbNodeConsoleConnections.
type GetDbNodeConsoleConnectionsResult struct {
	// The list of console_connections.
	ConsoleConnections []GetDbNodeConsoleConnectionsConsoleConnection `pulumi:"consoleConnections"`
	// The OCID of the database node.
	DbNodeId string                              `pulumi:"dbNodeId"`
	Filters  []GetDbNodeConsoleConnectionsFilter `pulumi:"filters"`
	// The provider-assigned unique ID for this managed resource.
	Id string `pulumi:"id"`
}

func GetDbNodeConsoleConnectionsOutput(ctx *pulumi.Context, args GetDbNodeConsoleConnectionsOutputArgs, opts ...pulumi.InvokeOption) GetDbNodeConsoleConnectionsResultOutput {
	return pulumi.ToOutputWithContext(ctx.Context(), args).
		ApplyT(func(v interface{}) (GetDbNodeConsoleConnectionsResultOutput, error) {
			args := v.(GetDbNodeConsoleConnectionsArgs)
			options := pulumi.InvokeOutputOptions{InvokeOptions: internal.PkgInvokeDefaultOpts(opts)}
			return ctx.InvokeOutput("oci:Database/getDbNodeConsoleConnections:getDbNodeConsoleConnections", args, GetDbNodeConsoleConnectionsResultOutput{}, options).(GetDbNodeConsoleConnectionsResultOutput), nil
		}).(GetDbNodeConsoleConnectionsResultOutput)
}

// A collection of arguments for invoking getDbNodeConsoleConnections.
type GetDbNodeConsoleConnectionsOutputArgs struct {
	// The database node [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
	DbNodeId pulumi.StringInput                          `pulumi:"dbNodeId"`
	Filters  GetDbNodeConsoleConnectionsFilterArrayInput `pulumi:"filters"`
}

func (GetDbNodeConsoleConnectionsOutputArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*GetDbNodeConsoleConnectionsArgs)(nil)).Elem()
}

// A collection of values returned by getDbNodeConsoleConnections.
type GetDbNodeConsoleConnectionsResultOutput struct{ *pulumi.OutputState }

func (GetDbNodeConsoleConnectionsResultOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*GetDbNodeConsoleConnectionsResult)(nil)).Elem()
}

func (o GetDbNodeConsoleConnectionsResultOutput) ToGetDbNodeConsoleConnectionsResultOutput() GetDbNodeConsoleConnectionsResultOutput {
	return o
}

func (o GetDbNodeConsoleConnectionsResultOutput) ToGetDbNodeConsoleConnectionsResultOutputWithContext(ctx context.Context) GetDbNodeConsoleConnectionsResultOutput {
	return o
}

// The list of console_connections.
func (o GetDbNodeConsoleConnectionsResultOutput) ConsoleConnections() GetDbNodeConsoleConnectionsConsoleConnectionArrayOutput {
	return o.ApplyT(func(v GetDbNodeConsoleConnectionsResult) []GetDbNodeConsoleConnectionsConsoleConnection {
		return v.ConsoleConnections
	}).(GetDbNodeConsoleConnectionsConsoleConnectionArrayOutput)
}

// The OCID of the database node.
func (o GetDbNodeConsoleConnectionsResultOutput) DbNodeId() pulumi.StringOutput {
	return o.ApplyT(func(v GetDbNodeConsoleConnectionsResult) string { return v.DbNodeId }).(pulumi.StringOutput)
}

func (o GetDbNodeConsoleConnectionsResultOutput) Filters() GetDbNodeConsoleConnectionsFilterArrayOutput {
	return o.ApplyT(func(v GetDbNodeConsoleConnectionsResult) []GetDbNodeConsoleConnectionsFilter { return v.Filters }).(GetDbNodeConsoleConnectionsFilterArrayOutput)
}

// The provider-assigned unique ID for this managed resource.
func (o GetDbNodeConsoleConnectionsResultOutput) Id() pulumi.StringOutput {
	return o.ApplyT(func(v GetDbNodeConsoleConnectionsResult) string { return v.Id }).(pulumi.StringOutput)
}

func init() {
	pulumi.RegisterOutputType(GetDbNodeConsoleConnectionsResultOutput{})
}
