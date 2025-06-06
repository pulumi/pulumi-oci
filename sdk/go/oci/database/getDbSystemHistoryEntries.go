// Code generated by pulumi-language-go DO NOT EDIT.
// *** WARNING: Do not edit by hand unless you're certain you know what you are doing! ***

package database

import (
	"context"
	"reflect"

	"github.com/pulumi/pulumi-oci/sdk/v3/go/oci/internal"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This data source provides the list of Db System Patch History Entries in Oracle Cloud Infrastructure Database service.
//
// Gets the history of the patch actions performed on the specified DB system.
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
//			_, err := database.GetDbSystemHistoryEntries(ctx, &database.GetDbSystemHistoryEntriesArgs{
//				DbSystemId: testDbSystem.Id,
//			}, nil)
//			if err != nil {
//				return err
//			}
//			return nil
//		})
//	}
//
// ```
func GetDbSystemHistoryEntries(ctx *pulumi.Context, args *GetDbSystemHistoryEntriesArgs, opts ...pulumi.InvokeOption) (*GetDbSystemHistoryEntriesResult, error) {
	opts = internal.PkgInvokeDefaultOpts(opts)
	var rv GetDbSystemHistoryEntriesResult
	err := ctx.Invoke("oci:Database/getDbSystemHistoryEntries:getDbSystemHistoryEntries", args, &rv, opts...)
	if err != nil {
		return nil, err
	}
	return &rv, nil
}

// A collection of arguments for invoking getDbSystemHistoryEntries.
type GetDbSystemHistoryEntriesArgs struct {
	// The DB system [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
	DbSystemId string                            `pulumi:"dbSystemId"`
	Filters    []GetDbSystemHistoryEntriesFilter `pulumi:"filters"`
}

// A collection of values returned by getDbSystemHistoryEntries.
type GetDbSystemHistoryEntriesResult struct {
	DbSystemId string                            `pulumi:"dbSystemId"`
	Filters    []GetDbSystemHistoryEntriesFilter `pulumi:"filters"`
	// The provider-assigned unique ID for this managed resource.
	Id string `pulumi:"id"`
	// The list of patch_history_entries.
	PatchHistoryEntries []GetDbSystemHistoryEntriesPatchHistoryEntry `pulumi:"patchHistoryEntries"`
}

func GetDbSystemHistoryEntriesOutput(ctx *pulumi.Context, args GetDbSystemHistoryEntriesOutputArgs, opts ...pulumi.InvokeOption) GetDbSystemHistoryEntriesResultOutput {
	return pulumi.ToOutputWithContext(ctx.Context(), args).
		ApplyT(func(v interface{}) (GetDbSystemHistoryEntriesResultOutput, error) {
			args := v.(GetDbSystemHistoryEntriesArgs)
			options := pulumi.InvokeOutputOptions{InvokeOptions: internal.PkgInvokeDefaultOpts(opts)}
			return ctx.InvokeOutput("oci:Database/getDbSystemHistoryEntries:getDbSystemHistoryEntries", args, GetDbSystemHistoryEntriesResultOutput{}, options).(GetDbSystemHistoryEntriesResultOutput), nil
		}).(GetDbSystemHistoryEntriesResultOutput)
}

// A collection of arguments for invoking getDbSystemHistoryEntries.
type GetDbSystemHistoryEntriesOutputArgs struct {
	// The DB system [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
	DbSystemId pulumi.StringInput                        `pulumi:"dbSystemId"`
	Filters    GetDbSystemHistoryEntriesFilterArrayInput `pulumi:"filters"`
}

func (GetDbSystemHistoryEntriesOutputArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*GetDbSystemHistoryEntriesArgs)(nil)).Elem()
}

// A collection of values returned by getDbSystemHistoryEntries.
type GetDbSystemHistoryEntriesResultOutput struct{ *pulumi.OutputState }

func (GetDbSystemHistoryEntriesResultOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*GetDbSystemHistoryEntriesResult)(nil)).Elem()
}

func (o GetDbSystemHistoryEntriesResultOutput) ToGetDbSystemHistoryEntriesResultOutput() GetDbSystemHistoryEntriesResultOutput {
	return o
}

func (o GetDbSystemHistoryEntriesResultOutput) ToGetDbSystemHistoryEntriesResultOutputWithContext(ctx context.Context) GetDbSystemHistoryEntriesResultOutput {
	return o
}

func (o GetDbSystemHistoryEntriesResultOutput) DbSystemId() pulumi.StringOutput {
	return o.ApplyT(func(v GetDbSystemHistoryEntriesResult) string { return v.DbSystemId }).(pulumi.StringOutput)
}

func (o GetDbSystemHistoryEntriesResultOutput) Filters() GetDbSystemHistoryEntriesFilterArrayOutput {
	return o.ApplyT(func(v GetDbSystemHistoryEntriesResult) []GetDbSystemHistoryEntriesFilter { return v.Filters }).(GetDbSystemHistoryEntriesFilterArrayOutput)
}

// The provider-assigned unique ID for this managed resource.
func (o GetDbSystemHistoryEntriesResultOutput) Id() pulumi.StringOutput {
	return o.ApplyT(func(v GetDbSystemHistoryEntriesResult) string { return v.Id }).(pulumi.StringOutput)
}

// The list of patch_history_entries.
func (o GetDbSystemHistoryEntriesResultOutput) PatchHistoryEntries() GetDbSystemHistoryEntriesPatchHistoryEntryArrayOutput {
	return o.ApplyT(func(v GetDbSystemHistoryEntriesResult) []GetDbSystemHistoryEntriesPatchHistoryEntry {
		return v.PatchHistoryEntries
	}).(GetDbSystemHistoryEntriesPatchHistoryEntryArrayOutput)
}

func init() {
	pulumi.RegisterOutputType(GetDbSystemHistoryEntriesResultOutput{})
}
