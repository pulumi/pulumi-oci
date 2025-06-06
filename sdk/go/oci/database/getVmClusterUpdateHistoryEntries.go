// Code generated by pulumi-language-go DO NOT EDIT.
// *** WARNING: Do not edit by hand unless you're certain you know what you are doing! ***

package database

import (
	"context"
	"reflect"

	"github.com/pulumi/pulumi-oci/sdk/v3/go/oci/internal"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This data source provides the list of Vm Cluster Update History Entries in Oracle Cloud Infrastructure Database service.
//
// Gets the history of the maintenance update actions performed on the specified VM cluster. Applies to Exadata Cloud@Customer instances only.
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
//			_, err := database.GetVmClusterUpdateHistoryEntries(ctx, &database.GetVmClusterUpdateHistoryEntriesArgs{
//				VmClusterId: testVmCluster.Id,
//				State:       pulumi.StringRef(vmClusterUpdateHistoryEntryState),
//				UpdateType:  pulumi.StringRef(vmClusterUpdateHistoryEntryUpdateType),
//			}, nil)
//			if err != nil {
//				return err
//			}
//			return nil
//		})
//	}
//
// ```
func GetVmClusterUpdateHistoryEntries(ctx *pulumi.Context, args *GetVmClusterUpdateHistoryEntriesArgs, opts ...pulumi.InvokeOption) (*GetVmClusterUpdateHistoryEntriesResult, error) {
	opts = internal.PkgInvokeDefaultOpts(opts)
	var rv GetVmClusterUpdateHistoryEntriesResult
	err := ctx.Invoke("oci:Database/getVmClusterUpdateHistoryEntries:getVmClusterUpdateHistoryEntries", args, &rv, opts...)
	if err != nil {
		return nil, err
	}
	return &rv, nil
}

// A collection of arguments for invoking getVmClusterUpdateHistoryEntries.
type GetVmClusterUpdateHistoryEntriesArgs struct {
	Filters []GetVmClusterUpdateHistoryEntriesFilter `pulumi:"filters"`
	// A filter to return only resources that match the given lifecycle state exactly.
	State *string `pulumi:"state"`
	// A filter to return only resources that match the given update type exactly.
	UpdateType *string `pulumi:"updateType"`
	// The VM cluster [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
	VmClusterId string `pulumi:"vmClusterId"`
}

// A collection of values returned by getVmClusterUpdateHistoryEntries.
type GetVmClusterUpdateHistoryEntriesResult struct {
	Filters []GetVmClusterUpdateHistoryEntriesFilter `pulumi:"filters"`
	// The provider-assigned unique ID for this managed resource.
	Id string `pulumi:"id"`
	// The current lifecycle state of the maintenance update operation.
	State *string `pulumi:"state"`
	// The type of VM cluster maintenance update.
	UpdateType  *string `pulumi:"updateType"`
	VmClusterId string  `pulumi:"vmClusterId"`
	// The list of vm_cluster_update_history_entries.
	VmClusterUpdateHistoryEntries []GetVmClusterUpdateHistoryEntriesVmClusterUpdateHistoryEntry `pulumi:"vmClusterUpdateHistoryEntries"`
}

func GetVmClusterUpdateHistoryEntriesOutput(ctx *pulumi.Context, args GetVmClusterUpdateHistoryEntriesOutputArgs, opts ...pulumi.InvokeOption) GetVmClusterUpdateHistoryEntriesResultOutput {
	return pulumi.ToOutputWithContext(ctx.Context(), args).
		ApplyT(func(v interface{}) (GetVmClusterUpdateHistoryEntriesResultOutput, error) {
			args := v.(GetVmClusterUpdateHistoryEntriesArgs)
			options := pulumi.InvokeOutputOptions{InvokeOptions: internal.PkgInvokeDefaultOpts(opts)}
			return ctx.InvokeOutput("oci:Database/getVmClusterUpdateHistoryEntries:getVmClusterUpdateHistoryEntries", args, GetVmClusterUpdateHistoryEntriesResultOutput{}, options).(GetVmClusterUpdateHistoryEntriesResultOutput), nil
		}).(GetVmClusterUpdateHistoryEntriesResultOutput)
}

// A collection of arguments for invoking getVmClusterUpdateHistoryEntries.
type GetVmClusterUpdateHistoryEntriesOutputArgs struct {
	Filters GetVmClusterUpdateHistoryEntriesFilterArrayInput `pulumi:"filters"`
	// A filter to return only resources that match the given lifecycle state exactly.
	State pulumi.StringPtrInput `pulumi:"state"`
	// A filter to return only resources that match the given update type exactly.
	UpdateType pulumi.StringPtrInput `pulumi:"updateType"`
	// The VM cluster [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
	VmClusterId pulumi.StringInput `pulumi:"vmClusterId"`
}

func (GetVmClusterUpdateHistoryEntriesOutputArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*GetVmClusterUpdateHistoryEntriesArgs)(nil)).Elem()
}

// A collection of values returned by getVmClusterUpdateHistoryEntries.
type GetVmClusterUpdateHistoryEntriesResultOutput struct{ *pulumi.OutputState }

func (GetVmClusterUpdateHistoryEntriesResultOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*GetVmClusterUpdateHistoryEntriesResult)(nil)).Elem()
}

func (o GetVmClusterUpdateHistoryEntriesResultOutput) ToGetVmClusterUpdateHistoryEntriesResultOutput() GetVmClusterUpdateHistoryEntriesResultOutput {
	return o
}

func (o GetVmClusterUpdateHistoryEntriesResultOutput) ToGetVmClusterUpdateHistoryEntriesResultOutputWithContext(ctx context.Context) GetVmClusterUpdateHistoryEntriesResultOutput {
	return o
}

func (o GetVmClusterUpdateHistoryEntriesResultOutput) Filters() GetVmClusterUpdateHistoryEntriesFilterArrayOutput {
	return o.ApplyT(func(v GetVmClusterUpdateHistoryEntriesResult) []GetVmClusterUpdateHistoryEntriesFilter {
		return v.Filters
	}).(GetVmClusterUpdateHistoryEntriesFilterArrayOutput)
}

// The provider-assigned unique ID for this managed resource.
func (o GetVmClusterUpdateHistoryEntriesResultOutput) Id() pulumi.StringOutput {
	return o.ApplyT(func(v GetVmClusterUpdateHistoryEntriesResult) string { return v.Id }).(pulumi.StringOutput)
}

// The current lifecycle state of the maintenance update operation.
func (o GetVmClusterUpdateHistoryEntriesResultOutput) State() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetVmClusterUpdateHistoryEntriesResult) *string { return v.State }).(pulumi.StringPtrOutput)
}

// The type of VM cluster maintenance update.
func (o GetVmClusterUpdateHistoryEntriesResultOutput) UpdateType() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetVmClusterUpdateHistoryEntriesResult) *string { return v.UpdateType }).(pulumi.StringPtrOutput)
}

func (o GetVmClusterUpdateHistoryEntriesResultOutput) VmClusterId() pulumi.StringOutput {
	return o.ApplyT(func(v GetVmClusterUpdateHistoryEntriesResult) string { return v.VmClusterId }).(pulumi.StringOutput)
}

// The list of vm_cluster_update_history_entries.
func (o GetVmClusterUpdateHistoryEntriesResultOutput) VmClusterUpdateHistoryEntries() GetVmClusterUpdateHistoryEntriesVmClusterUpdateHistoryEntryArrayOutput {
	return o.ApplyT(func(v GetVmClusterUpdateHistoryEntriesResult) []GetVmClusterUpdateHistoryEntriesVmClusterUpdateHistoryEntry {
		return v.VmClusterUpdateHistoryEntries
	}).(GetVmClusterUpdateHistoryEntriesVmClusterUpdateHistoryEntryArrayOutput)
}

func init() {
	pulumi.RegisterOutputType(GetVmClusterUpdateHistoryEntriesResultOutput{})
}
