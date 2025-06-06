// Code generated by pulumi-language-go DO NOT EDIT.
// *** WARNING: Do not edit by hand unless you're certain you know what you are doing! ***

package opsi

import (
	"context"
	"reflect"

	"github.com/pulumi/pulumi-oci/sdk/v3/go/oci/internal"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This data source provides details about a specific Operations Insights Warehouse resource in Oracle Cloud Infrastructure Opsi service.
//
// Gets details of an Ops Insights Warehouse.
// There is only expected to be 1 warehouse per tenant. The warehouse is expected to be in the root compartment.
//
// ## Example Usage
//
// ```go
// package main
//
// import (
//
//	"github.com/pulumi/pulumi-oci/sdk/v3/go/oci/opsi"
//	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
//
// )
//
//	func main() {
//		pulumi.Run(func(ctx *pulumi.Context) error {
//			_, err := opsi.GetOperationsInsightsWarehouse(ctx, &opsi.GetOperationsInsightsWarehouseArgs{
//				OperationsInsightsWarehouseId: testOperationsInsightsWarehouseOciOpsiOperationsInsightsWarehouse.Id,
//			}, nil)
//			if err != nil {
//				return err
//			}
//			return nil
//		})
//	}
//
// ```
func LookupOperationsInsightsWarehouse(ctx *pulumi.Context, args *LookupOperationsInsightsWarehouseArgs, opts ...pulumi.InvokeOption) (*LookupOperationsInsightsWarehouseResult, error) {
	opts = internal.PkgInvokeDefaultOpts(opts)
	var rv LookupOperationsInsightsWarehouseResult
	err := ctx.Invoke("oci:Opsi/getOperationsInsightsWarehouse:getOperationsInsightsWarehouse", args, &rv, opts...)
	if err != nil {
		return nil, err
	}
	return &rv, nil
}

// A collection of arguments for invoking getOperationsInsightsWarehouse.
type LookupOperationsInsightsWarehouseArgs struct {
	// Unique Ops Insights Warehouse identifier
	OperationsInsightsWarehouseId string `pulumi:"operationsInsightsWarehouseId"`
}

// A collection of values returned by getOperationsInsightsWarehouse.
type LookupOperationsInsightsWarehouseResult struct {
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
	CompartmentId string `pulumi:"compartmentId"`
	// The compute model for the OPSI warehouse ADW (OCPU or ECPU)
	ComputeModel string `pulumi:"computeModel"`
	// Number of CPUs allocated to OPSI Warehouse ADW.
	CpuAllocated float64 `pulumi:"cpuAllocated"`
	// Number of OCPUs used by OPSI Warehouse ADW. Can be fractional.
	CpuUsed float64 `pulumi:"cpuUsed"`
	// Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
	DefinedTags map[string]string `pulumi:"definedTags"`
	// User-friedly name of Ops Insights Warehouse that does not have to be unique.
	DisplayName string `pulumi:"displayName"`
	// OCID of the dynamic group created for the warehouse
	DynamicGroupId string `pulumi:"dynamicGroupId"`
	// Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
	FreeformTags map[string]string `pulumi:"freeformTags"`
	// OPSI Warehouse OCID
	Id string `pulumi:"id"`
	// A message describing the current state in more detail. For example, can be used to provide actionable information for a resource in Failed state.
	LifecycleDetails string `pulumi:"lifecycleDetails"`
	// Tenancy Identifier of Ops Insights service
	OperationsInsightsTenancyId   string `pulumi:"operationsInsightsTenancyId"`
	OperationsInsightsWarehouseId string `pulumi:"operationsInsightsWarehouseId"`
	// Possible lifecycle states
	State string `pulumi:"state"`
	// Storage allocated to OPSI Warehouse ADW.
	StorageAllocatedInGbs float64 `pulumi:"storageAllocatedInGbs"`
	// Storage by OPSI Warehouse ADW in GB.
	StorageUsedInGbs float64 `pulumi:"storageUsedInGbs"`
	// System tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"orcl-cloud.free-tier-retained": "true"}`
	SystemTags map[string]string `pulumi:"systemTags"`
	// The time at which the resource was first created. An RFC3339 formatted datetime string
	TimeCreated string `pulumi:"timeCreated"`
	// The time at which the ADW wallet was last rotated for the Ops Insights Warehouse. An RFC3339 formatted datetime string
	TimeLastWalletRotated string `pulumi:"timeLastWalletRotated"`
	// The time at which the resource was last updated. An RFC3339 formatted datetime string
	TimeUpdated string `pulumi:"timeUpdated"`
}

func LookupOperationsInsightsWarehouseOutput(ctx *pulumi.Context, args LookupOperationsInsightsWarehouseOutputArgs, opts ...pulumi.InvokeOption) LookupOperationsInsightsWarehouseResultOutput {
	return pulumi.ToOutputWithContext(ctx.Context(), args).
		ApplyT(func(v interface{}) (LookupOperationsInsightsWarehouseResultOutput, error) {
			args := v.(LookupOperationsInsightsWarehouseArgs)
			options := pulumi.InvokeOutputOptions{InvokeOptions: internal.PkgInvokeDefaultOpts(opts)}
			return ctx.InvokeOutput("oci:Opsi/getOperationsInsightsWarehouse:getOperationsInsightsWarehouse", args, LookupOperationsInsightsWarehouseResultOutput{}, options).(LookupOperationsInsightsWarehouseResultOutput), nil
		}).(LookupOperationsInsightsWarehouseResultOutput)
}

// A collection of arguments for invoking getOperationsInsightsWarehouse.
type LookupOperationsInsightsWarehouseOutputArgs struct {
	// Unique Ops Insights Warehouse identifier
	OperationsInsightsWarehouseId pulumi.StringInput `pulumi:"operationsInsightsWarehouseId"`
}

func (LookupOperationsInsightsWarehouseOutputArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*LookupOperationsInsightsWarehouseArgs)(nil)).Elem()
}

// A collection of values returned by getOperationsInsightsWarehouse.
type LookupOperationsInsightsWarehouseResultOutput struct{ *pulumi.OutputState }

func (LookupOperationsInsightsWarehouseResultOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*LookupOperationsInsightsWarehouseResult)(nil)).Elem()
}

func (o LookupOperationsInsightsWarehouseResultOutput) ToLookupOperationsInsightsWarehouseResultOutput() LookupOperationsInsightsWarehouseResultOutput {
	return o
}

func (o LookupOperationsInsightsWarehouseResultOutput) ToLookupOperationsInsightsWarehouseResultOutputWithContext(ctx context.Context) LookupOperationsInsightsWarehouseResultOutput {
	return o
}

// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
func (o LookupOperationsInsightsWarehouseResultOutput) CompartmentId() pulumi.StringOutput {
	return o.ApplyT(func(v LookupOperationsInsightsWarehouseResult) string { return v.CompartmentId }).(pulumi.StringOutput)
}

// The compute model for the OPSI warehouse ADW (OCPU or ECPU)
func (o LookupOperationsInsightsWarehouseResultOutput) ComputeModel() pulumi.StringOutput {
	return o.ApplyT(func(v LookupOperationsInsightsWarehouseResult) string { return v.ComputeModel }).(pulumi.StringOutput)
}

// Number of CPUs allocated to OPSI Warehouse ADW.
func (o LookupOperationsInsightsWarehouseResultOutput) CpuAllocated() pulumi.Float64Output {
	return o.ApplyT(func(v LookupOperationsInsightsWarehouseResult) float64 { return v.CpuAllocated }).(pulumi.Float64Output)
}

// Number of OCPUs used by OPSI Warehouse ADW. Can be fractional.
func (o LookupOperationsInsightsWarehouseResultOutput) CpuUsed() pulumi.Float64Output {
	return o.ApplyT(func(v LookupOperationsInsightsWarehouseResult) float64 { return v.CpuUsed }).(pulumi.Float64Output)
}

// Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
func (o LookupOperationsInsightsWarehouseResultOutput) DefinedTags() pulumi.StringMapOutput {
	return o.ApplyT(func(v LookupOperationsInsightsWarehouseResult) map[string]string { return v.DefinedTags }).(pulumi.StringMapOutput)
}

// User-friedly name of Ops Insights Warehouse that does not have to be unique.
func (o LookupOperationsInsightsWarehouseResultOutput) DisplayName() pulumi.StringOutput {
	return o.ApplyT(func(v LookupOperationsInsightsWarehouseResult) string { return v.DisplayName }).(pulumi.StringOutput)
}

// OCID of the dynamic group created for the warehouse
func (o LookupOperationsInsightsWarehouseResultOutput) DynamicGroupId() pulumi.StringOutput {
	return o.ApplyT(func(v LookupOperationsInsightsWarehouseResult) string { return v.DynamicGroupId }).(pulumi.StringOutput)
}

// Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
func (o LookupOperationsInsightsWarehouseResultOutput) FreeformTags() pulumi.StringMapOutput {
	return o.ApplyT(func(v LookupOperationsInsightsWarehouseResult) map[string]string { return v.FreeformTags }).(pulumi.StringMapOutput)
}

// OPSI Warehouse OCID
func (o LookupOperationsInsightsWarehouseResultOutput) Id() pulumi.StringOutput {
	return o.ApplyT(func(v LookupOperationsInsightsWarehouseResult) string { return v.Id }).(pulumi.StringOutput)
}

// A message describing the current state in more detail. For example, can be used to provide actionable information for a resource in Failed state.
func (o LookupOperationsInsightsWarehouseResultOutput) LifecycleDetails() pulumi.StringOutput {
	return o.ApplyT(func(v LookupOperationsInsightsWarehouseResult) string { return v.LifecycleDetails }).(pulumi.StringOutput)
}

// Tenancy Identifier of Ops Insights service
func (o LookupOperationsInsightsWarehouseResultOutput) OperationsInsightsTenancyId() pulumi.StringOutput {
	return o.ApplyT(func(v LookupOperationsInsightsWarehouseResult) string { return v.OperationsInsightsTenancyId }).(pulumi.StringOutput)
}

func (o LookupOperationsInsightsWarehouseResultOutput) OperationsInsightsWarehouseId() pulumi.StringOutput {
	return o.ApplyT(func(v LookupOperationsInsightsWarehouseResult) string { return v.OperationsInsightsWarehouseId }).(pulumi.StringOutput)
}

// Possible lifecycle states
func (o LookupOperationsInsightsWarehouseResultOutput) State() pulumi.StringOutput {
	return o.ApplyT(func(v LookupOperationsInsightsWarehouseResult) string { return v.State }).(pulumi.StringOutput)
}

// Storage allocated to OPSI Warehouse ADW.
func (o LookupOperationsInsightsWarehouseResultOutput) StorageAllocatedInGbs() pulumi.Float64Output {
	return o.ApplyT(func(v LookupOperationsInsightsWarehouseResult) float64 { return v.StorageAllocatedInGbs }).(pulumi.Float64Output)
}

// Storage by OPSI Warehouse ADW in GB.
func (o LookupOperationsInsightsWarehouseResultOutput) StorageUsedInGbs() pulumi.Float64Output {
	return o.ApplyT(func(v LookupOperationsInsightsWarehouseResult) float64 { return v.StorageUsedInGbs }).(pulumi.Float64Output)
}

// System tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"orcl-cloud.free-tier-retained": "true"}`
func (o LookupOperationsInsightsWarehouseResultOutput) SystemTags() pulumi.StringMapOutput {
	return o.ApplyT(func(v LookupOperationsInsightsWarehouseResult) map[string]string { return v.SystemTags }).(pulumi.StringMapOutput)
}

// The time at which the resource was first created. An RFC3339 formatted datetime string
func (o LookupOperationsInsightsWarehouseResultOutput) TimeCreated() pulumi.StringOutput {
	return o.ApplyT(func(v LookupOperationsInsightsWarehouseResult) string { return v.TimeCreated }).(pulumi.StringOutput)
}

// The time at which the ADW wallet was last rotated for the Ops Insights Warehouse. An RFC3339 formatted datetime string
func (o LookupOperationsInsightsWarehouseResultOutput) TimeLastWalletRotated() pulumi.StringOutput {
	return o.ApplyT(func(v LookupOperationsInsightsWarehouseResult) string { return v.TimeLastWalletRotated }).(pulumi.StringOutput)
}

// The time at which the resource was last updated. An RFC3339 formatted datetime string
func (o LookupOperationsInsightsWarehouseResultOutput) TimeUpdated() pulumi.StringOutput {
	return o.ApplyT(func(v LookupOperationsInsightsWarehouseResult) string { return v.TimeUpdated }).(pulumi.StringOutput)
}

func init() {
	pulumi.RegisterOutputType(LookupOperationsInsightsWarehouseResultOutput{})
}
