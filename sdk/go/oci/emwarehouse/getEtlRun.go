// Code generated by the Pulumi Terraform Bridge (tfgen) Tool DO NOT EDIT.
// *** WARNING: Do not edit by hand unless you're certain you know what you are doing! ***

package emwarehouse

import (
	"context"
	"reflect"

	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This data source provides details about a specific Em Warehouse Etl Run resource in Oracle Cloud Infrastructure Em Warehouse service.
//
// # Gets a list of runs of an EmWarehouseResource by identifier
//
// ## Example Usage
//
// ```go
// package main
//
// import (
//
//	"github.com/pulumi/pulumi-oci/sdk/go/oci/EmWarehouse"
//	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
//
// )
//
//	func main() {
//		pulumi.Run(func(ctx *pulumi.Context) error {
//			_, err := EmWarehouse.GetEtlRun(ctx, &emwarehouse.GetEtlRunArgs{
//				EmWarehouseId: oci_em_warehouse_em_warehouse.Test_em_warehouse.Id,
//				CompartmentId: pulumi.StringRef(_var.Compartment_id),
//				DisplayName:   pulumi.StringRef(_var.Em_warehouse_etl_run_display_name),
//			}, nil)
//			if err != nil {
//				return err
//			}
//			return nil
//		})
//	}
//
// ```
func GetEtlRun(ctx *pulumi.Context, args *GetEtlRunArgs, opts ...pulumi.InvokeOption) (*GetEtlRunResult, error) {
	var rv GetEtlRunResult
	err := ctx.Invoke("oci:EmWarehouse/getEtlRun:getEtlRun", args, &rv, opts...)
	if err != nil {
		return nil, err
	}
	return &rv, nil
}

// A collection of arguments for invoking getEtlRun.
type GetEtlRunArgs struct {
	// The ID of the compartment in which to list resources.
	CompartmentId *string `pulumi:"compartmentId"`
	// A filter to return only resources that match the entire display name given.
	DisplayName *string `pulumi:"displayName"`
	// unique EmWarehouse identifier
	EmWarehouseId string `pulumi:"emWarehouseId"`
}

// A collection of values returned by getEtlRun.
type GetEtlRunResult struct {
	// Compartment Identifier
	CompartmentId *string `pulumi:"compartmentId"`
	// The name of the ETLRun.
	DisplayName   *string `pulumi:"displayName"`
	EmWarehouseId string  `pulumi:"emWarehouseId"`
	// The provider-assigned unique ID for this managed resource.
	Id string `pulumi:"id"`
	// List of runs
	Items []GetEtlRunItem `pulumi:"items"`
}

func GetEtlRunOutput(ctx *pulumi.Context, args GetEtlRunOutputArgs, opts ...pulumi.InvokeOption) GetEtlRunResultOutput {
	return pulumi.ToOutputWithContext(context.Background(), args).
		ApplyT(func(v interface{}) (GetEtlRunResult, error) {
			args := v.(GetEtlRunArgs)
			r, err := GetEtlRun(ctx, &args, opts...)
			var s GetEtlRunResult
			if r != nil {
				s = *r
			}
			return s, err
		}).(GetEtlRunResultOutput)
}

// A collection of arguments for invoking getEtlRun.
type GetEtlRunOutputArgs struct {
	// The ID of the compartment in which to list resources.
	CompartmentId pulumi.StringPtrInput `pulumi:"compartmentId"`
	// A filter to return only resources that match the entire display name given.
	DisplayName pulumi.StringPtrInput `pulumi:"displayName"`
	// unique EmWarehouse identifier
	EmWarehouseId pulumi.StringInput `pulumi:"emWarehouseId"`
}

func (GetEtlRunOutputArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*GetEtlRunArgs)(nil)).Elem()
}

// A collection of values returned by getEtlRun.
type GetEtlRunResultOutput struct{ *pulumi.OutputState }

func (GetEtlRunResultOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*GetEtlRunResult)(nil)).Elem()
}

func (o GetEtlRunResultOutput) ToGetEtlRunResultOutput() GetEtlRunResultOutput {
	return o
}

func (o GetEtlRunResultOutput) ToGetEtlRunResultOutputWithContext(ctx context.Context) GetEtlRunResultOutput {
	return o
}

// Compartment Identifier
func (o GetEtlRunResultOutput) CompartmentId() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetEtlRunResult) *string { return v.CompartmentId }).(pulumi.StringPtrOutput)
}

// The name of the ETLRun.
func (o GetEtlRunResultOutput) DisplayName() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetEtlRunResult) *string { return v.DisplayName }).(pulumi.StringPtrOutput)
}

func (o GetEtlRunResultOutput) EmWarehouseId() pulumi.StringOutput {
	return o.ApplyT(func(v GetEtlRunResult) string { return v.EmWarehouseId }).(pulumi.StringOutput)
}

// The provider-assigned unique ID for this managed resource.
func (o GetEtlRunResultOutput) Id() pulumi.StringOutput {
	return o.ApplyT(func(v GetEtlRunResult) string { return v.Id }).(pulumi.StringOutput)
}

// List of runs
func (o GetEtlRunResultOutput) Items() GetEtlRunItemArrayOutput {
	return o.ApplyT(func(v GetEtlRunResult) []GetEtlRunItem { return v.Items }).(GetEtlRunItemArrayOutput)
}

func init() {
	pulumi.RegisterOutputType(GetEtlRunResultOutput{})
}