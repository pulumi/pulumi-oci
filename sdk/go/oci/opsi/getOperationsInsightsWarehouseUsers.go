// Code generated by the Pulumi Terraform Bridge (tfgen) Tool DO NOT EDIT.
// *** WARNING: Do not edit by hand unless you're certain you know what you are doing! ***

package opsi

import (
	"context"
	"reflect"

	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This data source provides the list of Operations Insights Warehouse Users in Oracle Cloud Infrastructure Opsi service.
//
// Gets a list of Operations Insights Warehouse users. Either compartmentId or id must be specified. All these resources are expected to be in root compartment.
//
// ## Example Usage
//
// ```go
// package main
//
// import (
//
//	"github.com/pulumi/pulumi-oci/sdk/go/oci/Opsi"
//	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
//
// )
//
//	func main() {
//		pulumi.Run(func(ctx *pulumi.Context) error {
//			_, err := Opsi.GetOperationsInsightsWarehouseUsers(ctx, &opsi.GetOperationsInsightsWarehouseUsersArgs{
//				OperationsInsightsWarehouseId: oci_opsi_operations_insights_warehouse.Test_operations_insights_warehouse.Id,
//				CompartmentId:                 pulumi.StringRef(_var.Compartment_id),
//				DisplayName:                   pulumi.StringRef(_var.Operations_insights_warehouse_user_display_name),
//				Id:                            pulumi.StringRef(_var.Operations_insights_warehouse_user_id),
//				States:                        _var.Operations_insights_warehouse_user_state,
//			}, nil)
//			if err != nil {
//				return err
//			}
//			return nil
//		})
//	}
//
// ```
func GetOperationsInsightsWarehouseUsers(ctx *pulumi.Context, args *GetOperationsInsightsWarehouseUsersArgs, opts ...pulumi.InvokeOption) (*GetOperationsInsightsWarehouseUsersResult, error) {
	var rv GetOperationsInsightsWarehouseUsersResult
	err := ctx.Invoke("oci:Opsi/getOperationsInsightsWarehouseUsers:getOperationsInsightsWarehouseUsers", args, &rv, opts...)
	if err != nil {
		return nil, err
	}
	return &rv, nil
}

// A collection of arguments for invoking getOperationsInsightsWarehouseUsers.
type GetOperationsInsightsWarehouseUsersArgs struct {
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
	CompartmentId *string `pulumi:"compartmentId"`
	// A filter to return only resources that match the entire display name.
	DisplayName *string                                     `pulumi:"displayName"`
	Filters     []GetOperationsInsightsWarehouseUsersFilter `pulumi:"filters"`
	// Unique Operations Insights Warehouse User identifier
	Id *string `pulumi:"id"`
	// Unique Operations Insights Warehouse identifier
	OperationsInsightsWarehouseId string `pulumi:"operationsInsightsWarehouseId"`
	// Lifecycle states
	States []string `pulumi:"states"`
}

// A collection of values returned by getOperationsInsightsWarehouseUsers.
type GetOperationsInsightsWarehouseUsersResult struct {
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
	CompartmentId *string                                     `pulumi:"compartmentId"`
	DisplayName   *string                                     `pulumi:"displayName"`
	Filters       []GetOperationsInsightsWarehouseUsersFilter `pulumi:"filters"`
	// Hub User OCID
	Id *string `pulumi:"id"`
	// OPSI Warehouse OCID
	OperationsInsightsWarehouseId string `pulumi:"operationsInsightsWarehouseId"`
	// The list of operations_insights_warehouse_user_summary_collection.
	OperationsInsightsWarehouseUserSummaryCollections []GetOperationsInsightsWarehouseUsersOperationsInsightsWarehouseUserSummaryCollection `pulumi:"operationsInsightsWarehouseUserSummaryCollections"`
	// Possible lifecycle states
	States []string `pulumi:"states"`
}

func GetOperationsInsightsWarehouseUsersOutput(ctx *pulumi.Context, args GetOperationsInsightsWarehouseUsersOutputArgs, opts ...pulumi.InvokeOption) GetOperationsInsightsWarehouseUsersResultOutput {
	return pulumi.ToOutputWithContext(context.Background(), args).
		ApplyT(func(v interface{}) (GetOperationsInsightsWarehouseUsersResult, error) {
			args := v.(GetOperationsInsightsWarehouseUsersArgs)
			r, err := GetOperationsInsightsWarehouseUsers(ctx, &args, opts...)
			var s GetOperationsInsightsWarehouseUsersResult
			if r != nil {
				s = *r
			}
			return s, err
		}).(GetOperationsInsightsWarehouseUsersResultOutput)
}

// A collection of arguments for invoking getOperationsInsightsWarehouseUsers.
type GetOperationsInsightsWarehouseUsersOutputArgs struct {
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
	CompartmentId pulumi.StringPtrInput `pulumi:"compartmentId"`
	// A filter to return only resources that match the entire display name.
	DisplayName pulumi.StringPtrInput                               `pulumi:"displayName"`
	Filters     GetOperationsInsightsWarehouseUsersFilterArrayInput `pulumi:"filters"`
	// Unique Operations Insights Warehouse User identifier
	Id pulumi.StringPtrInput `pulumi:"id"`
	// Unique Operations Insights Warehouse identifier
	OperationsInsightsWarehouseId pulumi.StringInput `pulumi:"operationsInsightsWarehouseId"`
	// Lifecycle states
	States pulumi.StringArrayInput `pulumi:"states"`
}

func (GetOperationsInsightsWarehouseUsersOutputArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*GetOperationsInsightsWarehouseUsersArgs)(nil)).Elem()
}

// A collection of values returned by getOperationsInsightsWarehouseUsers.
type GetOperationsInsightsWarehouseUsersResultOutput struct{ *pulumi.OutputState }

func (GetOperationsInsightsWarehouseUsersResultOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*GetOperationsInsightsWarehouseUsersResult)(nil)).Elem()
}

func (o GetOperationsInsightsWarehouseUsersResultOutput) ToGetOperationsInsightsWarehouseUsersResultOutput() GetOperationsInsightsWarehouseUsersResultOutput {
	return o
}

func (o GetOperationsInsightsWarehouseUsersResultOutput) ToGetOperationsInsightsWarehouseUsersResultOutputWithContext(ctx context.Context) GetOperationsInsightsWarehouseUsersResultOutput {
	return o
}

// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
func (o GetOperationsInsightsWarehouseUsersResultOutput) CompartmentId() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetOperationsInsightsWarehouseUsersResult) *string { return v.CompartmentId }).(pulumi.StringPtrOutput)
}

func (o GetOperationsInsightsWarehouseUsersResultOutput) DisplayName() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetOperationsInsightsWarehouseUsersResult) *string { return v.DisplayName }).(pulumi.StringPtrOutput)
}

func (o GetOperationsInsightsWarehouseUsersResultOutput) Filters() GetOperationsInsightsWarehouseUsersFilterArrayOutput {
	return o.ApplyT(func(v GetOperationsInsightsWarehouseUsersResult) []GetOperationsInsightsWarehouseUsersFilter {
		return v.Filters
	}).(GetOperationsInsightsWarehouseUsersFilterArrayOutput)
}

// Hub User OCID
func (o GetOperationsInsightsWarehouseUsersResultOutput) Id() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetOperationsInsightsWarehouseUsersResult) *string { return v.Id }).(pulumi.StringPtrOutput)
}

// OPSI Warehouse OCID
func (o GetOperationsInsightsWarehouseUsersResultOutput) OperationsInsightsWarehouseId() pulumi.StringOutput {
	return o.ApplyT(func(v GetOperationsInsightsWarehouseUsersResult) string { return v.OperationsInsightsWarehouseId }).(pulumi.StringOutput)
}

// The list of operations_insights_warehouse_user_summary_collection.
func (o GetOperationsInsightsWarehouseUsersResultOutput) OperationsInsightsWarehouseUserSummaryCollections() GetOperationsInsightsWarehouseUsersOperationsInsightsWarehouseUserSummaryCollectionArrayOutput {
	return o.ApplyT(func(v GetOperationsInsightsWarehouseUsersResult) []GetOperationsInsightsWarehouseUsersOperationsInsightsWarehouseUserSummaryCollection {
		return v.OperationsInsightsWarehouseUserSummaryCollections
	}).(GetOperationsInsightsWarehouseUsersOperationsInsightsWarehouseUserSummaryCollectionArrayOutput)
}

// Possible lifecycle states
func (o GetOperationsInsightsWarehouseUsersResultOutput) States() pulumi.StringArrayOutput {
	return o.ApplyT(func(v GetOperationsInsightsWarehouseUsersResult) []string { return v.States }).(pulumi.StringArrayOutput)
}

func init() {
	pulumi.RegisterOutputType(GetOperationsInsightsWarehouseUsersResultOutput{})
}