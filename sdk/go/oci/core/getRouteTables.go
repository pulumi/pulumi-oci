// Code generated by the Pulumi Terraform Bridge (tfgen) Tool DO NOT EDIT.
// *** WARNING: Do not edit by hand unless you're certain you know what you are doing! ***

package core

import (
	"context"
	"reflect"

	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This data source provides the list of Route Tables in Oracle Cloud Infrastructure Core service.
//
// Lists the route tables in the specified VCN and specified compartment.
// If the VCN ID is not provided, then the list includes the route tables from all VCNs in the specified compartment.
// The response includes the default route table that automatically comes with
// each VCN in the specified compartment, plus any route tables you've created.
//
// ## Example Usage
//
// ```go
// package main
//
// import (
//
//	"github.com/pulumi/pulumi-oci/sdk/go/oci/Core"
//	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
//
// )
//
//	func main() {
//		pulumi.Run(func(ctx *pulumi.Context) error {
//			_, err := Core.GetRouteTables(ctx, &core.GetRouteTablesArgs{
//				CompartmentId: _var.Compartment_id,
//				DisplayName:   pulumi.StringRef(_var.Route_table_display_name),
//				State:         pulumi.StringRef(_var.Route_table_state),
//				VcnId:         pulumi.StringRef(oci_core_vcn.Test_vcn.Id),
//			}, nil)
//			if err != nil {
//				return err
//			}
//			return nil
//		})
//	}
//
// ```
func GetRouteTables(ctx *pulumi.Context, args *GetRouteTablesArgs, opts ...pulumi.InvokeOption) (*GetRouteTablesResult, error) {
	var rv GetRouteTablesResult
	err := ctx.Invoke("oci:Core/getRouteTables:getRouteTables", args, &rv, opts...)
	if err != nil {
		return nil, err
	}
	return &rv, nil
}

// A collection of arguments for invoking getRouteTables.
type GetRouteTablesArgs struct {
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
	CompartmentId string `pulumi:"compartmentId"`
	// A filter to return only resources that match the given display name exactly.
	DisplayName *string                `pulumi:"displayName"`
	Filters     []GetRouteTablesFilter `pulumi:"filters"`
	// A filter to only return resources that match the given lifecycle state. The state value is case-insensitive.
	State *string `pulumi:"state"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the VCN.
	VcnId *string `pulumi:"vcnId"`
}

// A collection of values returned by getRouteTables.
type GetRouteTablesResult struct {
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment containing the route table.
	CompartmentId string `pulumi:"compartmentId"`
	// A user-friendly name. Does not have to be unique, and it's changeable. Avoid entering confidential information.
	DisplayName *string                `pulumi:"displayName"`
	Filters     []GetRouteTablesFilter `pulumi:"filters"`
	// The provider-assigned unique ID for this managed resource.
	Id string `pulumi:"id"`
	// The list of route_tables.
	RouteTables []GetRouteTablesRouteTable `pulumi:"routeTables"`
	// The route table's current state.
	State *string `pulumi:"state"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the VCN the route table list belongs to.
	VcnId *string `pulumi:"vcnId"`
}

func GetRouteTablesOutput(ctx *pulumi.Context, args GetRouteTablesOutputArgs, opts ...pulumi.InvokeOption) GetRouteTablesResultOutput {
	return pulumi.ToOutputWithContext(context.Background(), args).
		ApplyT(func(v interface{}) (GetRouteTablesResult, error) {
			args := v.(GetRouteTablesArgs)
			r, err := GetRouteTables(ctx, &args, opts...)
			var s GetRouteTablesResult
			if r != nil {
				s = *r
			}
			return s, err
		}).(GetRouteTablesResultOutput)
}

// A collection of arguments for invoking getRouteTables.
type GetRouteTablesOutputArgs struct {
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
	CompartmentId pulumi.StringInput `pulumi:"compartmentId"`
	// A filter to return only resources that match the given display name exactly.
	DisplayName pulumi.StringPtrInput          `pulumi:"displayName"`
	Filters     GetRouteTablesFilterArrayInput `pulumi:"filters"`
	// A filter to only return resources that match the given lifecycle state. The state value is case-insensitive.
	State pulumi.StringPtrInput `pulumi:"state"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the VCN.
	VcnId pulumi.StringPtrInput `pulumi:"vcnId"`
}

func (GetRouteTablesOutputArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*GetRouteTablesArgs)(nil)).Elem()
}

// A collection of values returned by getRouteTables.
type GetRouteTablesResultOutput struct{ *pulumi.OutputState }

func (GetRouteTablesResultOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*GetRouteTablesResult)(nil)).Elem()
}

func (o GetRouteTablesResultOutput) ToGetRouteTablesResultOutput() GetRouteTablesResultOutput {
	return o
}

func (o GetRouteTablesResultOutput) ToGetRouteTablesResultOutputWithContext(ctx context.Context) GetRouteTablesResultOutput {
	return o
}

// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment containing the route table.
func (o GetRouteTablesResultOutput) CompartmentId() pulumi.StringOutput {
	return o.ApplyT(func(v GetRouteTablesResult) string { return v.CompartmentId }).(pulumi.StringOutput)
}

// A user-friendly name. Does not have to be unique, and it's changeable. Avoid entering confidential information.
func (o GetRouteTablesResultOutput) DisplayName() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetRouteTablesResult) *string { return v.DisplayName }).(pulumi.StringPtrOutput)
}

func (o GetRouteTablesResultOutput) Filters() GetRouteTablesFilterArrayOutput {
	return o.ApplyT(func(v GetRouteTablesResult) []GetRouteTablesFilter { return v.Filters }).(GetRouteTablesFilterArrayOutput)
}

// The provider-assigned unique ID for this managed resource.
func (o GetRouteTablesResultOutput) Id() pulumi.StringOutput {
	return o.ApplyT(func(v GetRouteTablesResult) string { return v.Id }).(pulumi.StringOutput)
}

// The list of route_tables.
func (o GetRouteTablesResultOutput) RouteTables() GetRouteTablesRouteTableArrayOutput {
	return o.ApplyT(func(v GetRouteTablesResult) []GetRouteTablesRouteTable { return v.RouteTables }).(GetRouteTablesRouteTableArrayOutput)
}

// The route table's current state.
func (o GetRouteTablesResultOutput) State() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetRouteTablesResult) *string { return v.State }).(pulumi.StringPtrOutput)
}

// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the VCN the route table list belongs to.
func (o GetRouteTablesResultOutput) VcnId() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetRouteTablesResult) *string { return v.VcnId }).(pulumi.StringPtrOutput)
}

func init() {
	pulumi.RegisterOutputType(GetRouteTablesResultOutput{})
}