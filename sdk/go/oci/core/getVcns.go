// Code generated by the Pulumi Terraform Bridge (tfgen) Tool DO NOT EDIT.
// *** WARNING: Do not edit by hand unless you're certain you know what you are doing! ***

package core

import (
	"context"
	"reflect"

	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This data source provides the list of Vcns in Oracle Cloud Infrastructure Core service.
//
// Lists the virtual cloud networks (VCNs) in the specified compartment.
//
// ## Supported Aliases
//
// * `Core.getVirtualNetworks`
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
//			_, err := Core.GetVcns(ctx, &core.GetVcnsArgs{
//				CompartmentId: _var.Compartment_id,
//				DisplayName:   pulumi.StringRef(_var.Vcn_display_name),
//				State:         pulumi.StringRef(_var.Vcn_state),
//			}, nil)
//			if err != nil {
//				return err
//			}
//			return nil
//		})
//	}
//
// ```
func GetVcns(ctx *pulumi.Context, args *GetVcnsArgs, opts ...pulumi.InvokeOption) (*GetVcnsResult, error) {
	var rv GetVcnsResult
	err := ctx.Invoke("oci:Core/getVcns:getVcns", args, &rv, opts...)
	if err != nil {
		return nil, err
	}
	return &rv, nil
}

// A collection of arguments for invoking getVcns.
type GetVcnsArgs struct {
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
	CompartmentId string `pulumi:"compartmentId"`
	// A filter to return only resources that match the given display name exactly.
	DisplayName *string         `pulumi:"displayName"`
	Filters     []GetVcnsFilter `pulumi:"filters"`
	// A filter to only return resources that match the given lifecycle state. The state value is case-insensitive.
	State *string `pulumi:"state"`
}

// A collection of values returned by getVcns.
type GetVcnsResult struct {
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment containing the VCN.
	CompartmentId string `pulumi:"compartmentId"`
	// A user-friendly name. Does not have to be unique, and it's changeable. Avoid entering confidential information.
	DisplayName *string         `pulumi:"displayName"`
	Filters     []GetVcnsFilter `pulumi:"filters"`
	// The provider-assigned unique ID for this managed resource.
	Id string `pulumi:"id"`
	// The VCN's current state.
	State *string `pulumi:"state"`
	// The list of virtual_networks.
	VirtualNetworks []GetVcnsVirtualNetwork `pulumi:"virtualNetworks"`
}

func GetVcnsOutput(ctx *pulumi.Context, args GetVcnsOutputArgs, opts ...pulumi.InvokeOption) GetVcnsResultOutput {
	return pulumi.ToOutputWithContext(context.Background(), args).
		ApplyT(func(v interface{}) (GetVcnsResult, error) {
			args := v.(GetVcnsArgs)
			r, err := GetVcns(ctx, &args, opts...)
			var s GetVcnsResult
			if r != nil {
				s = *r
			}
			return s, err
		}).(GetVcnsResultOutput)
}

// A collection of arguments for invoking getVcns.
type GetVcnsOutputArgs struct {
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
	CompartmentId pulumi.StringInput `pulumi:"compartmentId"`
	// A filter to return only resources that match the given display name exactly.
	DisplayName pulumi.StringPtrInput   `pulumi:"displayName"`
	Filters     GetVcnsFilterArrayInput `pulumi:"filters"`
	// A filter to only return resources that match the given lifecycle state. The state value is case-insensitive.
	State pulumi.StringPtrInput `pulumi:"state"`
}

func (GetVcnsOutputArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*GetVcnsArgs)(nil)).Elem()
}

// A collection of values returned by getVcns.
type GetVcnsResultOutput struct{ *pulumi.OutputState }

func (GetVcnsResultOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*GetVcnsResult)(nil)).Elem()
}

func (o GetVcnsResultOutput) ToGetVcnsResultOutput() GetVcnsResultOutput {
	return o
}

func (o GetVcnsResultOutput) ToGetVcnsResultOutputWithContext(ctx context.Context) GetVcnsResultOutput {
	return o
}

// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment containing the VCN.
func (o GetVcnsResultOutput) CompartmentId() pulumi.StringOutput {
	return o.ApplyT(func(v GetVcnsResult) string { return v.CompartmentId }).(pulumi.StringOutput)
}

// A user-friendly name. Does not have to be unique, and it's changeable. Avoid entering confidential information.
func (o GetVcnsResultOutput) DisplayName() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetVcnsResult) *string { return v.DisplayName }).(pulumi.StringPtrOutput)
}

func (o GetVcnsResultOutput) Filters() GetVcnsFilterArrayOutput {
	return o.ApplyT(func(v GetVcnsResult) []GetVcnsFilter { return v.Filters }).(GetVcnsFilterArrayOutput)
}

// The provider-assigned unique ID for this managed resource.
func (o GetVcnsResultOutput) Id() pulumi.StringOutput {
	return o.ApplyT(func(v GetVcnsResult) string { return v.Id }).(pulumi.StringOutput)
}

// The VCN's current state.
func (o GetVcnsResultOutput) State() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetVcnsResult) *string { return v.State }).(pulumi.StringPtrOutput)
}

// The list of virtual_networks.
func (o GetVcnsResultOutput) VirtualNetworks() GetVcnsVirtualNetworkArrayOutput {
	return o.ApplyT(func(v GetVcnsResult) []GetVcnsVirtualNetwork { return v.VirtualNetworks }).(GetVcnsVirtualNetworkArrayOutput)
}

func init() {
	pulumi.RegisterOutputType(GetVcnsResultOutput{})
}