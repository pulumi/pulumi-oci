// Code generated by pulumi-language-go DO NOT EDIT.
// *** WARNING: Do not edit by hand unless you're certain you know what you are doing! ***

package core

import (
	"context"
	"reflect"

	"github.com/pulumi/pulumi-oci/sdk/v3/go/oci/internal"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This data source provides the list of Virtual Circuits in Oracle Cloud Infrastructure Core service.
//
// Lists the virtual circuits in the specified compartment.
//
// ## Example Usage
//
// ```go
// package main
//
// import (
//
//	"github.com/pulumi/pulumi-oci/sdk/v3/go/oci/core"
//	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
//
// )
//
//	func main() {
//		pulumi.Run(func(ctx *pulumi.Context) error {
//			_, err := core.GetVirtualCircuits(ctx, &core.GetVirtualCircuitsArgs{
//				CompartmentId: compartmentId,
//				DisplayName:   pulumi.StringRef(virtualCircuitDisplayName),
//				State:         pulumi.StringRef(virtualCircuitState),
//			}, nil)
//			if err != nil {
//				return err
//			}
//			return nil
//		})
//	}
//
// ```
func GetVirtualCircuits(ctx *pulumi.Context, args *GetVirtualCircuitsArgs, opts ...pulumi.InvokeOption) (*GetVirtualCircuitsResult, error) {
	opts = internal.PkgInvokeDefaultOpts(opts)
	var rv GetVirtualCircuitsResult
	err := ctx.Invoke("oci:Core/getVirtualCircuits:getVirtualCircuits", args, &rv, opts...)
	if err != nil {
		return nil, err
	}
	return &rv, nil
}

// A collection of arguments for invoking getVirtualCircuits.
type GetVirtualCircuitsArgs struct {
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
	CompartmentId string `pulumi:"compartmentId"`
	// A filter to return only resources that match the given display name exactly.
	DisplayName *string                    `pulumi:"displayName"`
	Filters     []GetVirtualCircuitsFilter `pulumi:"filters"`
	// A filter to return only resources that match the specified lifecycle state. The value is case insensitive.
	State *string `pulumi:"state"`
}

// A collection of values returned by getVirtualCircuits.
type GetVirtualCircuitsResult struct {
	// The OCID of the compartment containing the virtual circuit.
	CompartmentId string `pulumi:"compartmentId"`
	// A user-friendly name. Does not have to be unique, and it's changeable. Avoid entering confidential information.
	DisplayName *string                    `pulumi:"displayName"`
	Filters     []GetVirtualCircuitsFilter `pulumi:"filters"`
	// The provider-assigned unique ID for this managed resource.
	Id string `pulumi:"id"`
	// The virtual circuit's current state. For information about the different states, see [FastConnect Overview](https://docs.cloud.oracle.com/iaas/Content/Network/Concepts/fastconnect.htm).
	State *string `pulumi:"state"`
	// The list of virtual_circuits.
	VirtualCircuits []GetVirtualCircuitsVirtualCircuit `pulumi:"virtualCircuits"`
}

func GetVirtualCircuitsOutput(ctx *pulumi.Context, args GetVirtualCircuitsOutputArgs, opts ...pulumi.InvokeOption) GetVirtualCircuitsResultOutput {
	return pulumi.ToOutputWithContext(ctx.Context(), args).
		ApplyT(func(v interface{}) (GetVirtualCircuitsResultOutput, error) {
			args := v.(GetVirtualCircuitsArgs)
			options := pulumi.InvokeOutputOptions{InvokeOptions: internal.PkgInvokeDefaultOpts(opts)}
			return ctx.InvokeOutput("oci:Core/getVirtualCircuits:getVirtualCircuits", args, GetVirtualCircuitsResultOutput{}, options).(GetVirtualCircuitsResultOutput), nil
		}).(GetVirtualCircuitsResultOutput)
}

// A collection of arguments for invoking getVirtualCircuits.
type GetVirtualCircuitsOutputArgs struct {
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
	CompartmentId pulumi.StringInput `pulumi:"compartmentId"`
	// A filter to return only resources that match the given display name exactly.
	DisplayName pulumi.StringPtrInput              `pulumi:"displayName"`
	Filters     GetVirtualCircuitsFilterArrayInput `pulumi:"filters"`
	// A filter to return only resources that match the specified lifecycle state. The value is case insensitive.
	State pulumi.StringPtrInput `pulumi:"state"`
}

func (GetVirtualCircuitsOutputArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*GetVirtualCircuitsArgs)(nil)).Elem()
}

// A collection of values returned by getVirtualCircuits.
type GetVirtualCircuitsResultOutput struct{ *pulumi.OutputState }

func (GetVirtualCircuitsResultOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*GetVirtualCircuitsResult)(nil)).Elem()
}

func (o GetVirtualCircuitsResultOutput) ToGetVirtualCircuitsResultOutput() GetVirtualCircuitsResultOutput {
	return o
}

func (o GetVirtualCircuitsResultOutput) ToGetVirtualCircuitsResultOutputWithContext(ctx context.Context) GetVirtualCircuitsResultOutput {
	return o
}

// The OCID of the compartment containing the virtual circuit.
func (o GetVirtualCircuitsResultOutput) CompartmentId() pulumi.StringOutput {
	return o.ApplyT(func(v GetVirtualCircuitsResult) string { return v.CompartmentId }).(pulumi.StringOutput)
}

// A user-friendly name. Does not have to be unique, and it's changeable. Avoid entering confidential information.
func (o GetVirtualCircuitsResultOutput) DisplayName() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetVirtualCircuitsResult) *string { return v.DisplayName }).(pulumi.StringPtrOutput)
}

func (o GetVirtualCircuitsResultOutput) Filters() GetVirtualCircuitsFilterArrayOutput {
	return o.ApplyT(func(v GetVirtualCircuitsResult) []GetVirtualCircuitsFilter { return v.Filters }).(GetVirtualCircuitsFilterArrayOutput)
}

// The provider-assigned unique ID for this managed resource.
func (o GetVirtualCircuitsResultOutput) Id() pulumi.StringOutput {
	return o.ApplyT(func(v GetVirtualCircuitsResult) string { return v.Id }).(pulumi.StringOutput)
}

// The virtual circuit's current state. For information about the different states, see [FastConnect Overview](https://docs.cloud.oracle.com/iaas/Content/Network/Concepts/fastconnect.htm).
func (o GetVirtualCircuitsResultOutput) State() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetVirtualCircuitsResult) *string { return v.State }).(pulumi.StringPtrOutput)
}

// The list of virtual_circuits.
func (o GetVirtualCircuitsResultOutput) VirtualCircuits() GetVirtualCircuitsVirtualCircuitArrayOutput {
	return o.ApplyT(func(v GetVirtualCircuitsResult) []GetVirtualCircuitsVirtualCircuit { return v.VirtualCircuits }).(GetVirtualCircuitsVirtualCircuitArrayOutput)
}

func init() {
	pulumi.RegisterOutputType(GetVirtualCircuitsResultOutput{})
}
