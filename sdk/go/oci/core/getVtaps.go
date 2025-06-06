// Code generated by pulumi-language-go DO NOT EDIT.
// *** WARNING: Do not edit by hand unless you're certain you know what you are doing! ***

package core

import (
	"context"
	"reflect"

	"github.com/pulumi/pulumi-oci/sdk/v3/go/oci/internal"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This data source provides the list of Vtaps in Oracle Cloud Infrastructure Core service.
//
// Lists the virtual test access points (VTAPs) in the specified compartment.
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
//			_, err := core.GetVtaps(ctx, &core.GetVtapsArgs{
//				CompartmentId: compartmentId,
//				DisplayName:   pulumi.StringRef(vtapDisplayName),
//				IsVtapEnabled: pulumi.BoolRef(vtapIsVtapEnabled),
//				Source:        pulumi.StringRef(vtapSource),
//				State:         pulumi.StringRef(vtapState),
//				TargetId:      pulumi.StringRef(testTarget.Id),
//				TargetIp:      pulumi.StringRef(vtapTargetIp),
//				VcnId:         pulumi.StringRef(testVcn.Id),
//			}, nil)
//			if err != nil {
//				return err
//			}
//			return nil
//		})
//	}
//
// ```
func GetVtaps(ctx *pulumi.Context, args *GetVtapsArgs, opts ...pulumi.InvokeOption) (*GetVtapsResult, error) {
	opts = internal.PkgInvokeDefaultOpts(opts)
	var rv GetVtapsResult
	err := ctx.Invoke("oci:Core/getVtaps:getVtaps", args, &rv, opts...)
	if err != nil {
		return nil, err
	}
	return &rv, nil
}

// A collection of arguments for invoking getVtaps.
type GetVtapsArgs struct {
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
	CompartmentId string `pulumi:"compartmentId"`
	// A filter to return only resources that match the given display name exactly.
	DisplayName *string          `pulumi:"displayName"`
	Filters     []GetVtapsFilter `pulumi:"filters"`
	// Indicates whether to list all VTAPs or only running VTAPs.
	// * When `FALSE`, lists ALL running and stopped VTAPs.
	// * When `TRUE`, lists only running VTAPs (VTAPs where isVtapEnabled = `TRUE`).
	IsVtapEnabled *bool `pulumi:"isVtapEnabled"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the VTAP source.
	Source *string `pulumi:"source"`
	// A filter to return only resources that match the given VTAP administrative lifecycle state. The state value is case-insensitive.
	State *string `pulumi:"state"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the VTAP target.
	TargetId *string `pulumi:"targetId"`
	// The IP address of the VTAP target.
	TargetIp *string `pulumi:"targetIp"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the VCN.
	VcnId *string `pulumi:"vcnId"`
}

// A collection of values returned by getVtaps.
type GetVtapsResult struct {
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment containing the `Vtap` resource.
	CompartmentId string `pulumi:"compartmentId"`
	// A user-friendly name. Does not have to be unique, and it's changeable. Avoid entering confidential information.
	DisplayName *string          `pulumi:"displayName"`
	Filters     []GetVtapsFilter `pulumi:"filters"`
	// The provider-assigned unique ID for this managed resource.
	Id string `pulumi:"id"`
	// Used to start or stop a `Vtap` resource.
	// * `TRUE` directs the VTAP to start mirroring traffic.
	// * `FALSE` (Default) directs the VTAP to stop mirroring traffic.
	IsVtapEnabled *bool   `pulumi:"isVtapEnabled"`
	Source        *string `pulumi:"source"`
	// The VTAP's administrative lifecycle state.
	State *string `pulumi:"state"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the destination resource where mirrored packets are sent.
	TargetId *string `pulumi:"targetId"`
	// The IP address of the destination resource where mirrored packets are sent.
	TargetIp *string `pulumi:"targetIp"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the VCN containing the `Vtap` resource.
	VcnId *string `pulumi:"vcnId"`
	// The list of vtaps.
	Vtaps []GetVtapsVtap `pulumi:"vtaps"`
}

func GetVtapsOutput(ctx *pulumi.Context, args GetVtapsOutputArgs, opts ...pulumi.InvokeOption) GetVtapsResultOutput {
	return pulumi.ToOutputWithContext(ctx.Context(), args).
		ApplyT(func(v interface{}) (GetVtapsResultOutput, error) {
			args := v.(GetVtapsArgs)
			options := pulumi.InvokeOutputOptions{InvokeOptions: internal.PkgInvokeDefaultOpts(opts)}
			return ctx.InvokeOutput("oci:Core/getVtaps:getVtaps", args, GetVtapsResultOutput{}, options).(GetVtapsResultOutput), nil
		}).(GetVtapsResultOutput)
}

// A collection of arguments for invoking getVtaps.
type GetVtapsOutputArgs struct {
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
	CompartmentId pulumi.StringInput `pulumi:"compartmentId"`
	// A filter to return only resources that match the given display name exactly.
	DisplayName pulumi.StringPtrInput    `pulumi:"displayName"`
	Filters     GetVtapsFilterArrayInput `pulumi:"filters"`
	// Indicates whether to list all VTAPs or only running VTAPs.
	// * When `FALSE`, lists ALL running and stopped VTAPs.
	// * When `TRUE`, lists only running VTAPs (VTAPs where isVtapEnabled = `TRUE`).
	IsVtapEnabled pulumi.BoolPtrInput `pulumi:"isVtapEnabled"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the VTAP source.
	Source pulumi.StringPtrInput `pulumi:"source"`
	// A filter to return only resources that match the given VTAP administrative lifecycle state. The state value is case-insensitive.
	State pulumi.StringPtrInput `pulumi:"state"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the VTAP target.
	TargetId pulumi.StringPtrInput `pulumi:"targetId"`
	// The IP address of the VTAP target.
	TargetIp pulumi.StringPtrInput `pulumi:"targetIp"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the VCN.
	VcnId pulumi.StringPtrInput `pulumi:"vcnId"`
}

func (GetVtapsOutputArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*GetVtapsArgs)(nil)).Elem()
}

// A collection of values returned by getVtaps.
type GetVtapsResultOutput struct{ *pulumi.OutputState }

func (GetVtapsResultOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*GetVtapsResult)(nil)).Elem()
}

func (o GetVtapsResultOutput) ToGetVtapsResultOutput() GetVtapsResultOutput {
	return o
}

func (o GetVtapsResultOutput) ToGetVtapsResultOutputWithContext(ctx context.Context) GetVtapsResultOutput {
	return o
}

// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment containing the `Vtap` resource.
func (o GetVtapsResultOutput) CompartmentId() pulumi.StringOutput {
	return o.ApplyT(func(v GetVtapsResult) string { return v.CompartmentId }).(pulumi.StringOutput)
}

// A user-friendly name. Does not have to be unique, and it's changeable. Avoid entering confidential information.
func (o GetVtapsResultOutput) DisplayName() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetVtapsResult) *string { return v.DisplayName }).(pulumi.StringPtrOutput)
}

func (o GetVtapsResultOutput) Filters() GetVtapsFilterArrayOutput {
	return o.ApplyT(func(v GetVtapsResult) []GetVtapsFilter { return v.Filters }).(GetVtapsFilterArrayOutput)
}

// The provider-assigned unique ID for this managed resource.
func (o GetVtapsResultOutput) Id() pulumi.StringOutput {
	return o.ApplyT(func(v GetVtapsResult) string { return v.Id }).(pulumi.StringOutput)
}

// Used to start or stop a `Vtap` resource.
// * `TRUE` directs the VTAP to start mirroring traffic.
// * `FALSE` (Default) directs the VTAP to stop mirroring traffic.
func (o GetVtapsResultOutput) IsVtapEnabled() pulumi.BoolPtrOutput {
	return o.ApplyT(func(v GetVtapsResult) *bool { return v.IsVtapEnabled }).(pulumi.BoolPtrOutput)
}

func (o GetVtapsResultOutput) Source() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetVtapsResult) *string { return v.Source }).(pulumi.StringPtrOutput)
}

// The VTAP's administrative lifecycle state.
func (o GetVtapsResultOutput) State() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetVtapsResult) *string { return v.State }).(pulumi.StringPtrOutput)
}

// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the destination resource where mirrored packets are sent.
func (o GetVtapsResultOutput) TargetId() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetVtapsResult) *string { return v.TargetId }).(pulumi.StringPtrOutput)
}

// The IP address of the destination resource where mirrored packets are sent.
func (o GetVtapsResultOutput) TargetIp() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetVtapsResult) *string { return v.TargetIp }).(pulumi.StringPtrOutput)
}

// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the VCN containing the `Vtap` resource.
func (o GetVtapsResultOutput) VcnId() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetVtapsResult) *string { return v.VcnId }).(pulumi.StringPtrOutput)
}

// The list of vtaps.
func (o GetVtapsResultOutput) Vtaps() GetVtapsVtapArrayOutput {
	return o.ApplyT(func(v GetVtapsResult) []GetVtapsVtap { return v.Vtaps }).(GetVtapsVtapArrayOutput)
}

func init() {
	pulumi.RegisterOutputType(GetVtapsResultOutput{})
}
