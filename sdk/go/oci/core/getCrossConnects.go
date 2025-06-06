// Code generated by pulumi-language-go DO NOT EDIT.
// *** WARNING: Do not edit by hand unless you're certain you know what you are doing! ***

package core

import (
	"context"
	"reflect"

	"github.com/pulumi/pulumi-oci/sdk/v3/go/oci/internal"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This data source provides the list of Cross Connects in Oracle Cloud Infrastructure Core service.
//
// Lists the cross-connects in the specified compartment. You can filter the list
// by specifying the [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of a cross-connect group.
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
//			_, err := core.GetCrossConnects(ctx, &core.GetCrossConnectsArgs{
//				CompartmentId:       compartmentId,
//				CrossConnectGroupId: pulumi.StringRef(testCrossConnectGroup.Id),
//				DisplayName:         pulumi.StringRef(crossConnectDisplayName),
//				State:               pulumi.StringRef(crossConnectState),
//			}, nil)
//			if err != nil {
//				return err
//			}
//			return nil
//		})
//	}
//
// ```
func GetCrossConnects(ctx *pulumi.Context, args *GetCrossConnectsArgs, opts ...pulumi.InvokeOption) (*GetCrossConnectsResult, error) {
	opts = internal.PkgInvokeDefaultOpts(opts)
	var rv GetCrossConnectsResult
	err := ctx.Invoke("oci:Core/getCrossConnects:getCrossConnects", args, &rv, opts...)
	if err != nil {
		return nil, err
	}
	return &rv, nil
}

// A collection of arguments for invoking getCrossConnects.
type GetCrossConnectsArgs struct {
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
	CompartmentId string `pulumi:"compartmentId"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the cross-connect group.
	CrossConnectGroupId *string `pulumi:"crossConnectGroupId"`
	// A filter to return only resources that match the given display name exactly.
	DisplayName *string                  `pulumi:"displayName"`
	Filters     []GetCrossConnectsFilter `pulumi:"filters"`
	// A filter to return only resources that match the specified lifecycle state. The value is case insensitive.
	State *string `pulumi:"state"`
}

// A collection of values returned by getCrossConnects.
type GetCrossConnectsResult struct {
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment containing the cross-connect group.
	CompartmentId string `pulumi:"compartmentId"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the cross-connect group this cross-connect belongs to (if any).
	CrossConnectGroupId *string `pulumi:"crossConnectGroupId"`
	// The list of cross_connects.
	CrossConnects []GetCrossConnectsCrossConnect `pulumi:"crossConnects"`
	// A user-friendly name. Does not have to be unique, and it's changeable. Avoid entering confidential information.
	DisplayName *string                  `pulumi:"displayName"`
	Filters     []GetCrossConnectsFilter `pulumi:"filters"`
	// The provider-assigned unique ID for this managed resource.
	Id string `pulumi:"id"`
	// The cross-connect's current state.
	State *string `pulumi:"state"`
}

func GetCrossConnectsOutput(ctx *pulumi.Context, args GetCrossConnectsOutputArgs, opts ...pulumi.InvokeOption) GetCrossConnectsResultOutput {
	return pulumi.ToOutputWithContext(ctx.Context(), args).
		ApplyT(func(v interface{}) (GetCrossConnectsResultOutput, error) {
			args := v.(GetCrossConnectsArgs)
			options := pulumi.InvokeOutputOptions{InvokeOptions: internal.PkgInvokeDefaultOpts(opts)}
			return ctx.InvokeOutput("oci:Core/getCrossConnects:getCrossConnects", args, GetCrossConnectsResultOutput{}, options).(GetCrossConnectsResultOutput), nil
		}).(GetCrossConnectsResultOutput)
}

// A collection of arguments for invoking getCrossConnects.
type GetCrossConnectsOutputArgs struct {
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
	CompartmentId pulumi.StringInput `pulumi:"compartmentId"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the cross-connect group.
	CrossConnectGroupId pulumi.StringPtrInput `pulumi:"crossConnectGroupId"`
	// A filter to return only resources that match the given display name exactly.
	DisplayName pulumi.StringPtrInput            `pulumi:"displayName"`
	Filters     GetCrossConnectsFilterArrayInput `pulumi:"filters"`
	// A filter to return only resources that match the specified lifecycle state. The value is case insensitive.
	State pulumi.StringPtrInput `pulumi:"state"`
}

func (GetCrossConnectsOutputArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*GetCrossConnectsArgs)(nil)).Elem()
}

// A collection of values returned by getCrossConnects.
type GetCrossConnectsResultOutput struct{ *pulumi.OutputState }

func (GetCrossConnectsResultOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*GetCrossConnectsResult)(nil)).Elem()
}

func (o GetCrossConnectsResultOutput) ToGetCrossConnectsResultOutput() GetCrossConnectsResultOutput {
	return o
}

func (o GetCrossConnectsResultOutput) ToGetCrossConnectsResultOutputWithContext(ctx context.Context) GetCrossConnectsResultOutput {
	return o
}

// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment containing the cross-connect group.
func (o GetCrossConnectsResultOutput) CompartmentId() pulumi.StringOutput {
	return o.ApplyT(func(v GetCrossConnectsResult) string { return v.CompartmentId }).(pulumi.StringOutput)
}

// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the cross-connect group this cross-connect belongs to (if any).
func (o GetCrossConnectsResultOutput) CrossConnectGroupId() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetCrossConnectsResult) *string { return v.CrossConnectGroupId }).(pulumi.StringPtrOutput)
}

// The list of cross_connects.
func (o GetCrossConnectsResultOutput) CrossConnects() GetCrossConnectsCrossConnectArrayOutput {
	return o.ApplyT(func(v GetCrossConnectsResult) []GetCrossConnectsCrossConnect { return v.CrossConnects }).(GetCrossConnectsCrossConnectArrayOutput)
}

// A user-friendly name. Does not have to be unique, and it's changeable. Avoid entering confidential information.
func (o GetCrossConnectsResultOutput) DisplayName() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetCrossConnectsResult) *string { return v.DisplayName }).(pulumi.StringPtrOutput)
}

func (o GetCrossConnectsResultOutput) Filters() GetCrossConnectsFilterArrayOutput {
	return o.ApplyT(func(v GetCrossConnectsResult) []GetCrossConnectsFilter { return v.Filters }).(GetCrossConnectsFilterArrayOutput)
}

// The provider-assigned unique ID for this managed resource.
func (o GetCrossConnectsResultOutput) Id() pulumi.StringOutput {
	return o.ApplyT(func(v GetCrossConnectsResult) string { return v.Id }).(pulumi.StringOutput)
}

// The cross-connect's current state.
func (o GetCrossConnectsResultOutput) State() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetCrossConnectsResult) *string { return v.State }).(pulumi.StringPtrOutput)
}

func init() {
	pulumi.RegisterOutputType(GetCrossConnectsResultOutput{})
}
