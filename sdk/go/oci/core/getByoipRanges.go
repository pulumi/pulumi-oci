// Code generated by pulumi-language-go DO NOT EDIT.
// *** WARNING: Do not edit by hand unless you're certain you know what you are doing! ***

package core

import (
	"context"
	"reflect"

	"github.com/pulumi/pulumi-oci/sdk/v3/go/oci/internal"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This data source provides the list of Byoip Ranges in Oracle Cloud Infrastructure Core service.
//
// Lists the `ByoipRange` resources in the specified compartment.
// You can filter the list using query parameters.
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
//			_, err := core.GetByoipRanges(ctx, &core.GetByoipRangesArgs{
//				CompartmentId: compartmentId,
//				DisplayName:   pulumi.StringRef(byoipRangeDisplayName),
//				State:         pulumi.StringRef(byoipRangeState),
//			}, nil)
//			if err != nil {
//				return err
//			}
//			return nil
//		})
//	}
//
// ```
func GetByoipRanges(ctx *pulumi.Context, args *GetByoipRangesArgs, opts ...pulumi.InvokeOption) (*GetByoipRangesResult, error) {
	opts = internal.PkgInvokeDefaultOpts(opts)
	var rv GetByoipRangesResult
	err := ctx.Invoke("oci:Core/getByoipRanges:getByoipRanges", args, &rv, opts...)
	if err != nil {
		return nil, err
	}
	return &rv, nil
}

// A collection of arguments for invoking getByoipRanges.
type GetByoipRangesArgs struct {
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
	CompartmentId string `pulumi:"compartmentId"`
	// A filter to return only resources that match the given display name exactly.
	DisplayName *string                `pulumi:"displayName"`
	Filters     []GetByoipRangesFilter `pulumi:"filters"`
	// A filter to return only resources that match the given lifecycle state name exactly.
	State *string `pulumi:"state"`
}

// A collection of values returned by getByoipRanges.
type GetByoipRangesResult struct {
	// The list of byoip_range_collection.
	ByoipRangeCollections []GetByoipRangesByoipRangeCollection `pulumi:"byoipRangeCollections"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment containing the BYOIP CIDR block.
	CompartmentId string `pulumi:"compartmentId"`
	// A user-friendly name. Does not have to be unique, and it's changeable. Avoid entering confidential information.
	DisplayName *string                `pulumi:"displayName"`
	Filters     []GetByoipRangesFilter `pulumi:"filters"`
	// The provider-assigned unique ID for this managed resource.
	Id string `pulumi:"id"`
	// The `ByoipRange` resource's current state.
	State *string `pulumi:"state"`
}

func GetByoipRangesOutput(ctx *pulumi.Context, args GetByoipRangesOutputArgs, opts ...pulumi.InvokeOption) GetByoipRangesResultOutput {
	return pulumi.ToOutputWithContext(ctx.Context(), args).
		ApplyT(func(v interface{}) (GetByoipRangesResultOutput, error) {
			args := v.(GetByoipRangesArgs)
			options := pulumi.InvokeOutputOptions{InvokeOptions: internal.PkgInvokeDefaultOpts(opts)}
			return ctx.InvokeOutput("oci:Core/getByoipRanges:getByoipRanges", args, GetByoipRangesResultOutput{}, options).(GetByoipRangesResultOutput), nil
		}).(GetByoipRangesResultOutput)
}

// A collection of arguments for invoking getByoipRanges.
type GetByoipRangesOutputArgs struct {
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
	CompartmentId pulumi.StringInput `pulumi:"compartmentId"`
	// A filter to return only resources that match the given display name exactly.
	DisplayName pulumi.StringPtrInput          `pulumi:"displayName"`
	Filters     GetByoipRangesFilterArrayInput `pulumi:"filters"`
	// A filter to return only resources that match the given lifecycle state name exactly.
	State pulumi.StringPtrInput `pulumi:"state"`
}

func (GetByoipRangesOutputArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*GetByoipRangesArgs)(nil)).Elem()
}

// A collection of values returned by getByoipRanges.
type GetByoipRangesResultOutput struct{ *pulumi.OutputState }

func (GetByoipRangesResultOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*GetByoipRangesResult)(nil)).Elem()
}

func (o GetByoipRangesResultOutput) ToGetByoipRangesResultOutput() GetByoipRangesResultOutput {
	return o
}

func (o GetByoipRangesResultOutput) ToGetByoipRangesResultOutputWithContext(ctx context.Context) GetByoipRangesResultOutput {
	return o
}

// The list of byoip_range_collection.
func (o GetByoipRangesResultOutput) ByoipRangeCollections() GetByoipRangesByoipRangeCollectionArrayOutput {
	return o.ApplyT(func(v GetByoipRangesResult) []GetByoipRangesByoipRangeCollection { return v.ByoipRangeCollections }).(GetByoipRangesByoipRangeCollectionArrayOutput)
}

// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment containing the BYOIP CIDR block.
func (o GetByoipRangesResultOutput) CompartmentId() pulumi.StringOutput {
	return o.ApplyT(func(v GetByoipRangesResult) string { return v.CompartmentId }).(pulumi.StringOutput)
}

// A user-friendly name. Does not have to be unique, and it's changeable. Avoid entering confidential information.
func (o GetByoipRangesResultOutput) DisplayName() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetByoipRangesResult) *string { return v.DisplayName }).(pulumi.StringPtrOutput)
}

func (o GetByoipRangesResultOutput) Filters() GetByoipRangesFilterArrayOutput {
	return o.ApplyT(func(v GetByoipRangesResult) []GetByoipRangesFilter { return v.Filters }).(GetByoipRangesFilterArrayOutput)
}

// The provider-assigned unique ID for this managed resource.
func (o GetByoipRangesResultOutput) Id() pulumi.StringOutput {
	return o.ApplyT(func(v GetByoipRangesResult) string { return v.Id }).(pulumi.StringOutput)
}

// The `ByoipRange` resource's current state.
func (o GetByoipRangesResultOutput) State() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetByoipRangesResult) *string { return v.State }).(pulumi.StringPtrOutput)
}

func init() {
	pulumi.RegisterOutputType(GetByoipRangesResultOutput{})
}
