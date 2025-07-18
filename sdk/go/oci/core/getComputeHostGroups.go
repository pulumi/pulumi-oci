// Code generated by pulumi-language-go DO NOT EDIT.
// *** WARNING: Do not edit by hand unless you're certain you know what you are doing! ***

package core

import (
	"context"
	"reflect"

	"github.com/pulumi/pulumi-oci/sdk/v3/go/oci/internal"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This data source provides the list of Compute Host Groups in Oracle Cloud Infrastructure Core service.
//
// Lists the compute host groups that match the specified criteria and compartment.
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
//			_, err := core.GetComputeHostGroups(ctx, &core.GetComputeHostGroupsArgs{
//				CompartmentId: compartmentId,
//			}, nil)
//			if err != nil {
//				return err
//			}
//			return nil
//		})
//	}
//
// ```
func GetComputeHostGroups(ctx *pulumi.Context, args *GetComputeHostGroupsArgs, opts ...pulumi.InvokeOption) (*GetComputeHostGroupsResult, error) {
	opts = internal.PkgInvokeDefaultOpts(opts)
	var rv GetComputeHostGroupsResult
	err := ctx.Invoke("oci:Core/getComputeHostGroups:getComputeHostGroups", args, &rv, opts...)
	if err != nil {
		return nil, err
	}
	return &rv, nil
}

// A collection of arguments for invoking getComputeHostGroups.
type GetComputeHostGroupsArgs struct {
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
	CompartmentId string                       `pulumi:"compartmentId"`
	Filters       []GetComputeHostGroupsFilter `pulumi:"filters"`
}

// A collection of values returned by getComputeHostGroups.
type GetComputeHostGroupsResult struct {
	// The OCID of the compartment that contains host group.
	CompartmentId string `pulumi:"compartmentId"`
	// The list of compute_host_group_collection.
	ComputeHostGroupCollections []GetComputeHostGroupsComputeHostGroupCollection `pulumi:"computeHostGroupCollections"`
	Filters                     []GetComputeHostGroupsFilter                     `pulumi:"filters"`
	// The provider-assigned unique ID for this managed resource.
	Id string `pulumi:"id"`
}

func GetComputeHostGroupsOutput(ctx *pulumi.Context, args GetComputeHostGroupsOutputArgs, opts ...pulumi.InvokeOption) GetComputeHostGroupsResultOutput {
	return pulumi.ToOutputWithContext(ctx.Context(), args).
		ApplyT(func(v interface{}) (GetComputeHostGroupsResultOutput, error) {
			args := v.(GetComputeHostGroupsArgs)
			options := pulumi.InvokeOutputOptions{InvokeOptions: internal.PkgInvokeDefaultOpts(opts)}
			return ctx.InvokeOutput("oci:Core/getComputeHostGroups:getComputeHostGroups", args, GetComputeHostGroupsResultOutput{}, options).(GetComputeHostGroupsResultOutput), nil
		}).(GetComputeHostGroupsResultOutput)
}

// A collection of arguments for invoking getComputeHostGroups.
type GetComputeHostGroupsOutputArgs struct {
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
	CompartmentId pulumi.StringInput                   `pulumi:"compartmentId"`
	Filters       GetComputeHostGroupsFilterArrayInput `pulumi:"filters"`
}

func (GetComputeHostGroupsOutputArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*GetComputeHostGroupsArgs)(nil)).Elem()
}

// A collection of values returned by getComputeHostGroups.
type GetComputeHostGroupsResultOutput struct{ *pulumi.OutputState }

func (GetComputeHostGroupsResultOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*GetComputeHostGroupsResult)(nil)).Elem()
}

func (o GetComputeHostGroupsResultOutput) ToGetComputeHostGroupsResultOutput() GetComputeHostGroupsResultOutput {
	return o
}

func (o GetComputeHostGroupsResultOutput) ToGetComputeHostGroupsResultOutputWithContext(ctx context.Context) GetComputeHostGroupsResultOutput {
	return o
}

// The OCID of the compartment that contains host group.
func (o GetComputeHostGroupsResultOutput) CompartmentId() pulumi.StringOutput {
	return o.ApplyT(func(v GetComputeHostGroupsResult) string { return v.CompartmentId }).(pulumi.StringOutput)
}

// The list of compute_host_group_collection.
func (o GetComputeHostGroupsResultOutput) ComputeHostGroupCollections() GetComputeHostGroupsComputeHostGroupCollectionArrayOutput {
	return o.ApplyT(func(v GetComputeHostGroupsResult) []GetComputeHostGroupsComputeHostGroupCollection {
		return v.ComputeHostGroupCollections
	}).(GetComputeHostGroupsComputeHostGroupCollectionArrayOutput)
}

func (o GetComputeHostGroupsResultOutput) Filters() GetComputeHostGroupsFilterArrayOutput {
	return o.ApplyT(func(v GetComputeHostGroupsResult) []GetComputeHostGroupsFilter { return v.Filters }).(GetComputeHostGroupsFilterArrayOutput)
}

// The provider-assigned unique ID for this managed resource.
func (o GetComputeHostGroupsResultOutput) Id() pulumi.StringOutput {
	return o.ApplyT(func(v GetComputeHostGroupsResult) string { return v.Id }).(pulumi.StringOutput)
}

func init() {
	pulumi.RegisterOutputType(GetComputeHostGroupsResultOutput{})
}
