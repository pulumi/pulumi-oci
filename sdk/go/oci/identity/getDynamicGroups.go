// Code generated by pulumi-language-go DO NOT EDIT.
// *** WARNING: Do not edit by hand unless you're certain you know what you are doing! ***

package identity

import (
	"context"
	"reflect"

	"github.com/pulumi/pulumi-oci/sdk/v3/go/oci/internal"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This data source provides the list of Dynamic Groups in Oracle Cloud Infrastructure Identity service.
//
// Lists the dynamic groups in your tenancy. You must specify your tenancy's OCID as the value for
// the compartment ID (remember that the tenancy is simply the root compartment).
// See [Where to Get the Tenancy's OCID and User's OCID](https://docs.cloud.oracle.com/iaas/Content/API/Concepts/apisigningkey.htm#five).
//
// ## Example Usage
//
// ```go
// package main
//
// import (
//
//	"github.com/pulumi/pulumi-oci/sdk/v3/go/oci/identity"
//	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
//
// )
//
//	func main() {
//		pulumi.Run(func(ctx *pulumi.Context) error {
//			_, err := identity.GetDynamicGroups(ctx, &identity.GetDynamicGroupsArgs{
//				CompartmentId: tenancyOcid,
//				Name:          pulumi.StringRef(dynamicGroupName),
//				State:         pulumi.StringRef(dynamicGroupState),
//			}, nil)
//			if err != nil {
//				return err
//			}
//			return nil
//		})
//	}
//
// ```
func GetDynamicGroups(ctx *pulumi.Context, args *GetDynamicGroupsArgs, opts ...pulumi.InvokeOption) (*GetDynamicGroupsResult, error) {
	opts = internal.PkgInvokeDefaultOpts(opts)
	var rv GetDynamicGroupsResult
	err := ctx.Invoke("oci:Identity/getDynamicGroups:getDynamicGroups", args, &rv, opts...)
	if err != nil {
		return nil, err
	}
	return &rv, nil
}

// A collection of arguments for invoking getDynamicGroups.
type GetDynamicGroupsArgs struct {
	// The OCID of the compartment (remember that the tenancy is simply the root compartment).
	CompartmentId string                   `pulumi:"compartmentId"`
	Filters       []GetDynamicGroupsFilter `pulumi:"filters"`
	// A filter to only return resources that match the given name exactly.
	Name *string `pulumi:"name"`
	// A filter to only return resources that match the given lifecycle state.  The state value is case-insensitive.
	State *string `pulumi:"state"`
}

// A collection of values returned by getDynamicGroups.
type GetDynamicGroupsResult struct {
	// The OCID of the tenancy containing the group.
	CompartmentId string `pulumi:"compartmentId"`
	// The list of dynamic_groups.
	DynamicGroups []GetDynamicGroupsDynamicGroup `pulumi:"dynamicGroups"`
	Filters       []GetDynamicGroupsFilter       `pulumi:"filters"`
	// The provider-assigned unique ID for this managed resource.
	Id string `pulumi:"id"`
	// The name you assign to the group during creation. The name must be unique across all groups in the tenancy and cannot be changed.
	Name *string `pulumi:"name"`
	// The group's current state.
	State *string `pulumi:"state"`
}

func GetDynamicGroupsOutput(ctx *pulumi.Context, args GetDynamicGroupsOutputArgs, opts ...pulumi.InvokeOption) GetDynamicGroupsResultOutput {
	return pulumi.ToOutputWithContext(ctx.Context(), args).
		ApplyT(func(v interface{}) (GetDynamicGroupsResultOutput, error) {
			args := v.(GetDynamicGroupsArgs)
			options := pulumi.InvokeOutputOptions{InvokeOptions: internal.PkgInvokeDefaultOpts(opts)}
			return ctx.InvokeOutput("oci:Identity/getDynamicGroups:getDynamicGroups", args, GetDynamicGroupsResultOutput{}, options).(GetDynamicGroupsResultOutput), nil
		}).(GetDynamicGroupsResultOutput)
}

// A collection of arguments for invoking getDynamicGroups.
type GetDynamicGroupsOutputArgs struct {
	// The OCID of the compartment (remember that the tenancy is simply the root compartment).
	CompartmentId pulumi.StringInput               `pulumi:"compartmentId"`
	Filters       GetDynamicGroupsFilterArrayInput `pulumi:"filters"`
	// A filter to only return resources that match the given name exactly.
	Name pulumi.StringPtrInput `pulumi:"name"`
	// A filter to only return resources that match the given lifecycle state.  The state value is case-insensitive.
	State pulumi.StringPtrInput `pulumi:"state"`
}

func (GetDynamicGroupsOutputArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*GetDynamicGroupsArgs)(nil)).Elem()
}

// A collection of values returned by getDynamicGroups.
type GetDynamicGroupsResultOutput struct{ *pulumi.OutputState }

func (GetDynamicGroupsResultOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*GetDynamicGroupsResult)(nil)).Elem()
}

func (o GetDynamicGroupsResultOutput) ToGetDynamicGroupsResultOutput() GetDynamicGroupsResultOutput {
	return o
}

func (o GetDynamicGroupsResultOutput) ToGetDynamicGroupsResultOutputWithContext(ctx context.Context) GetDynamicGroupsResultOutput {
	return o
}

// The OCID of the tenancy containing the group.
func (o GetDynamicGroupsResultOutput) CompartmentId() pulumi.StringOutput {
	return o.ApplyT(func(v GetDynamicGroupsResult) string { return v.CompartmentId }).(pulumi.StringOutput)
}

// The list of dynamic_groups.
func (o GetDynamicGroupsResultOutput) DynamicGroups() GetDynamicGroupsDynamicGroupArrayOutput {
	return o.ApplyT(func(v GetDynamicGroupsResult) []GetDynamicGroupsDynamicGroup { return v.DynamicGroups }).(GetDynamicGroupsDynamicGroupArrayOutput)
}

func (o GetDynamicGroupsResultOutput) Filters() GetDynamicGroupsFilterArrayOutput {
	return o.ApplyT(func(v GetDynamicGroupsResult) []GetDynamicGroupsFilter { return v.Filters }).(GetDynamicGroupsFilterArrayOutput)
}

// The provider-assigned unique ID for this managed resource.
func (o GetDynamicGroupsResultOutput) Id() pulumi.StringOutput {
	return o.ApplyT(func(v GetDynamicGroupsResult) string { return v.Id }).(pulumi.StringOutput)
}

// The name you assign to the group during creation. The name must be unique across all groups in the tenancy and cannot be changed.
func (o GetDynamicGroupsResultOutput) Name() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetDynamicGroupsResult) *string { return v.Name }).(pulumi.StringPtrOutput)
}

// The group's current state.
func (o GetDynamicGroupsResultOutput) State() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetDynamicGroupsResult) *string { return v.State }).(pulumi.StringPtrOutput)
}

func init() {
	pulumi.RegisterOutputType(GetDynamicGroupsResultOutput{})
}
