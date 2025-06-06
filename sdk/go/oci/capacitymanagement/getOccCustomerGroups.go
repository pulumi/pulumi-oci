// Code generated by pulumi-language-go DO NOT EDIT.
// *** WARNING: Do not edit by hand unless you're certain you know what you are doing! ***

package capacitymanagement

import (
	"context"
	"reflect"

	"github.com/pulumi/pulumi-oci/sdk/v3/go/oci/internal"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This data source provides the list of Occ Customer Groups in Oracle Cloud Infrastructure Capacity Management service.
//
// Lists all the customer groups.
//
// ## Example Usage
//
// ```go
// package main
//
// import (
//
//	"github.com/pulumi/pulumi-oci/sdk/v3/go/oci/capacitymanagement"
//	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
//
// )
//
//	func main() {
//		pulumi.Run(func(ctx *pulumi.Context) error {
//			_, err := capacitymanagement.GetOccCustomerGroups(ctx, &capacitymanagement.GetOccCustomerGroupsArgs{
//				CompartmentId: compartmentId,
//				DisplayName:   pulumi.StringRef(occCustomerGroupDisplayName),
//				Id:            pulumi.StringRef(occCustomerGroupId),
//				Status:        pulumi.StringRef(occCustomerGroupStatus),
//			}, nil)
//			if err != nil {
//				return err
//			}
//			return nil
//		})
//	}
//
// ```
func GetOccCustomerGroups(ctx *pulumi.Context, args *GetOccCustomerGroupsArgs, opts ...pulumi.InvokeOption) (*GetOccCustomerGroupsResult, error) {
	opts = internal.PkgInvokeDefaultOpts(opts)
	var rv GetOccCustomerGroupsResult
	err := ctx.Invoke("oci:CapacityManagement/getOccCustomerGroups:getOccCustomerGroups", args, &rv, opts...)
	if err != nil {
		return nil, err
	}
	return &rv, nil
}

// A collection of arguments for invoking getOccCustomerGroups.
type GetOccCustomerGroupsArgs struct {
	// The ocid of the compartment or tenancy in which resources are to be listed. This will also be used for authorization purposes.
	CompartmentId string `pulumi:"compartmentId"`
	// A filter to return only the resources that match the entire display name. The match is not case sensitive.
	DisplayName *string                      `pulumi:"displayName"`
	Filters     []GetOccCustomerGroupsFilter `pulumi:"filters"`
	// A query filter to return the list result based on the customer group OCID. This is done for users who have INSPECT permission but do not have READ permission.
	Id *string `pulumi:"id"`
	// A query filter to return the list result based on status.
	Status *string `pulumi:"status"`
}

// A collection of values returned by getOccCustomerGroups.
type GetOccCustomerGroupsResult struct {
	// The OCID of the tenancy containing the customer group.
	CompartmentId string `pulumi:"compartmentId"`
	// The display name of the customer group.
	DisplayName *string                      `pulumi:"displayName"`
	Filters     []GetOccCustomerGroupsFilter `pulumi:"filters"`
	// The OCID of the customer group.
	Id *string `pulumi:"id"`
	// The list of occ_customer_group_collection.
	OccCustomerGroupCollections []GetOccCustomerGroupsOccCustomerGroupCollection `pulumi:"occCustomerGroupCollections"`
	// To determine whether the customer group is enabled/disabled.
	Status *string `pulumi:"status"`
}

func GetOccCustomerGroupsOutput(ctx *pulumi.Context, args GetOccCustomerGroupsOutputArgs, opts ...pulumi.InvokeOption) GetOccCustomerGroupsResultOutput {
	return pulumi.ToOutputWithContext(ctx.Context(), args).
		ApplyT(func(v interface{}) (GetOccCustomerGroupsResultOutput, error) {
			args := v.(GetOccCustomerGroupsArgs)
			options := pulumi.InvokeOutputOptions{InvokeOptions: internal.PkgInvokeDefaultOpts(opts)}
			return ctx.InvokeOutput("oci:CapacityManagement/getOccCustomerGroups:getOccCustomerGroups", args, GetOccCustomerGroupsResultOutput{}, options).(GetOccCustomerGroupsResultOutput), nil
		}).(GetOccCustomerGroupsResultOutput)
}

// A collection of arguments for invoking getOccCustomerGroups.
type GetOccCustomerGroupsOutputArgs struct {
	// The ocid of the compartment or tenancy in which resources are to be listed. This will also be used for authorization purposes.
	CompartmentId pulumi.StringInput `pulumi:"compartmentId"`
	// A filter to return only the resources that match the entire display name. The match is not case sensitive.
	DisplayName pulumi.StringPtrInput                `pulumi:"displayName"`
	Filters     GetOccCustomerGroupsFilterArrayInput `pulumi:"filters"`
	// A query filter to return the list result based on the customer group OCID. This is done for users who have INSPECT permission but do not have READ permission.
	Id pulumi.StringPtrInput `pulumi:"id"`
	// A query filter to return the list result based on status.
	Status pulumi.StringPtrInput `pulumi:"status"`
}

func (GetOccCustomerGroupsOutputArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*GetOccCustomerGroupsArgs)(nil)).Elem()
}

// A collection of values returned by getOccCustomerGroups.
type GetOccCustomerGroupsResultOutput struct{ *pulumi.OutputState }

func (GetOccCustomerGroupsResultOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*GetOccCustomerGroupsResult)(nil)).Elem()
}

func (o GetOccCustomerGroupsResultOutput) ToGetOccCustomerGroupsResultOutput() GetOccCustomerGroupsResultOutput {
	return o
}

func (o GetOccCustomerGroupsResultOutput) ToGetOccCustomerGroupsResultOutputWithContext(ctx context.Context) GetOccCustomerGroupsResultOutput {
	return o
}

// The OCID of the tenancy containing the customer group.
func (o GetOccCustomerGroupsResultOutput) CompartmentId() pulumi.StringOutput {
	return o.ApplyT(func(v GetOccCustomerGroupsResult) string { return v.CompartmentId }).(pulumi.StringOutput)
}

// The display name of the customer group.
func (o GetOccCustomerGroupsResultOutput) DisplayName() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetOccCustomerGroupsResult) *string { return v.DisplayName }).(pulumi.StringPtrOutput)
}

func (o GetOccCustomerGroupsResultOutput) Filters() GetOccCustomerGroupsFilterArrayOutput {
	return o.ApplyT(func(v GetOccCustomerGroupsResult) []GetOccCustomerGroupsFilter { return v.Filters }).(GetOccCustomerGroupsFilterArrayOutput)
}

// The OCID of the customer group.
func (o GetOccCustomerGroupsResultOutput) Id() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetOccCustomerGroupsResult) *string { return v.Id }).(pulumi.StringPtrOutput)
}

// The list of occ_customer_group_collection.
func (o GetOccCustomerGroupsResultOutput) OccCustomerGroupCollections() GetOccCustomerGroupsOccCustomerGroupCollectionArrayOutput {
	return o.ApplyT(func(v GetOccCustomerGroupsResult) []GetOccCustomerGroupsOccCustomerGroupCollection {
		return v.OccCustomerGroupCollections
	}).(GetOccCustomerGroupsOccCustomerGroupCollectionArrayOutput)
}

// To determine whether the customer group is enabled/disabled.
func (o GetOccCustomerGroupsResultOutput) Status() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetOccCustomerGroupsResult) *string { return v.Status }).(pulumi.StringPtrOutput)
}

func init() {
	pulumi.RegisterOutputType(GetOccCustomerGroupsResultOutput{})
}
