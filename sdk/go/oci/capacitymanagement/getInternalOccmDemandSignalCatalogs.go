// Code generated by pulumi-language-go DO NOT EDIT.
// *** WARNING: Do not edit by hand unless you're certain you know what you are doing! ***

package capacitymanagement

import (
	"context"
	"reflect"

	"github.com/pulumi/pulumi-oci/sdk/v3/go/oci/internal"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This data source provides the list of Internal Occm Demand Signal Catalogs in Oracle Cloud Infrastructure Capacity Management service.
//
// This API will list demand signal catalogs for a given customer group.
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
//			_, err := capacitymanagement.GetInternalOccmDemandSignalCatalogs(ctx, &capacitymanagement.GetInternalOccmDemandSignalCatalogsArgs{
//				CompartmentId:      compartmentId,
//				OccCustomerGroupId: testOccCustomerGroup.Id,
//				DisplayName:        pulumi.StringRef(internalOccmDemandSignalCatalogDisplayName),
//			}, nil)
//			if err != nil {
//				return err
//			}
//			return nil
//		})
//	}
//
// ```
func GetInternalOccmDemandSignalCatalogs(ctx *pulumi.Context, args *GetInternalOccmDemandSignalCatalogsArgs, opts ...pulumi.InvokeOption) (*GetInternalOccmDemandSignalCatalogsResult, error) {
	opts = internal.PkgInvokeDefaultOpts(opts)
	var rv GetInternalOccmDemandSignalCatalogsResult
	err := ctx.Invoke("oci:CapacityManagement/getInternalOccmDemandSignalCatalogs:getInternalOccmDemandSignalCatalogs", args, &rv, opts...)
	if err != nil {
		return nil, err
	}
	return &rv, nil
}

// A collection of arguments for invoking getInternalOccmDemandSignalCatalogs.
type GetInternalOccmDemandSignalCatalogsArgs struct {
	// The ocid of the compartment or tenancy in which resources are to be listed. This will also be used for authorization purposes.
	CompartmentId string `pulumi:"compartmentId"`
	// A filter to return only the resources that match the entire display name. The match is not case sensitive.
	DisplayName *string                                     `pulumi:"displayName"`
	Filters     []GetInternalOccmDemandSignalCatalogsFilter `pulumi:"filters"`
	// The customer group ocid by which we would filter the list.
	OccCustomerGroupId string `pulumi:"occCustomerGroupId"`
}

// A collection of values returned by getInternalOccmDemandSignalCatalogs.
type GetInternalOccmDemandSignalCatalogsResult struct {
	// compartment id from where demand signal catalog is created.
	CompartmentId string `pulumi:"compartmentId"`
	// displayName of demand signal catalog.
	DisplayName *string                                     `pulumi:"displayName"`
	Filters     []GetInternalOccmDemandSignalCatalogsFilter `pulumi:"filters"`
	// The provider-assigned unique ID for this managed resource.
	Id string `pulumi:"id"`
	// The customer group OCID to which the availability catalog belongs.
	OccCustomerGroupId string `pulumi:"occCustomerGroupId"`
	// The list of occm_demand_signal_catalog_collection.
	OccmDemandSignalCatalogCollections []GetInternalOccmDemandSignalCatalogsOccmDemandSignalCatalogCollection `pulumi:"occmDemandSignalCatalogCollections"`
}

func GetInternalOccmDemandSignalCatalogsOutput(ctx *pulumi.Context, args GetInternalOccmDemandSignalCatalogsOutputArgs, opts ...pulumi.InvokeOption) GetInternalOccmDemandSignalCatalogsResultOutput {
	return pulumi.ToOutputWithContext(ctx.Context(), args).
		ApplyT(func(v interface{}) (GetInternalOccmDemandSignalCatalogsResultOutput, error) {
			args := v.(GetInternalOccmDemandSignalCatalogsArgs)
			options := pulumi.InvokeOutputOptions{InvokeOptions: internal.PkgInvokeDefaultOpts(opts)}
			return ctx.InvokeOutput("oci:CapacityManagement/getInternalOccmDemandSignalCatalogs:getInternalOccmDemandSignalCatalogs", args, GetInternalOccmDemandSignalCatalogsResultOutput{}, options).(GetInternalOccmDemandSignalCatalogsResultOutput), nil
		}).(GetInternalOccmDemandSignalCatalogsResultOutput)
}

// A collection of arguments for invoking getInternalOccmDemandSignalCatalogs.
type GetInternalOccmDemandSignalCatalogsOutputArgs struct {
	// The ocid of the compartment or tenancy in which resources are to be listed. This will also be used for authorization purposes.
	CompartmentId pulumi.StringInput `pulumi:"compartmentId"`
	// A filter to return only the resources that match the entire display name. The match is not case sensitive.
	DisplayName pulumi.StringPtrInput                               `pulumi:"displayName"`
	Filters     GetInternalOccmDemandSignalCatalogsFilterArrayInput `pulumi:"filters"`
	// The customer group ocid by which we would filter the list.
	OccCustomerGroupId pulumi.StringInput `pulumi:"occCustomerGroupId"`
}

func (GetInternalOccmDemandSignalCatalogsOutputArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*GetInternalOccmDemandSignalCatalogsArgs)(nil)).Elem()
}

// A collection of values returned by getInternalOccmDemandSignalCatalogs.
type GetInternalOccmDemandSignalCatalogsResultOutput struct{ *pulumi.OutputState }

func (GetInternalOccmDemandSignalCatalogsResultOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*GetInternalOccmDemandSignalCatalogsResult)(nil)).Elem()
}

func (o GetInternalOccmDemandSignalCatalogsResultOutput) ToGetInternalOccmDemandSignalCatalogsResultOutput() GetInternalOccmDemandSignalCatalogsResultOutput {
	return o
}

func (o GetInternalOccmDemandSignalCatalogsResultOutput) ToGetInternalOccmDemandSignalCatalogsResultOutputWithContext(ctx context.Context) GetInternalOccmDemandSignalCatalogsResultOutput {
	return o
}

// compartment id from where demand signal catalog is created.
func (o GetInternalOccmDemandSignalCatalogsResultOutput) CompartmentId() pulumi.StringOutput {
	return o.ApplyT(func(v GetInternalOccmDemandSignalCatalogsResult) string { return v.CompartmentId }).(pulumi.StringOutput)
}

// displayName of demand signal catalog.
func (o GetInternalOccmDemandSignalCatalogsResultOutput) DisplayName() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetInternalOccmDemandSignalCatalogsResult) *string { return v.DisplayName }).(pulumi.StringPtrOutput)
}

func (o GetInternalOccmDemandSignalCatalogsResultOutput) Filters() GetInternalOccmDemandSignalCatalogsFilterArrayOutput {
	return o.ApplyT(func(v GetInternalOccmDemandSignalCatalogsResult) []GetInternalOccmDemandSignalCatalogsFilter {
		return v.Filters
	}).(GetInternalOccmDemandSignalCatalogsFilterArrayOutput)
}

// The provider-assigned unique ID for this managed resource.
func (o GetInternalOccmDemandSignalCatalogsResultOutput) Id() pulumi.StringOutput {
	return o.ApplyT(func(v GetInternalOccmDemandSignalCatalogsResult) string { return v.Id }).(pulumi.StringOutput)
}

// The customer group OCID to which the availability catalog belongs.
func (o GetInternalOccmDemandSignalCatalogsResultOutput) OccCustomerGroupId() pulumi.StringOutput {
	return o.ApplyT(func(v GetInternalOccmDemandSignalCatalogsResult) string { return v.OccCustomerGroupId }).(pulumi.StringOutput)
}

// The list of occm_demand_signal_catalog_collection.
func (o GetInternalOccmDemandSignalCatalogsResultOutput) OccmDemandSignalCatalogCollections() GetInternalOccmDemandSignalCatalogsOccmDemandSignalCatalogCollectionArrayOutput {
	return o.ApplyT(func(v GetInternalOccmDemandSignalCatalogsResult) []GetInternalOccmDemandSignalCatalogsOccmDemandSignalCatalogCollection {
		return v.OccmDemandSignalCatalogCollections
	}).(GetInternalOccmDemandSignalCatalogsOccmDemandSignalCatalogCollectionArrayOutput)
}

func init() {
	pulumi.RegisterOutputType(GetInternalOccmDemandSignalCatalogsResultOutput{})
}
