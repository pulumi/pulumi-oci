// Code generated by the Pulumi Terraform Bridge (tfgen) Tool DO NOT EDIT.
// *** WARNING: Do not edit by hand unless you're certain you know what you are doing! ***

package licensemanager

import (
	"context"
	"reflect"

	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This data source provides the list of Top Utilized Resources in Oracle Cloud Infrastructure License Manager service.
//
// Retrieves the top utilized resources for a given compartment.
//
// ## Example Usage
//
// ```go
// package main
//
// import (
//
//	"github.com/pulumi/pulumi-oci/sdk/go/oci/LicenseManager"
//	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
//
// )
//
//	func main() {
//		pulumi.Run(func(ctx *pulumi.Context) error {
//			_, err := LicenseManager.GetTopUtilizedResources(ctx, &licensemanager.GetTopUtilizedResourcesArgs{
//				CompartmentId:            _var.Compartment_id,
//				IsCompartmentIdInSubtree: pulumi.BoolRef(_var.Top_utilized_resource_is_compartment_id_in_subtree),
//				ResourceUnitType:         pulumi.StringRef(_var.Top_utilized_resource_resource_unit_type),
//			}, nil)
//			if err != nil {
//				return err
//			}
//			return nil
//		})
//	}
//
// ```
func GetTopUtilizedResources(ctx *pulumi.Context, args *GetTopUtilizedResourcesArgs, opts ...pulumi.InvokeOption) (*GetTopUtilizedResourcesResult, error) {
	var rv GetTopUtilizedResourcesResult
	err := ctx.Invoke("oci:LicenseManager/getTopUtilizedResources:getTopUtilizedResources", args, &rv, opts...)
	if err != nil {
		return nil, err
	}
	return &rv, nil
}

// A collection of arguments for invoking getTopUtilizedResources.
type GetTopUtilizedResourcesArgs struct {
	// The compartment [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) used for the license record, product license, and configuration.
	CompartmentId string `pulumi:"compartmentId"`
	// Indicates if the given compartment is the root compartment.
	IsCompartmentIdInSubtree *bool `pulumi:"isCompartmentIdInSubtree"`
	// A filter to return only resources whose unit matches the given resource unit.
	ResourceUnitType *string `pulumi:"resourceUnitType"`
}

// A collection of values returned by getTopUtilizedResources.
type GetTopUtilizedResourcesResult struct {
	CompartmentId string `pulumi:"compartmentId"`
	// The provider-assigned unique ID for this managed resource.
	Id                       string `pulumi:"id"`
	IsCompartmentIdInSubtree *bool  `pulumi:"isCompartmentIdInSubtree"`
	// The top utilized resource summary collection.
	Items            []GetTopUtilizedResourcesItem `pulumi:"items"`
	ResourceUnitType *string                       `pulumi:"resourceUnitType"`
}

func GetTopUtilizedResourcesOutput(ctx *pulumi.Context, args GetTopUtilizedResourcesOutputArgs, opts ...pulumi.InvokeOption) GetTopUtilizedResourcesResultOutput {
	return pulumi.ToOutputWithContext(context.Background(), args).
		ApplyT(func(v interface{}) (GetTopUtilizedResourcesResult, error) {
			args := v.(GetTopUtilizedResourcesArgs)
			r, err := GetTopUtilizedResources(ctx, &args, opts...)
			var s GetTopUtilizedResourcesResult
			if r != nil {
				s = *r
			}
			return s, err
		}).(GetTopUtilizedResourcesResultOutput)
}

// A collection of arguments for invoking getTopUtilizedResources.
type GetTopUtilizedResourcesOutputArgs struct {
	// The compartment [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) used for the license record, product license, and configuration.
	CompartmentId pulumi.StringInput `pulumi:"compartmentId"`
	// Indicates if the given compartment is the root compartment.
	IsCompartmentIdInSubtree pulumi.BoolPtrInput `pulumi:"isCompartmentIdInSubtree"`
	// A filter to return only resources whose unit matches the given resource unit.
	ResourceUnitType pulumi.StringPtrInput `pulumi:"resourceUnitType"`
}

func (GetTopUtilizedResourcesOutputArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*GetTopUtilizedResourcesArgs)(nil)).Elem()
}

// A collection of values returned by getTopUtilizedResources.
type GetTopUtilizedResourcesResultOutput struct{ *pulumi.OutputState }

func (GetTopUtilizedResourcesResultOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*GetTopUtilizedResourcesResult)(nil)).Elem()
}

func (o GetTopUtilizedResourcesResultOutput) ToGetTopUtilizedResourcesResultOutput() GetTopUtilizedResourcesResultOutput {
	return o
}

func (o GetTopUtilizedResourcesResultOutput) ToGetTopUtilizedResourcesResultOutputWithContext(ctx context.Context) GetTopUtilizedResourcesResultOutput {
	return o
}

func (o GetTopUtilizedResourcesResultOutput) CompartmentId() pulumi.StringOutput {
	return o.ApplyT(func(v GetTopUtilizedResourcesResult) string { return v.CompartmentId }).(pulumi.StringOutput)
}

// The provider-assigned unique ID for this managed resource.
func (o GetTopUtilizedResourcesResultOutput) Id() pulumi.StringOutput {
	return o.ApplyT(func(v GetTopUtilizedResourcesResult) string { return v.Id }).(pulumi.StringOutput)
}

func (o GetTopUtilizedResourcesResultOutput) IsCompartmentIdInSubtree() pulumi.BoolPtrOutput {
	return o.ApplyT(func(v GetTopUtilizedResourcesResult) *bool { return v.IsCompartmentIdInSubtree }).(pulumi.BoolPtrOutput)
}

// The top utilized resource summary collection.
func (o GetTopUtilizedResourcesResultOutput) Items() GetTopUtilizedResourcesItemArrayOutput {
	return o.ApplyT(func(v GetTopUtilizedResourcesResult) []GetTopUtilizedResourcesItem { return v.Items }).(GetTopUtilizedResourcesItemArrayOutput)
}

func (o GetTopUtilizedResourcesResultOutput) ResourceUnitType() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetTopUtilizedResourcesResult) *string { return v.ResourceUnitType }).(pulumi.StringPtrOutput)
}

func init() {
	pulumi.RegisterOutputType(GetTopUtilizedResourcesResultOutput{})
}