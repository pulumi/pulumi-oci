// Code generated by the Pulumi Terraform Bridge (tfgen) Tool DO NOT EDIT.
// *** WARNING: Do not edit by hand unless you're certain you know what you are doing! ***

package licensemanager

import (
	"context"
	"reflect"

	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This data source provides the list of Product License Consumers in Oracle Cloud Infrastructure License Manager service.
//
// Retrieves the product license consumers for a particular product license ID.
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
//			_, err := LicenseManager.GetProductLicenseConsumers(ctx, &licensemanager.GetProductLicenseConsumersArgs{
//				CompartmentId:            _var.Compartment_id,
//				ProductLicenseId:         oci_license_manager_product_license.Test_product_license.Id,
//				IsCompartmentIdInSubtree: pulumi.BoolRef(_var.Product_license_consumer_is_compartment_id_in_subtree),
//			}, nil)
//			if err != nil {
//				return err
//			}
//			return nil
//		})
//	}
//
// ```
func GetProductLicenseConsumers(ctx *pulumi.Context, args *GetProductLicenseConsumersArgs, opts ...pulumi.InvokeOption) (*GetProductLicenseConsumersResult, error) {
	var rv GetProductLicenseConsumersResult
	err := ctx.Invoke("oci:LicenseManager/getProductLicenseConsumers:getProductLicenseConsumers", args, &rv, opts...)
	if err != nil {
		return nil, err
	}
	return &rv, nil
}

// A collection of arguments for invoking getProductLicenseConsumers.
type GetProductLicenseConsumersArgs struct {
	// The compartment [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) used for the license record, product license, and configuration.
	CompartmentId string `pulumi:"compartmentId"`
	// Indicates if the given compartment is the root compartment.
	IsCompartmentIdInSubtree *bool `pulumi:"isCompartmentIdInSubtree"`
	// Unique product license identifier.
	ProductLicenseId string `pulumi:"productLicenseId"`
}

// A collection of values returned by getProductLicenseConsumers.
type GetProductLicenseConsumersResult struct {
	CompartmentId string `pulumi:"compartmentId"`
	// The provider-assigned unique ID for this managed resource.
	Id                       string `pulumi:"id"`
	IsCompartmentIdInSubtree *bool  `pulumi:"isCompartmentIdInSubtree"`
	// Collection of product license consumers.
	Items            []GetProductLicenseConsumersItem `pulumi:"items"`
	ProductLicenseId string                           `pulumi:"productLicenseId"`
}

func GetProductLicenseConsumersOutput(ctx *pulumi.Context, args GetProductLicenseConsumersOutputArgs, opts ...pulumi.InvokeOption) GetProductLicenseConsumersResultOutput {
	return pulumi.ToOutputWithContext(context.Background(), args).
		ApplyT(func(v interface{}) (GetProductLicenseConsumersResult, error) {
			args := v.(GetProductLicenseConsumersArgs)
			r, err := GetProductLicenseConsumers(ctx, &args, opts...)
			var s GetProductLicenseConsumersResult
			if r != nil {
				s = *r
			}
			return s, err
		}).(GetProductLicenseConsumersResultOutput)
}

// A collection of arguments for invoking getProductLicenseConsumers.
type GetProductLicenseConsumersOutputArgs struct {
	// The compartment [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) used for the license record, product license, and configuration.
	CompartmentId pulumi.StringInput `pulumi:"compartmentId"`
	// Indicates if the given compartment is the root compartment.
	IsCompartmentIdInSubtree pulumi.BoolPtrInput `pulumi:"isCompartmentIdInSubtree"`
	// Unique product license identifier.
	ProductLicenseId pulumi.StringInput `pulumi:"productLicenseId"`
}

func (GetProductLicenseConsumersOutputArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*GetProductLicenseConsumersArgs)(nil)).Elem()
}

// A collection of values returned by getProductLicenseConsumers.
type GetProductLicenseConsumersResultOutput struct{ *pulumi.OutputState }

func (GetProductLicenseConsumersResultOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*GetProductLicenseConsumersResult)(nil)).Elem()
}

func (o GetProductLicenseConsumersResultOutput) ToGetProductLicenseConsumersResultOutput() GetProductLicenseConsumersResultOutput {
	return o
}

func (o GetProductLicenseConsumersResultOutput) ToGetProductLicenseConsumersResultOutputWithContext(ctx context.Context) GetProductLicenseConsumersResultOutput {
	return o
}

func (o GetProductLicenseConsumersResultOutput) CompartmentId() pulumi.StringOutput {
	return o.ApplyT(func(v GetProductLicenseConsumersResult) string { return v.CompartmentId }).(pulumi.StringOutput)
}

// The provider-assigned unique ID for this managed resource.
func (o GetProductLicenseConsumersResultOutput) Id() pulumi.StringOutput {
	return o.ApplyT(func(v GetProductLicenseConsumersResult) string { return v.Id }).(pulumi.StringOutput)
}

func (o GetProductLicenseConsumersResultOutput) IsCompartmentIdInSubtree() pulumi.BoolPtrOutput {
	return o.ApplyT(func(v GetProductLicenseConsumersResult) *bool { return v.IsCompartmentIdInSubtree }).(pulumi.BoolPtrOutput)
}

// Collection of product license consumers.
func (o GetProductLicenseConsumersResultOutput) Items() GetProductLicenseConsumersItemArrayOutput {
	return o.ApplyT(func(v GetProductLicenseConsumersResult) []GetProductLicenseConsumersItem { return v.Items }).(GetProductLicenseConsumersItemArrayOutput)
}

func (o GetProductLicenseConsumersResultOutput) ProductLicenseId() pulumi.StringOutput {
	return o.ApplyT(func(v GetProductLicenseConsumersResult) string { return v.ProductLicenseId }).(pulumi.StringOutput)
}

func init() {
	pulumi.RegisterOutputType(GetProductLicenseConsumersResultOutput{})
}