// Code generated by the Pulumi Terraform Bridge (tfgen) Tool DO NOT EDIT.
// *** WARNING: Do not edit by hand unless you're certain you know what you are doing! ***

package marketplace

import (
	"context"
	"reflect"

	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This data source provides details about a specific Listing Package resource in Oracle Cloud Infrastructure Marketplace service.
//
// Get the details of the specified version of a package, including information needed to launch the package.
//
// If you plan to launch an instance from an image listing, you must first subscribe to the listing. When
// you launch the instance, you also need to provide the image ID of the listing resource version that you want.
//
// Subscribing to the listing requires you to first get a signature from the terms of use agreement for the
// listing resource version. To get the signature, issue a [GetAppCatalogListingAgreements](https://docs.cloud.oracle.com/en-us/iaas/api/#/en/iaas/latest/AppCatalogListingResourceVersionAgreements/GetAppCatalogListingAgreements) API call.
// The [AppCatalogListingResourceVersionAgreements](https://docs.cloud.oracle.com/en-us/iaas/api/#/en/iaas/latest/AppCatalogListingResourceVersionAgreements) object, including
// its signature, is returned in the response. With the signature for the terms of use agreement for the desired
// listing resource version, create a subscription by issuing a
// [CreateAppCatalogSubscription](https://docs.cloud.oracle.com/en-us/iaas/api/#/en/iaas/latest/AppCatalogSubscription/CreateAppCatalogSubscription) API call.
//
// To get the image ID to launch an instance, issue a [GetAppCatalogListingResourceVersion](https://docs.cloud.oracle.com/en-us/iaas/api/#/en/iaas/latest/AppCatalogListingResourceVersion/GetAppCatalogListingResourceVersion) API call.
// Lastly, to launch the instance, use the image ID of the listing resource version to issue a [LaunchInstance](https://docs.cloud.oracle.com/en-us/iaas/api/#/en/iaas/latest/Instance/LaunchInstance) API call.
//
// ## Example Usage
//
// ```go
// package main
//
// import (
//
//	"github.com/pulumi/pulumi-oci/sdk/go/oci/Marketplace"
//	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
//
// )
//
//	func main() {
//		pulumi.Run(func(ctx *pulumi.Context) error {
//			_, err := Marketplace.GetListingPackage(ctx, &marketplace.GetListingPackageArgs{
//				ListingId:      oci_marketplace_listing.Test_listing.Id,
//				PackageVersion: _var.Listing_package_package_version,
//				CompartmentId:  pulumi.StringRef(_var.Compartment_id),
//			}, nil)
//			if err != nil {
//				return err
//			}
//			return nil
//		})
//	}
//
// ```
func GetListingPackage(ctx *pulumi.Context, args *GetListingPackageArgs, opts ...pulumi.InvokeOption) (*GetListingPackageResult, error) {
	var rv GetListingPackageResult
	err := ctx.Invoke("oci:Marketplace/getListingPackage:getListingPackage", args, &rv, opts...)
	if err != nil {
		return nil, err
	}
	return &rv, nil
}

// A collection of arguments for invoking getListingPackage.
type GetListingPackageArgs struct {
	// The unique identifier for the compartment.
	CompartmentId *string `pulumi:"compartmentId"`
	// The unique identifier for the listing.
	ListingId string `pulumi:"listingId"`
	// The version of the package. Package versions are unique within a listing.
	PackageVersion string `pulumi:"packageVersion"`
}

// A collection of values returned by getListingPackage.
type GetListingPackageResult struct {
	// The ID of the listing resource associated with this listing package. For more information, see [AppCatalogListing](https://docs.cloud.oracle.com/en-us/iaas/api/#/en/iaas/latest/AppCatalogListing/) in the Core Services API.
	AppCatalogListingId string `pulumi:"appCatalogListingId"`
	// The resource version of the listing resource associated with this listing package.
	AppCatalogListingResourceVersion string  `pulumi:"appCatalogListingResourceVersion"`
	CompartmentId                    *string `pulumi:"compartmentId"`
	// A description of the variable.
	Description string `pulumi:"description"`
	// The provider-assigned unique ID for this managed resource.
	Id string `pulumi:"id"`
	// The ID of the image corresponding to the package.
	ImageId string `pulumi:"imageId"`
	// The ID of the listing that the specified package belongs to.
	ListingId string `pulumi:"listingId"`
	// The operating system used by the listing.
	OperatingSystems []GetListingPackageOperatingSystem `pulumi:"operatingSystems"`
	// The specified package's type.
	PackageType    string `pulumi:"packageType"`
	PackageVersion string `pulumi:"packageVersion"`
	// The model for pricing.
	Pricings []GetListingPackagePricing `pulumi:"pricings"`
	// The regions where you can deploy this listing package. (Some packages have restrictions that limit their deployment to United States regions only.)
	Regions []GetListingPackageRegion `pulumi:"regions"`
	// The unique identifier for the package resource.
	ResourceId string `pulumi:"resourceId"`
	// Link to the orchestration resource.
	ResourceLink string `pulumi:"resourceLink"`
	// The date and time this listing package was created, expressed in [RFC 3339](https://tools.ietf.org/html/rfc3339) timestamp format.  Example: `2016-08-25T21:10:29.600Z`
	TimeCreated string `pulumi:"timeCreated"`
	// List of variables for the orchestration resource.
	Variables []GetListingPackageVariable `pulumi:"variables"`
	// The package version.
	Version string `pulumi:"version"`
}

func GetListingPackageOutput(ctx *pulumi.Context, args GetListingPackageOutputArgs, opts ...pulumi.InvokeOption) GetListingPackageResultOutput {
	return pulumi.ToOutputWithContext(context.Background(), args).
		ApplyT(func(v interface{}) (GetListingPackageResult, error) {
			args := v.(GetListingPackageArgs)
			r, err := GetListingPackage(ctx, &args, opts...)
			var s GetListingPackageResult
			if r != nil {
				s = *r
			}
			return s, err
		}).(GetListingPackageResultOutput)
}

// A collection of arguments for invoking getListingPackage.
type GetListingPackageOutputArgs struct {
	// The unique identifier for the compartment.
	CompartmentId pulumi.StringPtrInput `pulumi:"compartmentId"`
	// The unique identifier for the listing.
	ListingId pulumi.StringInput `pulumi:"listingId"`
	// The version of the package. Package versions are unique within a listing.
	PackageVersion pulumi.StringInput `pulumi:"packageVersion"`
}

func (GetListingPackageOutputArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*GetListingPackageArgs)(nil)).Elem()
}

// A collection of values returned by getListingPackage.
type GetListingPackageResultOutput struct{ *pulumi.OutputState }

func (GetListingPackageResultOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*GetListingPackageResult)(nil)).Elem()
}

func (o GetListingPackageResultOutput) ToGetListingPackageResultOutput() GetListingPackageResultOutput {
	return o
}

func (o GetListingPackageResultOutput) ToGetListingPackageResultOutputWithContext(ctx context.Context) GetListingPackageResultOutput {
	return o
}

// The ID of the listing resource associated with this listing package. For more information, see [AppCatalogListing](https://docs.cloud.oracle.com/en-us/iaas/api/#/en/iaas/latest/AppCatalogListing/) in the Core Services API.
func (o GetListingPackageResultOutput) AppCatalogListingId() pulumi.StringOutput {
	return o.ApplyT(func(v GetListingPackageResult) string { return v.AppCatalogListingId }).(pulumi.StringOutput)
}

// The resource version of the listing resource associated with this listing package.
func (o GetListingPackageResultOutput) AppCatalogListingResourceVersion() pulumi.StringOutput {
	return o.ApplyT(func(v GetListingPackageResult) string { return v.AppCatalogListingResourceVersion }).(pulumi.StringOutput)
}

func (o GetListingPackageResultOutput) CompartmentId() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetListingPackageResult) *string { return v.CompartmentId }).(pulumi.StringPtrOutput)
}

// A description of the variable.
func (o GetListingPackageResultOutput) Description() pulumi.StringOutput {
	return o.ApplyT(func(v GetListingPackageResult) string { return v.Description }).(pulumi.StringOutput)
}

// The provider-assigned unique ID for this managed resource.
func (o GetListingPackageResultOutput) Id() pulumi.StringOutput {
	return o.ApplyT(func(v GetListingPackageResult) string { return v.Id }).(pulumi.StringOutput)
}

// The ID of the image corresponding to the package.
func (o GetListingPackageResultOutput) ImageId() pulumi.StringOutput {
	return o.ApplyT(func(v GetListingPackageResult) string { return v.ImageId }).(pulumi.StringOutput)
}

// The ID of the listing that the specified package belongs to.
func (o GetListingPackageResultOutput) ListingId() pulumi.StringOutput {
	return o.ApplyT(func(v GetListingPackageResult) string { return v.ListingId }).(pulumi.StringOutput)
}

// The operating system used by the listing.
func (o GetListingPackageResultOutput) OperatingSystems() GetListingPackageOperatingSystemArrayOutput {
	return o.ApplyT(func(v GetListingPackageResult) []GetListingPackageOperatingSystem { return v.OperatingSystems }).(GetListingPackageOperatingSystemArrayOutput)
}

// The specified package's type.
func (o GetListingPackageResultOutput) PackageType() pulumi.StringOutput {
	return o.ApplyT(func(v GetListingPackageResult) string { return v.PackageType }).(pulumi.StringOutput)
}

func (o GetListingPackageResultOutput) PackageVersion() pulumi.StringOutput {
	return o.ApplyT(func(v GetListingPackageResult) string { return v.PackageVersion }).(pulumi.StringOutput)
}

// The model for pricing.
func (o GetListingPackageResultOutput) Pricings() GetListingPackagePricingArrayOutput {
	return o.ApplyT(func(v GetListingPackageResult) []GetListingPackagePricing { return v.Pricings }).(GetListingPackagePricingArrayOutput)
}

// The regions where you can deploy this listing package. (Some packages have restrictions that limit their deployment to United States regions only.)
func (o GetListingPackageResultOutput) Regions() GetListingPackageRegionArrayOutput {
	return o.ApplyT(func(v GetListingPackageResult) []GetListingPackageRegion { return v.Regions }).(GetListingPackageRegionArrayOutput)
}

// The unique identifier for the package resource.
func (o GetListingPackageResultOutput) ResourceId() pulumi.StringOutput {
	return o.ApplyT(func(v GetListingPackageResult) string { return v.ResourceId }).(pulumi.StringOutput)
}

// Link to the orchestration resource.
func (o GetListingPackageResultOutput) ResourceLink() pulumi.StringOutput {
	return o.ApplyT(func(v GetListingPackageResult) string { return v.ResourceLink }).(pulumi.StringOutput)
}

// The date and time this listing package was created, expressed in [RFC 3339](https://tools.ietf.org/html/rfc3339) timestamp format.  Example: `2016-08-25T21:10:29.600Z`
func (o GetListingPackageResultOutput) TimeCreated() pulumi.StringOutput {
	return o.ApplyT(func(v GetListingPackageResult) string { return v.TimeCreated }).(pulumi.StringOutput)
}

// List of variables for the orchestration resource.
func (o GetListingPackageResultOutput) Variables() GetListingPackageVariableArrayOutput {
	return o.ApplyT(func(v GetListingPackageResult) []GetListingPackageVariable { return v.Variables }).(GetListingPackageVariableArrayOutput)
}

// The package version.
func (o GetListingPackageResultOutput) Version() pulumi.StringOutput {
	return o.ApplyT(func(v GetListingPackageResult) string { return v.Version }).(pulumi.StringOutput)
}

func init() {
	pulumi.RegisterOutputType(GetListingPackageResultOutput{})
}