// Code generated by the Pulumi Terraform Bridge (tfgen) Tool DO NOT EDIT.
// *** WARNING: Do not edit by hand unless you're certain you know what you are doing! ***

package marketplace

import (
	"context"
	"reflect"

	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This data source provides the list of Listings in Oracle Cloud Infrastructure Marketplace service.
//
// Gets a list of listings from Oracle Cloud Infrastructure Marketplace by searching keywords and
// filtering according to listing attributes.
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
//			_, err := Marketplace.GetListings(ctx, &marketplace.GetListingsArgs{
//				Categories:       _var.Listing_category,
//				CompartmentId:    pulumi.StringRef(_var.Compartment_id),
//				ImageId:          pulumi.StringRef(oci_core_image.Test_image.Id),
//				IsFeatured:       pulumi.BoolRef(_var.Listing_is_featured),
//				ListingId:        pulumi.StringRef(oci_marketplace_listing.Test_listing.Id),
//				ListingTypes:     _var.Listing_listing_types,
//				Names:            _var.Listing_name,
//				OperatingSystems: _var.Listing_operating_systems,
//				PackageType:      pulumi.StringRef(_var.Listing_package_type),
//				Pricings:         _var.Listing_pricing,
//				PublisherId:      pulumi.StringRef(oci_marketplace_publisher.Test_publisher.Id),
//			}, nil)
//			if err != nil {
//				return err
//			}
//			return nil
//		})
//	}
//
// ```
func GetListings(ctx *pulumi.Context, args *GetListingsArgs, opts ...pulumi.InvokeOption) (*GetListingsResult, error) {
	var rv GetListingsResult
	err := ctx.Invoke("oci:Marketplace/getListings:getListings", args, &rv, opts...)
	if err != nil {
		return nil, err
	}
	return &rv, nil
}

// A collection of arguments for invoking getListings.
type GetListingsArgs struct {
	// Name of the product category or categories. If you specify multiple categories, then Marketplace returns any listing with one or more matching categories.
	Categories []string `pulumi:"categories"`
	// The unique identifier for the compartment.
	CompartmentId *string             `pulumi:"compartmentId"`
	Filters       []GetListingsFilter `pulumi:"filters"`
	// The image identifier of the listing.
	ImageId *string `pulumi:"imageId"`
	// Indicates whether to show only featured listings. If this is set to `false` or is omitted, then all listings will be returned.
	IsFeatured *bool `pulumi:"isFeatured"`
	// The unique identifier for the listing.
	ListingId *string `pulumi:"listingId"`
	// The type of the listing.
	ListingTypes []string `pulumi:"listingTypes"`
	// The name of the listing.
	Names []string `pulumi:"names"`
	// The operating system of the listing.
	OperatingSystems []string `pulumi:"operatingSystems"`
	// A filter to return only packages that match the given package type exactly.
	PackageType *string `pulumi:"packageType"`
	// Name of the pricing type. If multiple pricing types are provided, then any listing with one or more matching pricing models will be returned.
	Pricings []string `pulumi:"pricings"`
	// Limit results to just this publisher.
	PublisherId *string `pulumi:"publisherId"`
}

// A collection of values returned by getListings.
type GetListingsResult struct {
	Categories    []string            `pulumi:"categories"`
	CompartmentId *string             `pulumi:"compartmentId"`
	Filters       []GetListingsFilter `pulumi:"filters"`
	// The provider-assigned unique ID for this managed resource.
	Id      string  `pulumi:"id"`
	ImageId *string `pulumi:"imageId"`
	// Indicates whether the listing is included in Featured Listings.
	IsFeatured   *bool    `pulumi:"isFeatured"`
	ListingId    *string  `pulumi:"listingId"`
	ListingTypes []string `pulumi:"listingTypes"`
	// The list of listings.
	Listings []GetListingsListing `pulumi:"listings"`
	// Text that describes the resource.
	Names            []string `pulumi:"names"`
	OperatingSystems []string `pulumi:"operatingSystems"`
	// The listing's package type.
	PackageType *string  `pulumi:"packageType"`
	Pricings    []string `pulumi:"pricings"`
	PublisherId *string  `pulumi:"publisherId"`
}

func GetListingsOutput(ctx *pulumi.Context, args GetListingsOutputArgs, opts ...pulumi.InvokeOption) GetListingsResultOutput {
	return pulumi.ToOutputWithContext(context.Background(), args).
		ApplyT(func(v interface{}) (GetListingsResult, error) {
			args := v.(GetListingsArgs)
			r, err := GetListings(ctx, &args, opts...)
			var s GetListingsResult
			if r != nil {
				s = *r
			}
			return s, err
		}).(GetListingsResultOutput)
}

// A collection of arguments for invoking getListings.
type GetListingsOutputArgs struct {
	// Name of the product category or categories. If you specify multiple categories, then Marketplace returns any listing with one or more matching categories.
	Categories pulumi.StringArrayInput `pulumi:"categories"`
	// The unique identifier for the compartment.
	CompartmentId pulumi.StringPtrInput       `pulumi:"compartmentId"`
	Filters       GetListingsFilterArrayInput `pulumi:"filters"`
	// The image identifier of the listing.
	ImageId pulumi.StringPtrInput `pulumi:"imageId"`
	// Indicates whether to show only featured listings. If this is set to `false` or is omitted, then all listings will be returned.
	IsFeatured pulumi.BoolPtrInput `pulumi:"isFeatured"`
	// The unique identifier for the listing.
	ListingId pulumi.StringPtrInput `pulumi:"listingId"`
	// The type of the listing.
	ListingTypes pulumi.StringArrayInput `pulumi:"listingTypes"`
	// The name of the listing.
	Names pulumi.StringArrayInput `pulumi:"names"`
	// The operating system of the listing.
	OperatingSystems pulumi.StringArrayInput `pulumi:"operatingSystems"`
	// A filter to return only packages that match the given package type exactly.
	PackageType pulumi.StringPtrInput `pulumi:"packageType"`
	// Name of the pricing type. If multiple pricing types are provided, then any listing with one or more matching pricing models will be returned.
	Pricings pulumi.StringArrayInput `pulumi:"pricings"`
	// Limit results to just this publisher.
	PublisherId pulumi.StringPtrInput `pulumi:"publisherId"`
}

func (GetListingsOutputArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*GetListingsArgs)(nil)).Elem()
}

// A collection of values returned by getListings.
type GetListingsResultOutput struct{ *pulumi.OutputState }

func (GetListingsResultOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*GetListingsResult)(nil)).Elem()
}

func (o GetListingsResultOutput) ToGetListingsResultOutput() GetListingsResultOutput {
	return o
}

func (o GetListingsResultOutput) ToGetListingsResultOutputWithContext(ctx context.Context) GetListingsResultOutput {
	return o
}

func (o GetListingsResultOutput) Categories() pulumi.StringArrayOutput {
	return o.ApplyT(func(v GetListingsResult) []string { return v.Categories }).(pulumi.StringArrayOutput)
}

func (o GetListingsResultOutput) CompartmentId() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetListingsResult) *string { return v.CompartmentId }).(pulumi.StringPtrOutput)
}

func (o GetListingsResultOutput) Filters() GetListingsFilterArrayOutput {
	return o.ApplyT(func(v GetListingsResult) []GetListingsFilter { return v.Filters }).(GetListingsFilterArrayOutput)
}

// The provider-assigned unique ID for this managed resource.
func (o GetListingsResultOutput) Id() pulumi.StringOutput {
	return o.ApplyT(func(v GetListingsResult) string { return v.Id }).(pulumi.StringOutput)
}

func (o GetListingsResultOutput) ImageId() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetListingsResult) *string { return v.ImageId }).(pulumi.StringPtrOutput)
}

// Indicates whether the listing is included in Featured Listings.
func (o GetListingsResultOutput) IsFeatured() pulumi.BoolPtrOutput {
	return o.ApplyT(func(v GetListingsResult) *bool { return v.IsFeatured }).(pulumi.BoolPtrOutput)
}

func (o GetListingsResultOutput) ListingId() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetListingsResult) *string { return v.ListingId }).(pulumi.StringPtrOutput)
}

func (o GetListingsResultOutput) ListingTypes() pulumi.StringArrayOutput {
	return o.ApplyT(func(v GetListingsResult) []string { return v.ListingTypes }).(pulumi.StringArrayOutput)
}

// The list of listings.
func (o GetListingsResultOutput) Listings() GetListingsListingArrayOutput {
	return o.ApplyT(func(v GetListingsResult) []GetListingsListing { return v.Listings }).(GetListingsListingArrayOutput)
}

// Text that describes the resource.
func (o GetListingsResultOutput) Names() pulumi.StringArrayOutput {
	return o.ApplyT(func(v GetListingsResult) []string { return v.Names }).(pulumi.StringArrayOutput)
}

func (o GetListingsResultOutput) OperatingSystems() pulumi.StringArrayOutput {
	return o.ApplyT(func(v GetListingsResult) []string { return v.OperatingSystems }).(pulumi.StringArrayOutput)
}

// The listing's package type.
func (o GetListingsResultOutput) PackageType() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetListingsResult) *string { return v.PackageType }).(pulumi.StringPtrOutput)
}

func (o GetListingsResultOutput) Pricings() pulumi.StringArrayOutput {
	return o.ApplyT(func(v GetListingsResult) []string { return v.Pricings }).(pulumi.StringArrayOutput)
}

func (o GetListingsResultOutput) PublisherId() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetListingsResult) *string { return v.PublisherId }).(pulumi.StringPtrOutput)
}

func init() {
	pulumi.RegisterOutputType(GetListingsResultOutput{})
}