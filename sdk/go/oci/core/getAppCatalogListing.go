// Code generated by the Pulumi Terraform Bridge (tfgen) Tool DO NOT EDIT.
// *** WARNING: Do not edit by hand unless you're certain you know what you are doing! ***

package core

import (
	"context"
	"reflect"

	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This data source provides details about a specific App Catalog Listing resource in Oracle Cloud Infrastructure Core service.
//
// Gets the specified listing.
//
// ## Example Usage
//
// ```go
// package main
//
// import (
//
//	"github.com/pulumi/pulumi-oci/sdk/go/oci/Core"
//	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
//
// )
//
//	func main() {
//		pulumi.Run(func(ctx *pulumi.Context) error {
//			_, err := Core.GetAppCatalogListing(ctx, &core.GetAppCatalogListingArgs{
//				ListingId: data.Oci_core_app_catalog_listing.Test_listing.Id,
//			}, nil)
//			if err != nil {
//				return err
//			}
//			return nil
//		})
//	}
//
// ```
func GetAppCatalogListing(ctx *pulumi.Context, args *GetAppCatalogListingArgs, opts ...pulumi.InvokeOption) (*GetAppCatalogListingResult, error) {
	var rv GetAppCatalogListingResult
	err := ctx.Invoke("oci:Core/getAppCatalogListing:getAppCatalogListing", args, &rv, opts...)
	if err != nil {
		return nil, err
	}
	return &rv, nil
}

// A collection of arguments for invoking getAppCatalogListing.
type GetAppCatalogListingArgs struct {
	// The OCID of the listing.
	ListingId string `pulumi:"listingId"`
}

// A collection of values returned by getAppCatalogListing.
type GetAppCatalogListingResult struct {
	// Listing's contact URL.
	ContactUrl string `pulumi:"contactUrl"`
	// Description of the listing.
	Description string `pulumi:"description"`
	// A user-friendly name. Does not have to be unique, and it's changeable. Avoid entering confidential information.
	DisplayName string `pulumi:"displayName"`
	// The provider-assigned unique ID for this managed resource.
	Id string `pulumi:"id"`
	// the region free ocid of the listing resource.
	ListingId string `pulumi:"listingId"`
	// Publisher's logo URL.
	PublisherLogoUrl string `pulumi:"publisherLogoUrl"`
	// The name of the publisher who published this listing.
	PublisherName string `pulumi:"publisherName"`
	// The short summary for the listing.
	Summary string `pulumi:"summary"`
	// Date and time the listing was published, in [RFC3339](https://tools.ietf.org/html/rfc3339) format. Example: `2018-03-20T12:32:53.532Z`
	TimePublished string `pulumi:"timePublished"`
}

func GetAppCatalogListingOutput(ctx *pulumi.Context, args GetAppCatalogListingOutputArgs, opts ...pulumi.InvokeOption) GetAppCatalogListingResultOutput {
	return pulumi.ToOutputWithContext(context.Background(), args).
		ApplyT(func(v interface{}) (GetAppCatalogListingResult, error) {
			args := v.(GetAppCatalogListingArgs)
			r, err := GetAppCatalogListing(ctx, &args, opts...)
			var s GetAppCatalogListingResult
			if r != nil {
				s = *r
			}
			return s, err
		}).(GetAppCatalogListingResultOutput)
}

// A collection of arguments for invoking getAppCatalogListing.
type GetAppCatalogListingOutputArgs struct {
	// The OCID of the listing.
	ListingId pulumi.StringInput `pulumi:"listingId"`
}

func (GetAppCatalogListingOutputArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*GetAppCatalogListingArgs)(nil)).Elem()
}

// A collection of values returned by getAppCatalogListing.
type GetAppCatalogListingResultOutput struct{ *pulumi.OutputState }

func (GetAppCatalogListingResultOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*GetAppCatalogListingResult)(nil)).Elem()
}

func (o GetAppCatalogListingResultOutput) ToGetAppCatalogListingResultOutput() GetAppCatalogListingResultOutput {
	return o
}

func (o GetAppCatalogListingResultOutput) ToGetAppCatalogListingResultOutputWithContext(ctx context.Context) GetAppCatalogListingResultOutput {
	return o
}

// Listing's contact URL.
func (o GetAppCatalogListingResultOutput) ContactUrl() pulumi.StringOutput {
	return o.ApplyT(func(v GetAppCatalogListingResult) string { return v.ContactUrl }).(pulumi.StringOutput)
}

// Description of the listing.
func (o GetAppCatalogListingResultOutput) Description() pulumi.StringOutput {
	return o.ApplyT(func(v GetAppCatalogListingResult) string { return v.Description }).(pulumi.StringOutput)
}

// A user-friendly name. Does not have to be unique, and it's changeable. Avoid entering confidential information.
func (o GetAppCatalogListingResultOutput) DisplayName() pulumi.StringOutput {
	return o.ApplyT(func(v GetAppCatalogListingResult) string { return v.DisplayName }).(pulumi.StringOutput)
}

// The provider-assigned unique ID for this managed resource.
func (o GetAppCatalogListingResultOutput) Id() pulumi.StringOutput {
	return o.ApplyT(func(v GetAppCatalogListingResult) string { return v.Id }).(pulumi.StringOutput)
}

// the region free ocid of the listing resource.
func (o GetAppCatalogListingResultOutput) ListingId() pulumi.StringOutput {
	return o.ApplyT(func(v GetAppCatalogListingResult) string { return v.ListingId }).(pulumi.StringOutput)
}

// Publisher's logo URL.
func (o GetAppCatalogListingResultOutput) PublisherLogoUrl() pulumi.StringOutput {
	return o.ApplyT(func(v GetAppCatalogListingResult) string { return v.PublisherLogoUrl }).(pulumi.StringOutput)
}

// The name of the publisher who published this listing.
func (o GetAppCatalogListingResultOutput) PublisherName() pulumi.StringOutput {
	return o.ApplyT(func(v GetAppCatalogListingResult) string { return v.PublisherName }).(pulumi.StringOutput)
}

// The short summary for the listing.
func (o GetAppCatalogListingResultOutput) Summary() pulumi.StringOutput {
	return o.ApplyT(func(v GetAppCatalogListingResult) string { return v.Summary }).(pulumi.StringOutput)
}

// Date and time the listing was published, in [RFC3339](https://tools.ietf.org/html/rfc3339) format. Example: `2018-03-20T12:32:53.532Z`
func (o GetAppCatalogListingResultOutput) TimePublished() pulumi.StringOutput {
	return o.ApplyT(func(v GetAppCatalogListingResult) string { return v.TimePublished }).(pulumi.StringOutput)
}

func init() {
	pulumi.RegisterOutputType(GetAppCatalogListingResultOutput{})
}