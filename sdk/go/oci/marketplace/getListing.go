// Code generated by pulumi-language-go DO NOT EDIT.
// *** WARNING: Do not edit by hand unless you're certain you know what you are doing! ***

package marketplace

import (
	"context"
	"reflect"

	"github.com/pulumi/pulumi-oci/sdk/v3/go/oci/internal"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This data source provides details about a specific Listing resource in Oracle Cloud Infrastructure Marketplace service.
//
// Gets detailed information about a listing, including the listing's name, version, description, and
// resources.
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
//	"github.com/pulumi/pulumi-oci/sdk/v3/go/oci/marketplace"
//	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
//
// )
//
//	func main() {
//		pulumi.Run(func(ctx *pulumi.Context) error {
//			_, err := marketplace.GetListing(ctx, &marketplace.GetListingArgs{
//				ListingId:     testListingOciMarketplaceListing.Id,
//				CompartmentId: pulumi.StringRef(compartmentId),
//			}, nil)
//			if err != nil {
//				return err
//			}
//			return nil
//		})
//	}
//
// ```
func GetListing(ctx *pulumi.Context, args *GetListingArgs, opts ...pulumi.InvokeOption) (*GetListingResult, error) {
	opts = internal.PkgInvokeDefaultOpts(opts)
	var rv GetListingResult
	err := ctx.Invoke("oci:Marketplace/getListing:getListing", args, &rv, opts...)
	if err != nil {
		return nil, err
	}
	return &rv, nil
}

// A collection of arguments for invoking getListing.
type GetListingArgs struct {
	// The unique identifier for the compartment. It is mandatory when used in non-commercial realms.
	CompartmentId *string `pulumi:"compartmentId"`
	// The unique identifier for the listing.
	ListingId string `pulumi:"listingId"`
}

// A collection of values returned by getListing.
type GetListingResult struct {
	// The model for upload data for images and icons.
	Banners []GetListingBanner `pulumi:"banners"`
	// Product categories that the listing belongs to.
	Categories    []string `pulumi:"categories"`
	CompartmentId *string  `pulumi:"compartmentId"`
	// The list of compatible architectures supported by the listing
	CompatibleArchitectures []string `pulumi:"compatibleArchitectures"`
	// The default package version.
	DefaultPackageVersion string `pulumi:"defaultPackageVersion"`
	// Links to additional documentation provided by the publisher specifically for the listing.
	DocumentationLinks []GetListingDocumentationLink `pulumi:"documentationLinks"`
	// The model for upload data for images and icons.
	Icons []GetListingIcon `pulumi:"icons"`
	// The provider-assigned unique ID for this managed resource.
	Id string `pulumi:"id"`
	// Indicates whether the listing is included in Featured Listings.
	IsFeatured bool `pulumi:"isFeatured"`
	// Keywords associated with the listing.
	Keywords string `pulumi:"keywords"`
	// Languages supported by the listing.
	Languages []GetListingLanguage `pulumi:"languages"`
	// A description of the publisher's licensing model for the listing.
	LicenseModelDescription string `pulumi:"licenseModelDescription"`
	// Reference links.
	Links     []GetListingLink `pulumi:"links"`
	ListingId string           `pulumi:"listingId"`
	// The publisher category to which the listing belongs. The publisher category informs where the listing appears for use.
	ListingType string `pulumi:"listingType"`
	// A long description of the listing.
	LongDescription string `pulumi:"longDescription"`
	// Text that describes the resource.
	Name string `pulumi:"name"`
	// The listing's package type.
	PackageType string `pulumi:"packageType"`
	// Summary details about the publisher of the listing.
	Publishers []GetListingPublisher `pulumi:"publishers"`
	// The regions where the listing is eligible to be deployed.
	Regions []GetListingRegion `pulumi:"regions"`
	// Release notes for the listing.
	ReleaseNotes string `pulumi:"releaseNotes"`
	// Screenshots of the listing.
	Screenshots []GetListingScreenshot `pulumi:"screenshots"`
	// A short description of the listing.
	ShortDescription string `pulumi:"shortDescription"`
	// Contact information to use to get support from the publisher for the listing.
	SupportContacts []GetListingSupportContact `pulumi:"supportContacts"`
	// Links to support resources for the listing.
	SupportLinks []GetListingSupportLink `pulumi:"supportLinks"`
	// The list of operating systems supported by the listing.
	SupportedOperatingSystems []GetListingSupportedOperatingSystem `pulumi:"supportedOperatingSystems"`
	// System requirements for the listing.
	SystemRequirements string `pulumi:"systemRequirements"`
	// The tagline of the listing.
	Tagline string `pulumi:"tagline"`
	// The release date of the listing.
	TimeReleased string `pulumi:"timeReleased"`
	// Usage information for the listing.
	UsageInformation string `pulumi:"usageInformation"`
	// The version of the listing.
	Version string `pulumi:"version"`
	// Videos of the listing.
	Videos []GetListingVideo `pulumi:"videos"`
}

func GetListingOutput(ctx *pulumi.Context, args GetListingOutputArgs, opts ...pulumi.InvokeOption) GetListingResultOutput {
	return pulumi.ToOutputWithContext(ctx.Context(), args).
		ApplyT(func(v interface{}) (GetListingResultOutput, error) {
			args := v.(GetListingArgs)
			options := pulumi.InvokeOutputOptions{InvokeOptions: internal.PkgInvokeDefaultOpts(opts)}
			return ctx.InvokeOutput("oci:Marketplace/getListing:getListing", args, GetListingResultOutput{}, options).(GetListingResultOutput), nil
		}).(GetListingResultOutput)
}

// A collection of arguments for invoking getListing.
type GetListingOutputArgs struct {
	// The unique identifier for the compartment. It is mandatory when used in non-commercial realms.
	CompartmentId pulumi.StringPtrInput `pulumi:"compartmentId"`
	// The unique identifier for the listing.
	ListingId pulumi.StringInput `pulumi:"listingId"`
}

func (GetListingOutputArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*GetListingArgs)(nil)).Elem()
}

// A collection of values returned by getListing.
type GetListingResultOutput struct{ *pulumi.OutputState }

func (GetListingResultOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*GetListingResult)(nil)).Elem()
}

func (o GetListingResultOutput) ToGetListingResultOutput() GetListingResultOutput {
	return o
}

func (o GetListingResultOutput) ToGetListingResultOutputWithContext(ctx context.Context) GetListingResultOutput {
	return o
}

// The model for upload data for images and icons.
func (o GetListingResultOutput) Banners() GetListingBannerArrayOutput {
	return o.ApplyT(func(v GetListingResult) []GetListingBanner { return v.Banners }).(GetListingBannerArrayOutput)
}

// Product categories that the listing belongs to.
func (o GetListingResultOutput) Categories() pulumi.StringArrayOutput {
	return o.ApplyT(func(v GetListingResult) []string { return v.Categories }).(pulumi.StringArrayOutput)
}

func (o GetListingResultOutput) CompartmentId() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetListingResult) *string { return v.CompartmentId }).(pulumi.StringPtrOutput)
}

// The list of compatible architectures supported by the listing
func (o GetListingResultOutput) CompatibleArchitectures() pulumi.StringArrayOutput {
	return o.ApplyT(func(v GetListingResult) []string { return v.CompatibleArchitectures }).(pulumi.StringArrayOutput)
}

// The default package version.
func (o GetListingResultOutput) DefaultPackageVersion() pulumi.StringOutput {
	return o.ApplyT(func(v GetListingResult) string { return v.DefaultPackageVersion }).(pulumi.StringOutput)
}

// Links to additional documentation provided by the publisher specifically for the listing.
func (o GetListingResultOutput) DocumentationLinks() GetListingDocumentationLinkArrayOutput {
	return o.ApplyT(func(v GetListingResult) []GetListingDocumentationLink { return v.DocumentationLinks }).(GetListingDocumentationLinkArrayOutput)
}

// The model for upload data for images and icons.
func (o GetListingResultOutput) Icons() GetListingIconArrayOutput {
	return o.ApplyT(func(v GetListingResult) []GetListingIcon { return v.Icons }).(GetListingIconArrayOutput)
}

// The provider-assigned unique ID for this managed resource.
func (o GetListingResultOutput) Id() pulumi.StringOutput {
	return o.ApplyT(func(v GetListingResult) string { return v.Id }).(pulumi.StringOutput)
}

// Indicates whether the listing is included in Featured Listings.
func (o GetListingResultOutput) IsFeatured() pulumi.BoolOutput {
	return o.ApplyT(func(v GetListingResult) bool { return v.IsFeatured }).(pulumi.BoolOutput)
}

// Keywords associated with the listing.
func (o GetListingResultOutput) Keywords() pulumi.StringOutput {
	return o.ApplyT(func(v GetListingResult) string { return v.Keywords }).(pulumi.StringOutput)
}

// Languages supported by the listing.
func (o GetListingResultOutput) Languages() GetListingLanguageArrayOutput {
	return o.ApplyT(func(v GetListingResult) []GetListingLanguage { return v.Languages }).(GetListingLanguageArrayOutput)
}

// A description of the publisher's licensing model for the listing.
func (o GetListingResultOutput) LicenseModelDescription() pulumi.StringOutput {
	return o.ApplyT(func(v GetListingResult) string { return v.LicenseModelDescription }).(pulumi.StringOutput)
}

// Reference links.
func (o GetListingResultOutput) Links() GetListingLinkArrayOutput {
	return o.ApplyT(func(v GetListingResult) []GetListingLink { return v.Links }).(GetListingLinkArrayOutput)
}

func (o GetListingResultOutput) ListingId() pulumi.StringOutput {
	return o.ApplyT(func(v GetListingResult) string { return v.ListingId }).(pulumi.StringOutput)
}

// The publisher category to which the listing belongs. The publisher category informs where the listing appears for use.
func (o GetListingResultOutput) ListingType() pulumi.StringOutput {
	return o.ApplyT(func(v GetListingResult) string { return v.ListingType }).(pulumi.StringOutput)
}

// A long description of the listing.
func (o GetListingResultOutput) LongDescription() pulumi.StringOutput {
	return o.ApplyT(func(v GetListingResult) string { return v.LongDescription }).(pulumi.StringOutput)
}

// Text that describes the resource.
func (o GetListingResultOutput) Name() pulumi.StringOutput {
	return o.ApplyT(func(v GetListingResult) string { return v.Name }).(pulumi.StringOutput)
}

// The listing's package type.
func (o GetListingResultOutput) PackageType() pulumi.StringOutput {
	return o.ApplyT(func(v GetListingResult) string { return v.PackageType }).(pulumi.StringOutput)
}

// Summary details about the publisher of the listing.
func (o GetListingResultOutput) Publishers() GetListingPublisherArrayOutput {
	return o.ApplyT(func(v GetListingResult) []GetListingPublisher { return v.Publishers }).(GetListingPublisherArrayOutput)
}

// The regions where the listing is eligible to be deployed.
func (o GetListingResultOutput) Regions() GetListingRegionArrayOutput {
	return o.ApplyT(func(v GetListingResult) []GetListingRegion { return v.Regions }).(GetListingRegionArrayOutput)
}

// Release notes for the listing.
func (o GetListingResultOutput) ReleaseNotes() pulumi.StringOutput {
	return o.ApplyT(func(v GetListingResult) string { return v.ReleaseNotes }).(pulumi.StringOutput)
}

// Screenshots of the listing.
func (o GetListingResultOutput) Screenshots() GetListingScreenshotArrayOutput {
	return o.ApplyT(func(v GetListingResult) []GetListingScreenshot { return v.Screenshots }).(GetListingScreenshotArrayOutput)
}

// A short description of the listing.
func (o GetListingResultOutput) ShortDescription() pulumi.StringOutput {
	return o.ApplyT(func(v GetListingResult) string { return v.ShortDescription }).(pulumi.StringOutput)
}

// Contact information to use to get support from the publisher for the listing.
func (o GetListingResultOutput) SupportContacts() GetListingSupportContactArrayOutput {
	return o.ApplyT(func(v GetListingResult) []GetListingSupportContact { return v.SupportContacts }).(GetListingSupportContactArrayOutput)
}

// Links to support resources for the listing.
func (o GetListingResultOutput) SupportLinks() GetListingSupportLinkArrayOutput {
	return o.ApplyT(func(v GetListingResult) []GetListingSupportLink { return v.SupportLinks }).(GetListingSupportLinkArrayOutput)
}

// The list of operating systems supported by the listing.
func (o GetListingResultOutput) SupportedOperatingSystems() GetListingSupportedOperatingSystemArrayOutput {
	return o.ApplyT(func(v GetListingResult) []GetListingSupportedOperatingSystem { return v.SupportedOperatingSystems }).(GetListingSupportedOperatingSystemArrayOutput)
}

// System requirements for the listing.
func (o GetListingResultOutput) SystemRequirements() pulumi.StringOutput {
	return o.ApplyT(func(v GetListingResult) string { return v.SystemRequirements }).(pulumi.StringOutput)
}

// The tagline of the listing.
func (o GetListingResultOutput) Tagline() pulumi.StringOutput {
	return o.ApplyT(func(v GetListingResult) string { return v.Tagline }).(pulumi.StringOutput)
}

// The release date of the listing.
func (o GetListingResultOutput) TimeReleased() pulumi.StringOutput {
	return o.ApplyT(func(v GetListingResult) string { return v.TimeReleased }).(pulumi.StringOutput)
}

// Usage information for the listing.
func (o GetListingResultOutput) UsageInformation() pulumi.StringOutput {
	return o.ApplyT(func(v GetListingResult) string { return v.UsageInformation }).(pulumi.StringOutput)
}

// The version of the listing.
func (o GetListingResultOutput) Version() pulumi.StringOutput {
	return o.ApplyT(func(v GetListingResult) string { return v.Version }).(pulumi.StringOutput)
}

// Videos of the listing.
func (o GetListingResultOutput) Videos() GetListingVideoArrayOutput {
	return o.ApplyT(func(v GetListingResult) []GetListingVideo { return v.Videos }).(GetListingVideoArrayOutput)
}

func init() {
	pulumi.RegisterOutputType(GetListingResultOutput{})
}
