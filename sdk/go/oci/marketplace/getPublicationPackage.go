// Code generated by the Pulumi Terraform Bridge (tfgen) Tool DO NOT EDIT.
// *** WARNING: Do not edit by hand unless you're certain you know what you are doing! ***

package marketplace

import (
	"context"
	"reflect"

	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This data source provides details about a specific Publication Package resource in Oracle Cloud Infrastructure Marketplace service.
//
// Gets the details of a specific package version within a given publication.
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
//			_, err := Marketplace.GetPublicationPackage(ctx, &marketplace.GetPublicationPackageArgs{
//				PackageVersion: _var.Publication_package_package_version,
//				PublicationId:  oci_marketplace_publication.Test_publication.Id,
//			}, nil)
//			if err != nil {
//				return err
//			}
//			return nil
//		})
//	}
//
// ```
func GetPublicationPackage(ctx *pulumi.Context, args *GetPublicationPackageArgs, opts ...pulumi.InvokeOption) (*GetPublicationPackageResult, error) {
	var rv GetPublicationPackageResult
	err := ctx.Invoke("oci:Marketplace/getPublicationPackage:getPublicationPackage", args, &rv, opts...)
	if err != nil {
		return nil, err
	}
	return &rv, nil
}

// A collection of arguments for invoking getPublicationPackage.
type GetPublicationPackageArgs struct {
	// The version of the package. Package versions are unique within a listing.
	PackageVersion string `pulumi:"packageVersion"`
	// The unique identifier for the publication.
	PublicationId string `pulumi:"publicationId"`
}

// A collection of values returned by getPublicationPackage.
type GetPublicationPackageResult struct {
	// The ID of the listing resource associated with this publication package. For more information, see [AppCatalogListing](https://docs.cloud.oracle.com/en-us/iaas/api/#/en/iaas/latest/AppCatalogListing/) in the Core Services API.
	AppCatalogListingId string `pulumi:"appCatalogListingId"`
	// The resource version of the listing resource associated with this publication package.
	AppCatalogListingResourceVersion string `pulumi:"appCatalogListingResourceVersion"`
	// A description of the variable.
	Description string `pulumi:"description"`
	// The provider-assigned unique ID for this managed resource.
	Id string `pulumi:"id"`
	// The ID of the image that corresponds to the package.
	ImageId string `pulumi:"imageId"`
	// The ID of the listing that the specified package belongs to.
	ListingId string `pulumi:"listingId"`
	// The operating system used by the listing.
	OperatingSystems []GetPublicationPackageOperatingSystem `pulumi:"operatingSystems"`
	// The specified package's type.
	PackageType    string `pulumi:"packageType"`
	PackageVersion string `pulumi:"packageVersion"`
	PublicationId  string `pulumi:"publicationId"`
	// The unique identifier for the package resource.
	ResourceId string `pulumi:"resourceId"`
	// A link to the stack resource.
	ResourceLink string `pulumi:"resourceLink"`
	// The date and time the publication package was created, expressed in [RFC 3339](https://tools.ietf.org/html/rfc3339) timestamp format.  Example: `2016-08-25T21:10:29.600Z`
	TimeCreated string `pulumi:"timeCreated"`
	// A list of variables for the stack resource.
	Variables []GetPublicationPackageVariable `pulumi:"variables"`
	// The package version.
	Version string `pulumi:"version"`
}

func GetPublicationPackageOutput(ctx *pulumi.Context, args GetPublicationPackageOutputArgs, opts ...pulumi.InvokeOption) GetPublicationPackageResultOutput {
	return pulumi.ToOutputWithContext(context.Background(), args).
		ApplyT(func(v interface{}) (GetPublicationPackageResult, error) {
			args := v.(GetPublicationPackageArgs)
			r, err := GetPublicationPackage(ctx, &args, opts...)
			var s GetPublicationPackageResult
			if r != nil {
				s = *r
			}
			return s, err
		}).(GetPublicationPackageResultOutput)
}

// A collection of arguments for invoking getPublicationPackage.
type GetPublicationPackageOutputArgs struct {
	// The version of the package. Package versions are unique within a listing.
	PackageVersion pulumi.StringInput `pulumi:"packageVersion"`
	// The unique identifier for the publication.
	PublicationId pulumi.StringInput `pulumi:"publicationId"`
}

func (GetPublicationPackageOutputArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*GetPublicationPackageArgs)(nil)).Elem()
}

// A collection of values returned by getPublicationPackage.
type GetPublicationPackageResultOutput struct{ *pulumi.OutputState }

func (GetPublicationPackageResultOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*GetPublicationPackageResult)(nil)).Elem()
}

func (o GetPublicationPackageResultOutput) ToGetPublicationPackageResultOutput() GetPublicationPackageResultOutput {
	return o
}

func (o GetPublicationPackageResultOutput) ToGetPublicationPackageResultOutputWithContext(ctx context.Context) GetPublicationPackageResultOutput {
	return o
}

// The ID of the listing resource associated with this publication package. For more information, see [AppCatalogListing](https://docs.cloud.oracle.com/en-us/iaas/api/#/en/iaas/latest/AppCatalogListing/) in the Core Services API.
func (o GetPublicationPackageResultOutput) AppCatalogListingId() pulumi.StringOutput {
	return o.ApplyT(func(v GetPublicationPackageResult) string { return v.AppCatalogListingId }).(pulumi.StringOutput)
}

// The resource version of the listing resource associated with this publication package.
func (o GetPublicationPackageResultOutput) AppCatalogListingResourceVersion() pulumi.StringOutput {
	return o.ApplyT(func(v GetPublicationPackageResult) string { return v.AppCatalogListingResourceVersion }).(pulumi.StringOutput)
}

// A description of the variable.
func (o GetPublicationPackageResultOutput) Description() pulumi.StringOutput {
	return o.ApplyT(func(v GetPublicationPackageResult) string { return v.Description }).(pulumi.StringOutput)
}

// The provider-assigned unique ID for this managed resource.
func (o GetPublicationPackageResultOutput) Id() pulumi.StringOutput {
	return o.ApplyT(func(v GetPublicationPackageResult) string { return v.Id }).(pulumi.StringOutput)
}

// The ID of the image that corresponds to the package.
func (o GetPublicationPackageResultOutput) ImageId() pulumi.StringOutput {
	return o.ApplyT(func(v GetPublicationPackageResult) string { return v.ImageId }).(pulumi.StringOutput)
}

// The ID of the listing that the specified package belongs to.
func (o GetPublicationPackageResultOutput) ListingId() pulumi.StringOutput {
	return o.ApplyT(func(v GetPublicationPackageResult) string { return v.ListingId }).(pulumi.StringOutput)
}

// The operating system used by the listing.
func (o GetPublicationPackageResultOutput) OperatingSystems() GetPublicationPackageOperatingSystemArrayOutput {
	return o.ApplyT(func(v GetPublicationPackageResult) []GetPublicationPackageOperatingSystem { return v.OperatingSystems }).(GetPublicationPackageOperatingSystemArrayOutput)
}

// The specified package's type.
func (o GetPublicationPackageResultOutput) PackageType() pulumi.StringOutput {
	return o.ApplyT(func(v GetPublicationPackageResult) string { return v.PackageType }).(pulumi.StringOutput)
}

func (o GetPublicationPackageResultOutput) PackageVersion() pulumi.StringOutput {
	return o.ApplyT(func(v GetPublicationPackageResult) string { return v.PackageVersion }).(pulumi.StringOutput)
}

func (o GetPublicationPackageResultOutput) PublicationId() pulumi.StringOutput {
	return o.ApplyT(func(v GetPublicationPackageResult) string { return v.PublicationId }).(pulumi.StringOutput)
}

// The unique identifier for the package resource.
func (o GetPublicationPackageResultOutput) ResourceId() pulumi.StringOutput {
	return o.ApplyT(func(v GetPublicationPackageResult) string { return v.ResourceId }).(pulumi.StringOutput)
}

// A link to the stack resource.
func (o GetPublicationPackageResultOutput) ResourceLink() pulumi.StringOutput {
	return o.ApplyT(func(v GetPublicationPackageResult) string { return v.ResourceLink }).(pulumi.StringOutput)
}

// The date and time the publication package was created, expressed in [RFC 3339](https://tools.ietf.org/html/rfc3339) timestamp format.  Example: `2016-08-25T21:10:29.600Z`
func (o GetPublicationPackageResultOutput) TimeCreated() pulumi.StringOutput {
	return o.ApplyT(func(v GetPublicationPackageResult) string { return v.TimeCreated }).(pulumi.StringOutput)
}

// A list of variables for the stack resource.
func (o GetPublicationPackageResultOutput) Variables() GetPublicationPackageVariableArrayOutput {
	return o.ApplyT(func(v GetPublicationPackageResult) []GetPublicationPackageVariable { return v.Variables }).(GetPublicationPackageVariableArrayOutput)
}

// The package version.
func (o GetPublicationPackageResultOutput) Version() pulumi.StringOutput {
	return o.ApplyT(func(v GetPublicationPackageResult) string { return v.Version }).(pulumi.StringOutput)
}

func init() {
	pulumi.RegisterOutputType(GetPublicationPackageResultOutput{})
}