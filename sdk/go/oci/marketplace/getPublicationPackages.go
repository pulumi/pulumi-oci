// Code generated by the Pulumi Terraform Bridge (tfgen) Tool DO NOT EDIT.
// *** WARNING: Do not edit by hand unless you're certain you know what you are doing! ***

package marketplace

import (
	"context"
	"reflect"

	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This data source provides the list of Publication Packages in Oracle Cloud Infrastructure Marketplace service.
//
// Lists the packages in the specified publication.
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
//			_, err := Marketplace.GetPublicationPackages(ctx, &marketplace.GetPublicationPackagesArgs{
//				PublicationId:  oci_marketplace_publication.Test_publication.Id,
//				PackageType:    pulumi.StringRef(_var.Publication_package_package_type),
//				PackageVersion: pulumi.StringRef(_var.Publication_package_package_version),
//			}, nil)
//			if err != nil {
//				return err
//			}
//			return nil
//		})
//	}
//
// ```
func GetPublicationPackages(ctx *pulumi.Context, args *GetPublicationPackagesArgs, opts ...pulumi.InvokeOption) (*GetPublicationPackagesResult, error) {
	var rv GetPublicationPackagesResult
	err := ctx.Invoke("oci:Marketplace/getPublicationPackages:getPublicationPackages", args, &rv, opts...)
	if err != nil {
		return nil, err
	}
	return &rv, nil
}

// A collection of arguments for invoking getPublicationPackages.
type GetPublicationPackagesArgs struct {
	Filters []GetPublicationPackagesFilter `pulumi:"filters"`
	// A filter to return only packages that match the given package type exactly.
	PackageType *string `pulumi:"packageType"`
	// The version of the package. Package versions are unique within a listing.
	PackageVersion *string `pulumi:"packageVersion"`
	// The unique identifier for the publication.
	PublicationId string `pulumi:"publicationId"`
}

// A collection of values returned by getPublicationPackages.
type GetPublicationPackagesResult struct {
	Filters []GetPublicationPackagesFilter `pulumi:"filters"`
	// The provider-assigned unique ID for this managed resource.
	Id string `pulumi:"id"`
	// The specified package's type.
	PackageType    *string `pulumi:"packageType"`
	PackageVersion *string `pulumi:"packageVersion"`
	PublicationId  string  `pulumi:"publicationId"`
	// The list of publication_packages.
	PublicationPackages []GetPublicationPackagesPublicationPackage `pulumi:"publicationPackages"`
}

func GetPublicationPackagesOutput(ctx *pulumi.Context, args GetPublicationPackagesOutputArgs, opts ...pulumi.InvokeOption) GetPublicationPackagesResultOutput {
	return pulumi.ToOutputWithContext(context.Background(), args).
		ApplyT(func(v interface{}) (GetPublicationPackagesResult, error) {
			args := v.(GetPublicationPackagesArgs)
			r, err := GetPublicationPackages(ctx, &args, opts...)
			var s GetPublicationPackagesResult
			if r != nil {
				s = *r
			}
			return s, err
		}).(GetPublicationPackagesResultOutput)
}

// A collection of arguments for invoking getPublicationPackages.
type GetPublicationPackagesOutputArgs struct {
	Filters GetPublicationPackagesFilterArrayInput `pulumi:"filters"`
	// A filter to return only packages that match the given package type exactly.
	PackageType pulumi.StringPtrInput `pulumi:"packageType"`
	// The version of the package. Package versions are unique within a listing.
	PackageVersion pulumi.StringPtrInput `pulumi:"packageVersion"`
	// The unique identifier for the publication.
	PublicationId pulumi.StringInput `pulumi:"publicationId"`
}

func (GetPublicationPackagesOutputArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*GetPublicationPackagesArgs)(nil)).Elem()
}

// A collection of values returned by getPublicationPackages.
type GetPublicationPackagesResultOutput struct{ *pulumi.OutputState }

func (GetPublicationPackagesResultOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*GetPublicationPackagesResult)(nil)).Elem()
}

func (o GetPublicationPackagesResultOutput) ToGetPublicationPackagesResultOutput() GetPublicationPackagesResultOutput {
	return o
}

func (o GetPublicationPackagesResultOutput) ToGetPublicationPackagesResultOutputWithContext(ctx context.Context) GetPublicationPackagesResultOutput {
	return o
}

func (o GetPublicationPackagesResultOutput) Filters() GetPublicationPackagesFilterArrayOutput {
	return o.ApplyT(func(v GetPublicationPackagesResult) []GetPublicationPackagesFilter { return v.Filters }).(GetPublicationPackagesFilterArrayOutput)
}

// The provider-assigned unique ID for this managed resource.
func (o GetPublicationPackagesResultOutput) Id() pulumi.StringOutput {
	return o.ApplyT(func(v GetPublicationPackagesResult) string { return v.Id }).(pulumi.StringOutput)
}

// The specified package's type.
func (o GetPublicationPackagesResultOutput) PackageType() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetPublicationPackagesResult) *string { return v.PackageType }).(pulumi.StringPtrOutput)
}

func (o GetPublicationPackagesResultOutput) PackageVersion() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetPublicationPackagesResult) *string { return v.PackageVersion }).(pulumi.StringPtrOutput)
}

func (o GetPublicationPackagesResultOutput) PublicationId() pulumi.StringOutput {
	return o.ApplyT(func(v GetPublicationPackagesResult) string { return v.PublicationId }).(pulumi.StringOutput)
}

// The list of publication_packages.
func (o GetPublicationPackagesResultOutput) PublicationPackages() GetPublicationPackagesPublicationPackageArrayOutput {
	return o.ApplyT(func(v GetPublicationPackagesResult) []GetPublicationPackagesPublicationPackage {
		return v.PublicationPackages
	}).(GetPublicationPackagesPublicationPackageArrayOutput)
}

func init() {
	pulumi.RegisterOutputType(GetPublicationPackagesResultOutput{})
}