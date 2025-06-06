// Code generated by pulumi-language-go DO NOT EDIT.
// *** WARNING: Do not edit by hand unless you're certain you know what you are doing! ***

package core

import (
	"context"
	"reflect"

	"github.com/pulumi/pulumi-oci/sdk/v3/go/oci/internal"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This data source provides the list of Images in Oracle Cloud Infrastructure Core service.
//
// Lists a subset of images available in the specified compartment, including
// [platform images](https://docs.cloud.oracle.com/iaas/Content/Compute/References/images.htm) and
// [custom images](https://docs.cloud.oracle.com/iaas/Content/Compute/Tasks/managingcustomimages.htm).
// The list of platform images includes the three most recently published versions
// of each major distribution. The list does not support filtering based on image tags.
//
// The list of images returned is ordered to first show the recent platform images,
// then all of the custom images.
//
// **Caution:** Platform images are refreshed regularly. When new images are released, older versions are replaced.
// The image OCIDs remain available, but when the platform image is replaced, the image OCIDs are no longer returned as part of the platform image list.
//
// ## Example Usage
//
// ```go
// package main
//
// import (
//
//	"github.com/pulumi/pulumi-oci/sdk/v3/go/oci/core"
//	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
//
// )
//
//	func main() {
//		pulumi.Run(func(ctx *pulumi.Context) error {
//			_, err := core.GetImages(ctx, &core.GetImagesArgs{
//				CompartmentId:          compartmentId,
//				DisplayName:            pulumi.StringRef(imageDisplayName),
//				OperatingSystem:        pulumi.StringRef(imageOperatingSystem),
//				OperatingSystemVersion: pulumi.StringRef(imageOperatingSystemVersion),
//				Shape:                  pulumi.StringRef(imageShape),
//				State:                  pulumi.StringRef(imageState),
//				SortBy:                 pulumi.StringRef(imageSortBy),
//				SortOrder:              pulumi.StringRef(imageSortOrder),
//			}, nil)
//			if err != nil {
//				return err
//			}
//			return nil
//		})
//	}
//
// ```
func GetImages(ctx *pulumi.Context, args *GetImagesArgs, opts ...pulumi.InvokeOption) (*GetImagesResult, error) {
	opts = internal.PkgInvokeDefaultOpts(opts)
	var rv GetImagesResult
	err := ctx.Invoke("oci:Core/getImages:getImages", args, &rv, opts...)
	if err != nil {
		return nil, err
	}
	return &rv, nil
}

// A collection of arguments for invoking getImages.
type GetImagesArgs struct {
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
	CompartmentId string `pulumi:"compartmentId"`
	// A filter to return only resources that match the given display name exactly.
	DisplayName *string           `pulumi:"displayName"`
	Filters     []GetImagesFilter `pulumi:"filters"`
	// The image's operating system.  Example: `Oracle Linux`
	OperatingSystem *string `pulumi:"operatingSystem"`
	// The image's operating system version.  Example: `7.2`
	OperatingSystemVersion *string `pulumi:"operatingSystemVersion"`
	// Shape name.
	Shape *string `pulumi:"shape"`
	// Sort the resources returned, by creation time or display name. Example `TIMECREATED` or `DISPLAYNAME`.
	SortBy *string `pulumi:"sortBy"`
	// The sort order to use, either ascending (`ASC`) or descending (`DESC`).
	SortOrder *string `pulumi:"sortOrder"`
	// A filter to only return resources that match the given lifecycle state.  The state value is case-insensitive.
	State *string `pulumi:"state"`
}

// A collection of values returned by getImages.
type GetImagesResult struct {
	// The OCID of the compartment containing the instance you want to use as the basis for the image.
	CompartmentId string `pulumi:"compartmentId"`
	// A user-friendly name for the image. It does not have to be unique, and it's changeable. Avoid entering confidential information.
	DisplayName *string           `pulumi:"displayName"`
	Filters     []GetImagesFilter `pulumi:"filters"`
	// The provider-assigned unique ID for this managed resource.
	Id string `pulumi:"id"`
	// The list of images.
	Images []GetImagesImage `pulumi:"images"`
	// The image's operating system.  Example: `Oracle Linux`
	OperatingSystem *string `pulumi:"operatingSystem"`
	// The image's operating system version.  Example: `7.2`
	OperatingSystemVersion *string `pulumi:"operatingSystemVersion"`
	Shape                  *string `pulumi:"shape"`
	SortBy                 *string `pulumi:"sortBy"`
	SortOrder              *string `pulumi:"sortOrder"`
	// The current state of the image.
	State *string `pulumi:"state"`
}

func GetImagesOutput(ctx *pulumi.Context, args GetImagesOutputArgs, opts ...pulumi.InvokeOption) GetImagesResultOutput {
	return pulumi.ToOutputWithContext(ctx.Context(), args).
		ApplyT(func(v interface{}) (GetImagesResultOutput, error) {
			args := v.(GetImagesArgs)
			options := pulumi.InvokeOutputOptions{InvokeOptions: internal.PkgInvokeDefaultOpts(opts)}
			return ctx.InvokeOutput("oci:Core/getImages:getImages", args, GetImagesResultOutput{}, options).(GetImagesResultOutput), nil
		}).(GetImagesResultOutput)
}

// A collection of arguments for invoking getImages.
type GetImagesOutputArgs struct {
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
	CompartmentId pulumi.StringInput `pulumi:"compartmentId"`
	// A filter to return only resources that match the given display name exactly.
	DisplayName pulumi.StringPtrInput     `pulumi:"displayName"`
	Filters     GetImagesFilterArrayInput `pulumi:"filters"`
	// The image's operating system.  Example: `Oracle Linux`
	OperatingSystem pulumi.StringPtrInput `pulumi:"operatingSystem"`
	// The image's operating system version.  Example: `7.2`
	OperatingSystemVersion pulumi.StringPtrInput `pulumi:"operatingSystemVersion"`
	// Shape name.
	Shape pulumi.StringPtrInput `pulumi:"shape"`
	// Sort the resources returned, by creation time or display name. Example `TIMECREATED` or `DISPLAYNAME`.
	SortBy pulumi.StringPtrInput `pulumi:"sortBy"`
	// The sort order to use, either ascending (`ASC`) or descending (`DESC`).
	SortOrder pulumi.StringPtrInput `pulumi:"sortOrder"`
	// A filter to only return resources that match the given lifecycle state.  The state value is case-insensitive.
	State pulumi.StringPtrInput `pulumi:"state"`
}

func (GetImagesOutputArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*GetImagesArgs)(nil)).Elem()
}

// A collection of values returned by getImages.
type GetImagesResultOutput struct{ *pulumi.OutputState }

func (GetImagesResultOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*GetImagesResult)(nil)).Elem()
}

func (o GetImagesResultOutput) ToGetImagesResultOutput() GetImagesResultOutput {
	return o
}

func (o GetImagesResultOutput) ToGetImagesResultOutputWithContext(ctx context.Context) GetImagesResultOutput {
	return o
}

// The OCID of the compartment containing the instance you want to use as the basis for the image.
func (o GetImagesResultOutput) CompartmentId() pulumi.StringOutput {
	return o.ApplyT(func(v GetImagesResult) string { return v.CompartmentId }).(pulumi.StringOutput)
}

// A user-friendly name for the image. It does not have to be unique, and it's changeable. Avoid entering confidential information.
func (o GetImagesResultOutput) DisplayName() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetImagesResult) *string { return v.DisplayName }).(pulumi.StringPtrOutput)
}

func (o GetImagesResultOutput) Filters() GetImagesFilterArrayOutput {
	return o.ApplyT(func(v GetImagesResult) []GetImagesFilter { return v.Filters }).(GetImagesFilterArrayOutput)
}

// The provider-assigned unique ID for this managed resource.
func (o GetImagesResultOutput) Id() pulumi.StringOutput {
	return o.ApplyT(func(v GetImagesResult) string { return v.Id }).(pulumi.StringOutput)
}

// The list of images.
func (o GetImagesResultOutput) Images() GetImagesImageArrayOutput {
	return o.ApplyT(func(v GetImagesResult) []GetImagesImage { return v.Images }).(GetImagesImageArrayOutput)
}

// The image's operating system.  Example: `Oracle Linux`
func (o GetImagesResultOutput) OperatingSystem() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetImagesResult) *string { return v.OperatingSystem }).(pulumi.StringPtrOutput)
}

// The image's operating system version.  Example: `7.2`
func (o GetImagesResultOutput) OperatingSystemVersion() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetImagesResult) *string { return v.OperatingSystemVersion }).(pulumi.StringPtrOutput)
}

func (o GetImagesResultOutput) Shape() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetImagesResult) *string { return v.Shape }).(pulumi.StringPtrOutput)
}

func (o GetImagesResultOutput) SortBy() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetImagesResult) *string { return v.SortBy }).(pulumi.StringPtrOutput)
}

func (o GetImagesResultOutput) SortOrder() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetImagesResult) *string { return v.SortOrder }).(pulumi.StringPtrOutput)
}

// The current state of the image.
func (o GetImagesResultOutput) State() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetImagesResult) *string { return v.State }).(pulumi.StringPtrOutput)
}

func init() {
	pulumi.RegisterOutputType(GetImagesResultOutput{})
}
