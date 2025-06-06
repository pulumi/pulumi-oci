// Code generated by pulumi-language-go DO NOT EDIT.
// *** WARNING: Do not edit by hand unless you're certain you know what you are doing! ***

package core

import (
	"context"
	"reflect"

	"github.com/pulumi/pulumi-oci/sdk/v3/go/oci/internal"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

func GetListingResourceVersion(ctx *pulumi.Context, args *GetListingResourceVersionArgs, opts ...pulumi.InvokeOption) (*GetListingResourceVersionResult, error) {
	opts = internal.PkgInvokeDefaultOpts(opts)
	var rv GetListingResourceVersionResult
	err := ctx.Invoke("oci:Core/getListingResourceVersion:getListingResourceVersion", args, &rv, opts...)
	if err != nil {
		return nil, err
	}
	return &rv, nil
}

// A collection of arguments for invoking getListingResourceVersion.
type GetListingResourceVersionArgs struct {
	ListingId       string `pulumi:"listingId"`
	ResourceVersion string `pulumi:"resourceVersion"`
}

// A collection of values returned by getListingResourceVersion.
type GetListingResourceVersionResult struct {
	AccessiblePorts  []int    `pulumi:"accessiblePorts"`
	AllowedActions   []string `pulumi:"allowedActions"`
	AvailableRegions []string `pulumi:"availableRegions"`
	CompatibleShapes []string `pulumi:"compatibleShapes"`
	// The provider-assigned unique ID for this managed resource.
	Id                     string `pulumi:"id"`
	ListingId              string `pulumi:"listingId"`
	ListingResourceId      string `pulumi:"listingResourceId"`
	ListingResourceVersion string `pulumi:"listingResourceVersion"`
	ResourceVersion        string `pulumi:"resourceVersion"`
	TimePublished          string `pulumi:"timePublished"`
}

func GetListingResourceVersionOutput(ctx *pulumi.Context, args GetListingResourceVersionOutputArgs, opts ...pulumi.InvokeOption) GetListingResourceVersionResultOutput {
	return pulumi.ToOutputWithContext(ctx.Context(), args).
		ApplyT(func(v interface{}) (GetListingResourceVersionResultOutput, error) {
			args := v.(GetListingResourceVersionArgs)
			options := pulumi.InvokeOutputOptions{InvokeOptions: internal.PkgInvokeDefaultOpts(opts)}
			return ctx.InvokeOutput("oci:Core/getListingResourceVersion:getListingResourceVersion", args, GetListingResourceVersionResultOutput{}, options).(GetListingResourceVersionResultOutput), nil
		}).(GetListingResourceVersionResultOutput)
}

// A collection of arguments for invoking getListingResourceVersion.
type GetListingResourceVersionOutputArgs struct {
	ListingId       pulumi.StringInput `pulumi:"listingId"`
	ResourceVersion pulumi.StringInput `pulumi:"resourceVersion"`
}

func (GetListingResourceVersionOutputArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*GetListingResourceVersionArgs)(nil)).Elem()
}

// A collection of values returned by getListingResourceVersion.
type GetListingResourceVersionResultOutput struct{ *pulumi.OutputState }

func (GetListingResourceVersionResultOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*GetListingResourceVersionResult)(nil)).Elem()
}

func (o GetListingResourceVersionResultOutput) ToGetListingResourceVersionResultOutput() GetListingResourceVersionResultOutput {
	return o
}

func (o GetListingResourceVersionResultOutput) ToGetListingResourceVersionResultOutputWithContext(ctx context.Context) GetListingResourceVersionResultOutput {
	return o
}

func (o GetListingResourceVersionResultOutput) AccessiblePorts() pulumi.IntArrayOutput {
	return o.ApplyT(func(v GetListingResourceVersionResult) []int { return v.AccessiblePorts }).(pulumi.IntArrayOutput)
}

func (o GetListingResourceVersionResultOutput) AllowedActions() pulumi.StringArrayOutput {
	return o.ApplyT(func(v GetListingResourceVersionResult) []string { return v.AllowedActions }).(pulumi.StringArrayOutput)
}

func (o GetListingResourceVersionResultOutput) AvailableRegions() pulumi.StringArrayOutput {
	return o.ApplyT(func(v GetListingResourceVersionResult) []string { return v.AvailableRegions }).(pulumi.StringArrayOutput)
}

func (o GetListingResourceVersionResultOutput) CompatibleShapes() pulumi.StringArrayOutput {
	return o.ApplyT(func(v GetListingResourceVersionResult) []string { return v.CompatibleShapes }).(pulumi.StringArrayOutput)
}

// The provider-assigned unique ID for this managed resource.
func (o GetListingResourceVersionResultOutput) Id() pulumi.StringOutput {
	return o.ApplyT(func(v GetListingResourceVersionResult) string { return v.Id }).(pulumi.StringOutput)
}

func (o GetListingResourceVersionResultOutput) ListingId() pulumi.StringOutput {
	return o.ApplyT(func(v GetListingResourceVersionResult) string { return v.ListingId }).(pulumi.StringOutput)
}

func (o GetListingResourceVersionResultOutput) ListingResourceId() pulumi.StringOutput {
	return o.ApplyT(func(v GetListingResourceVersionResult) string { return v.ListingResourceId }).(pulumi.StringOutput)
}

func (o GetListingResourceVersionResultOutput) ListingResourceVersion() pulumi.StringOutput {
	return o.ApplyT(func(v GetListingResourceVersionResult) string { return v.ListingResourceVersion }).(pulumi.StringOutput)
}

func (o GetListingResourceVersionResultOutput) ResourceVersion() pulumi.StringOutput {
	return o.ApplyT(func(v GetListingResourceVersionResult) string { return v.ResourceVersion }).(pulumi.StringOutput)
}

func (o GetListingResourceVersionResultOutput) TimePublished() pulumi.StringOutput {
	return o.ApplyT(func(v GetListingResourceVersionResult) string { return v.TimePublished }).(pulumi.StringOutput)
}

func init() {
	pulumi.RegisterOutputType(GetListingResourceVersionResultOutput{})
}
