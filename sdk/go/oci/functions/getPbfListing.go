// Code generated by pulumi-language-go DO NOT EDIT.
// *** WARNING: Do not edit by hand unless you're certain you know what you are doing! ***

package functions

import (
	"context"
	"reflect"

	"github.com/pulumi/pulumi-oci/sdk/v3/go/oci/internal"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This data source provides details about a specific Pbf Listing resource in Oracle Cloud Infrastructure Functions service.
//
// Fetches a Pre-built Function(PBF) Listing. Returns a PbfListing response model.
//
// ## Example Usage
//
// ```go
// package main
//
// import (
//
//	"github.com/pulumi/pulumi-oci/sdk/v3/go/oci/functions"
//	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
//
// )
//
//	func main() {
//		pulumi.Run(func(ctx *pulumi.Context) error {
//			_, err := functions.GetPbfListing(ctx, &functions.GetPbfListingArgs{
//				PbfListingId: testPbfListingOciFunctionsPbfListing.Id,
//			}, nil)
//			if err != nil {
//				return err
//			}
//			return nil
//		})
//	}
//
// ```
func GetPbfListing(ctx *pulumi.Context, args *GetPbfListingArgs, opts ...pulumi.InvokeOption) (*GetPbfListingResult, error) {
	opts = internal.PkgInvokeDefaultOpts(opts)
	var rv GetPbfListingResult
	err := ctx.Invoke("oci:Functions/getPbfListing:getPbfListing", args, &rv, opts...)
	if err != nil {
		return nil, err
	}
	return &rv, nil
}

// A collection of arguments for invoking getPbfListing.
type GetPbfListingArgs struct {
	// unique PbfListing identifier
	PbfListingId string `pulumi:"pbfListingId"`
}

// A collection of values returned by getPbfListing.
type GetPbfListingResult struct {
	// Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
	DefinedTags map[string]string `pulumi:"definedTags"`
	// A short overview of the PBF Listing: the purpose of the PBF and and associated information.
	Description string `pulumi:"description"`
	// Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
	FreeformTags map[string]string `pulumi:"freeformTags"`
	// The provider-assigned unique ID for this managed resource.
	Id string `pulumi:"id"`
	// A brief descriptive name for the PBF trigger.
	Name         string `pulumi:"name"`
	PbfListingId string `pulumi:"pbfListingId"`
	// Contains details about the publisher of this PBF Listing.
	PublisherDetails []GetPbfListingPublisherDetail `pulumi:"publisherDetails"`
	// The current state of the PBF resource.
	State string `pulumi:"state"`
	// System tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"orcl-cloud.free-tier-retained": "true"}`
	SystemTags map[string]string `pulumi:"systemTags"`
	// The time the PbfListing was created. An RFC3339 formatted datetime string.
	TimeCreated string `pulumi:"timeCreated"`
	// The last time the PbfListing was updated. An RFC3339 formatted datetime string.
	TimeUpdated string `pulumi:"timeUpdated"`
	// An array of Trigger. A list of triggers that may activate the PBF.
	Triggers []GetPbfListingTrigger `pulumi:"triggers"`
}

func GetPbfListingOutput(ctx *pulumi.Context, args GetPbfListingOutputArgs, opts ...pulumi.InvokeOption) GetPbfListingResultOutput {
	return pulumi.ToOutputWithContext(ctx.Context(), args).
		ApplyT(func(v interface{}) (GetPbfListingResultOutput, error) {
			args := v.(GetPbfListingArgs)
			options := pulumi.InvokeOutputOptions{InvokeOptions: internal.PkgInvokeDefaultOpts(opts)}
			return ctx.InvokeOutput("oci:Functions/getPbfListing:getPbfListing", args, GetPbfListingResultOutput{}, options).(GetPbfListingResultOutput), nil
		}).(GetPbfListingResultOutput)
}

// A collection of arguments for invoking getPbfListing.
type GetPbfListingOutputArgs struct {
	// unique PbfListing identifier
	PbfListingId pulumi.StringInput `pulumi:"pbfListingId"`
}

func (GetPbfListingOutputArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*GetPbfListingArgs)(nil)).Elem()
}

// A collection of values returned by getPbfListing.
type GetPbfListingResultOutput struct{ *pulumi.OutputState }

func (GetPbfListingResultOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*GetPbfListingResult)(nil)).Elem()
}

func (o GetPbfListingResultOutput) ToGetPbfListingResultOutput() GetPbfListingResultOutput {
	return o
}

func (o GetPbfListingResultOutput) ToGetPbfListingResultOutputWithContext(ctx context.Context) GetPbfListingResultOutput {
	return o
}

// Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
func (o GetPbfListingResultOutput) DefinedTags() pulumi.StringMapOutput {
	return o.ApplyT(func(v GetPbfListingResult) map[string]string { return v.DefinedTags }).(pulumi.StringMapOutput)
}

// A short overview of the PBF Listing: the purpose of the PBF and and associated information.
func (o GetPbfListingResultOutput) Description() pulumi.StringOutput {
	return o.ApplyT(func(v GetPbfListingResult) string { return v.Description }).(pulumi.StringOutput)
}

// Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
func (o GetPbfListingResultOutput) FreeformTags() pulumi.StringMapOutput {
	return o.ApplyT(func(v GetPbfListingResult) map[string]string { return v.FreeformTags }).(pulumi.StringMapOutput)
}

// The provider-assigned unique ID for this managed resource.
func (o GetPbfListingResultOutput) Id() pulumi.StringOutput {
	return o.ApplyT(func(v GetPbfListingResult) string { return v.Id }).(pulumi.StringOutput)
}

// A brief descriptive name for the PBF trigger.
func (o GetPbfListingResultOutput) Name() pulumi.StringOutput {
	return o.ApplyT(func(v GetPbfListingResult) string { return v.Name }).(pulumi.StringOutput)
}

func (o GetPbfListingResultOutput) PbfListingId() pulumi.StringOutput {
	return o.ApplyT(func(v GetPbfListingResult) string { return v.PbfListingId }).(pulumi.StringOutput)
}

// Contains details about the publisher of this PBF Listing.
func (o GetPbfListingResultOutput) PublisherDetails() GetPbfListingPublisherDetailArrayOutput {
	return o.ApplyT(func(v GetPbfListingResult) []GetPbfListingPublisherDetail { return v.PublisherDetails }).(GetPbfListingPublisherDetailArrayOutput)
}

// The current state of the PBF resource.
func (o GetPbfListingResultOutput) State() pulumi.StringOutput {
	return o.ApplyT(func(v GetPbfListingResult) string { return v.State }).(pulumi.StringOutput)
}

// System tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"orcl-cloud.free-tier-retained": "true"}`
func (o GetPbfListingResultOutput) SystemTags() pulumi.StringMapOutput {
	return o.ApplyT(func(v GetPbfListingResult) map[string]string { return v.SystemTags }).(pulumi.StringMapOutput)
}

// The time the PbfListing was created. An RFC3339 formatted datetime string.
func (o GetPbfListingResultOutput) TimeCreated() pulumi.StringOutput {
	return o.ApplyT(func(v GetPbfListingResult) string { return v.TimeCreated }).(pulumi.StringOutput)
}

// The last time the PbfListing was updated. An RFC3339 formatted datetime string.
func (o GetPbfListingResultOutput) TimeUpdated() pulumi.StringOutput {
	return o.ApplyT(func(v GetPbfListingResult) string { return v.TimeUpdated }).(pulumi.StringOutput)
}

// An array of Trigger. A list of triggers that may activate the PBF.
func (o GetPbfListingResultOutput) Triggers() GetPbfListingTriggerArrayOutput {
	return o.ApplyT(func(v GetPbfListingResult) []GetPbfListingTrigger { return v.Triggers }).(GetPbfListingTriggerArrayOutput)
}

func init() {
	pulumi.RegisterOutputType(GetPbfListingResultOutput{})
}
