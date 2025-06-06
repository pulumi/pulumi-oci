// Code generated by pulumi-language-go DO NOT EDIT.
// *** WARNING: Do not edit by hand unless you're certain you know what you are doing! ***

package fleetsoftwareupdate

import (
	"context"
	"reflect"

	"github.com/pulumi/pulumi-oci/sdk/v3/go/oci/internal"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This data source provides the list of Fsu Collections in Oracle Cloud Infrastructure Fleet Software Update service.
//
// Gets a list of all Exadata Fleet Update Collections in a compartment.
//
// ## Example Usage
//
// ```go
// package main
//
// import (
//
//	"github.com/pulumi/pulumi-oci/sdk/v3/go/oci/fleetsoftwareupdate"
//	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
//
// )
//
//	func main() {
//		pulumi.Run(func(ctx *pulumi.Context) error {
//			_, err := fleetsoftwareupdate.GetFsuCollections(ctx, &fleetsoftwareupdate.GetFsuCollectionsArgs{
//				CompartmentId: compartmentId,
//				DisplayName:   pulumi.StringRef(fsuCollectionDisplayName),
//				State:         pulumi.StringRef(fsuCollectionState),
//				Type:          pulumi.StringRef(fsuCollectionType),
//			}, nil)
//			if err != nil {
//				return err
//			}
//			return nil
//		})
//	}
//
// ```
func GetFsuCollections(ctx *pulumi.Context, args *GetFsuCollectionsArgs, opts ...pulumi.InvokeOption) (*GetFsuCollectionsResult, error) {
	opts = internal.PkgInvokeDefaultOpts(opts)
	var rv GetFsuCollectionsResult
	err := ctx.Invoke("oci:FleetSoftwareUpdate/getFsuCollections:getFsuCollections", args, &rv, opts...)
	if err != nil {
		return nil, err
	}
	return &rv, nil
}

// A collection of arguments for invoking getFsuCollections.
type GetFsuCollectionsArgs struct {
	// The ID of the compartment in which to list resources.
	CompartmentId string `pulumi:"compartmentId"`
	// A filter to return only resources that match the entire display name given.
	DisplayName *string                   `pulumi:"displayName"`
	Filters     []GetFsuCollectionsFilter `pulumi:"filters"`
	// A filter to return only resources whose lifecycleState matches the given lifecycleState.
	State *string `pulumi:"state"`
	// A filter to return only resources whose type matches the given type.
	Type *string `pulumi:"type"`
}

// A collection of values returned by getFsuCollections.
type GetFsuCollectionsResult struct {
	// Compartment Identifier
	CompartmentId string `pulumi:"compartmentId"`
	// Exadata Fleet Update Collection resource display name.
	DisplayName *string                   `pulumi:"displayName"`
	Filters     []GetFsuCollectionsFilter `pulumi:"filters"`
	// The list of fsu_collection_summary_collection.
	FsuCollectionSummaryCollections []GetFsuCollectionsFsuCollectionSummaryCollection `pulumi:"fsuCollectionSummaryCollections"`
	// The provider-assigned unique ID for this managed resource.
	Id string `pulumi:"id"`
	// The current state of the Exadata Fleet Update Collection.
	State *string `pulumi:"state"`
	// Exadata Fleet Update Collection type.
	Type *string `pulumi:"type"`
}

func GetFsuCollectionsOutput(ctx *pulumi.Context, args GetFsuCollectionsOutputArgs, opts ...pulumi.InvokeOption) GetFsuCollectionsResultOutput {
	return pulumi.ToOutputWithContext(ctx.Context(), args).
		ApplyT(func(v interface{}) (GetFsuCollectionsResultOutput, error) {
			args := v.(GetFsuCollectionsArgs)
			options := pulumi.InvokeOutputOptions{InvokeOptions: internal.PkgInvokeDefaultOpts(opts)}
			return ctx.InvokeOutput("oci:FleetSoftwareUpdate/getFsuCollections:getFsuCollections", args, GetFsuCollectionsResultOutput{}, options).(GetFsuCollectionsResultOutput), nil
		}).(GetFsuCollectionsResultOutput)
}

// A collection of arguments for invoking getFsuCollections.
type GetFsuCollectionsOutputArgs struct {
	// The ID of the compartment in which to list resources.
	CompartmentId pulumi.StringInput `pulumi:"compartmentId"`
	// A filter to return only resources that match the entire display name given.
	DisplayName pulumi.StringPtrInput             `pulumi:"displayName"`
	Filters     GetFsuCollectionsFilterArrayInput `pulumi:"filters"`
	// A filter to return only resources whose lifecycleState matches the given lifecycleState.
	State pulumi.StringPtrInput `pulumi:"state"`
	// A filter to return only resources whose type matches the given type.
	Type pulumi.StringPtrInput `pulumi:"type"`
}

func (GetFsuCollectionsOutputArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*GetFsuCollectionsArgs)(nil)).Elem()
}

// A collection of values returned by getFsuCollections.
type GetFsuCollectionsResultOutput struct{ *pulumi.OutputState }

func (GetFsuCollectionsResultOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*GetFsuCollectionsResult)(nil)).Elem()
}

func (o GetFsuCollectionsResultOutput) ToGetFsuCollectionsResultOutput() GetFsuCollectionsResultOutput {
	return o
}

func (o GetFsuCollectionsResultOutput) ToGetFsuCollectionsResultOutputWithContext(ctx context.Context) GetFsuCollectionsResultOutput {
	return o
}

// Compartment Identifier
func (o GetFsuCollectionsResultOutput) CompartmentId() pulumi.StringOutput {
	return o.ApplyT(func(v GetFsuCollectionsResult) string { return v.CompartmentId }).(pulumi.StringOutput)
}

// Exadata Fleet Update Collection resource display name.
func (o GetFsuCollectionsResultOutput) DisplayName() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetFsuCollectionsResult) *string { return v.DisplayName }).(pulumi.StringPtrOutput)
}

func (o GetFsuCollectionsResultOutput) Filters() GetFsuCollectionsFilterArrayOutput {
	return o.ApplyT(func(v GetFsuCollectionsResult) []GetFsuCollectionsFilter { return v.Filters }).(GetFsuCollectionsFilterArrayOutput)
}

// The list of fsu_collection_summary_collection.
func (o GetFsuCollectionsResultOutput) FsuCollectionSummaryCollections() GetFsuCollectionsFsuCollectionSummaryCollectionArrayOutput {
	return o.ApplyT(func(v GetFsuCollectionsResult) []GetFsuCollectionsFsuCollectionSummaryCollection {
		return v.FsuCollectionSummaryCollections
	}).(GetFsuCollectionsFsuCollectionSummaryCollectionArrayOutput)
}

// The provider-assigned unique ID for this managed resource.
func (o GetFsuCollectionsResultOutput) Id() pulumi.StringOutput {
	return o.ApplyT(func(v GetFsuCollectionsResult) string { return v.Id }).(pulumi.StringOutput)
}

// The current state of the Exadata Fleet Update Collection.
func (o GetFsuCollectionsResultOutput) State() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetFsuCollectionsResult) *string { return v.State }).(pulumi.StringPtrOutput)
}

// Exadata Fleet Update Collection type.
func (o GetFsuCollectionsResultOutput) Type() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetFsuCollectionsResult) *string { return v.Type }).(pulumi.StringPtrOutput)
}

func init() {
	pulumi.RegisterOutputType(GetFsuCollectionsResultOutput{})
}
