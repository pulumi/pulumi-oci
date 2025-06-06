// Code generated by pulumi-language-go DO NOT EDIT.
// *** WARNING: Do not edit by hand unless you're certain you know what you are doing! ***

package datasafe

import (
	"context"
	"reflect"

	"github.com/pulumi/pulumi-oci/sdk/v3/go/oci/internal"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This data source provides the list of Masking Analytics in Oracle Cloud Infrastructure Data Safe service.
//
// Gets consolidated masking analytics data based on the specified query parameters.
// If CompartmentIdInSubtreeQueryParam is specified as true, the behaviour
// is equivalent to accessLevel "ACCESSIBLE" by default.
//
// ## Example Usage
//
// ```go
// package main
//
// import (
//
//	"github.com/pulumi/pulumi-oci/sdk/v3/go/oci/datasafe"
//	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
//
// )
//
//	func main() {
//		pulumi.Run(func(ctx *pulumi.Context) error {
//			_, err := datasafe.GetMaskingAnalytics(ctx, &datasafe.GetMaskingAnalyticsArgs{
//				CompartmentId:          compartmentId,
//				CompartmentIdInSubtree: pulumi.BoolRef(maskingAnalyticCompartmentIdInSubtree),
//				GroupBy:                pulumi.StringRef(maskingAnalyticGroupBy),
//				MaskingPolicyId:        pulumi.StringRef(testMaskingPolicy.Id),
//				TargetId:               pulumi.StringRef(testTarget.Id),
//			}, nil)
//			if err != nil {
//				return err
//			}
//			return nil
//		})
//	}
//
// ```
func GetMaskingAnalytics(ctx *pulumi.Context, args *GetMaskingAnalyticsArgs, opts ...pulumi.InvokeOption) (*GetMaskingAnalyticsResult, error) {
	opts = internal.PkgInvokeDefaultOpts(opts)
	var rv GetMaskingAnalyticsResult
	err := ctx.Invoke("oci:DataSafe/getMaskingAnalytics:getMaskingAnalytics", args, &rv, opts...)
	if err != nil {
		return nil, err
	}
	return &rv, nil
}

// A collection of arguments for invoking getMaskingAnalytics.
type GetMaskingAnalyticsArgs struct {
	// A filter to return only resources that match the specified compartment OCID.
	CompartmentId string `pulumi:"compartmentId"`
	// Default is false. When set to true, the hierarchy of compartments is traversed and all compartments and subcompartments in the tenancy are returned. Depends on the 'accessLevel' setting.
	CompartmentIdInSubtree *bool                       `pulumi:"compartmentIdInSubtree"`
	Filters                []GetMaskingAnalyticsFilter `pulumi:"filters"`
	// Attribute by which the masking analytics data should be grouped.
	GroupBy *string `pulumi:"groupBy"`
	// A filter to return only the resources that match the specified masking policy OCID.
	MaskingPolicyId *string `pulumi:"maskingPolicyId"`
	// A filter to return only items related to a specific target OCID.
	TargetId *string `pulumi:"targetId"`
}

// A collection of values returned by getMaskingAnalytics.
type GetMaskingAnalyticsResult struct {
	CompartmentId          string                      `pulumi:"compartmentId"`
	CompartmentIdInSubtree *bool                       `pulumi:"compartmentIdInSubtree"`
	Filters                []GetMaskingAnalyticsFilter `pulumi:"filters"`
	GroupBy                *string                     `pulumi:"groupBy"`
	// The provider-assigned unique ID for this managed resource.
	Id string `pulumi:"id"`
	// The list of masking_analytics_collection.
	MaskingAnalyticsCollections []GetMaskingAnalyticsMaskingAnalyticsCollection `pulumi:"maskingAnalyticsCollections"`
	MaskingPolicyId             *string                                         `pulumi:"maskingPolicyId"`
	// The OCID of the target database.
	TargetId *string `pulumi:"targetId"`
}

func GetMaskingAnalyticsOutput(ctx *pulumi.Context, args GetMaskingAnalyticsOutputArgs, opts ...pulumi.InvokeOption) GetMaskingAnalyticsResultOutput {
	return pulumi.ToOutputWithContext(ctx.Context(), args).
		ApplyT(func(v interface{}) (GetMaskingAnalyticsResultOutput, error) {
			args := v.(GetMaskingAnalyticsArgs)
			options := pulumi.InvokeOutputOptions{InvokeOptions: internal.PkgInvokeDefaultOpts(opts)}
			return ctx.InvokeOutput("oci:DataSafe/getMaskingAnalytics:getMaskingAnalytics", args, GetMaskingAnalyticsResultOutput{}, options).(GetMaskingAnalyticsResultOutput), nil
		}).(GetMaskingAnalyticsResultOutput)
}

// A collection of arguments for invoking getMaskingAnalytics.
type GetMaskingAnalyticsOutputArgs struct {
	// A filter to return only resources that match the specified compartment OCID.
	CompartmentId pulumi.StringInput `pulumi:"compartmentId"`
	// Default is false. When set to true, the hierarchy of compartments is traversed and all compartments and subcompartments in the tenancy are returned. Depends on the 'accessLevel' setting.
	CompartmentIdInSubtree pulumi.BoolPtrInput                 `pulumi:"compartmentIdInSubtree"`
	Filters                GetMaskingAnalyticsFilterArrayInput `pulumi:"filters"`
	// Attribute by which the masking analytics data should be grouped.
	GroupBy pulumi.StringPtrInput `pulumi:"groupBy"`
	// A filter to return only the resources that match the specified masking policy OCID.
	MaskingPolicyId pulumi.StringPtrInput `pulumi:"maskingPolicyId"`
	// A filter to return only items related to a specific target OCID.
	TargetId pulumi.StringPtrInput `pulumi:"targetId"`
}

func (GetMaskingAnalyticsOutputArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*GetMaskingAnalyticsArgs)(nil)).Elem()
}

// A collection of values returned by getMaskingAnalytics.
type GetMaskingAnalyticsResultOutput struct{ *pulumi.OutputState }

func (GetMaskingAnalyticsResultOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*GetMaskingAnalyticsResult)(nil)).Elem()
}

func (o GetMaskingAnalyticsResultOutput) ToGetMaskingAnalyticsResultOutput() GetMaskingAnalyticsResultOutput {
	return o
}

func (o GetMaskingAnalyticsResultOutput) ToGetMaskingAnalyticsResultOutputWithContext(ctx context.Context) GetMaskingAnalyticsResultOutput {
	return o
}

func (o GetMaskingAnalyticsResultOutput) CompartmentId() pulumi.StringOutput {
	return o.ApplyT(func(v GetMaskingAnalyticsResult) string { return v.CompartmentId }).(pulumi.StringOutput)
}

func (o GetMaskingAnalyticsResultOutput) CompartmentIdInSubtree() pulumi.BoolPtrOutput {
	return o.ApplyT(func(v GetMaskingAnalyticsResult) *bool { return v.CompartmentIdInSubtree }).(pulumi.BoolPtrOutput)
}

func (o GetMaskingAnalyticsResultOutput) Filters() GetMaskingAnalyticsFilterArrayOutput {
	return o.ApplyT(func(v GetMaskingAnalyticsResult) []GetMaskingAnalyticsFilter { return v.Filters }).(GetMaskingAnalyticsFilterArrayOutput)
}

func (o GetMaskingAnalyticsResultOutput) GroupBy() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetMaskingAnalyticsResult) *string { return v.GroupBy }).(pulumi.StringPtrOutput)
}

// The provider-assigned unique ID for this managed resource.
func (o GetMaskingAnalyticsResultOutput) Id() pulumi.StringOutput {
	return o.ApplyT(func(v GetMaskingAnalyticsResult) string { return v.Id }).(pulumi.StringOutput)
}

// The list of masking_analytics_collection.
func (o GetMaskingAnalyticsResultOutput) MaskingAnalyticsCollections() GetMaskingAnalyticsMaskingAnalyticsCollectionArrayOutput {
	return o.ApplyT(func(v GetMaskingAnalyticsResult) []GetMaskingAnalyticsMaskingAnalyticsCollection {
		return v.MaskingAnalyticsCollections
	}).(GetMaskingAnalyticsMaskingAnalyticsCollectionArrayOutput)
}

func (o GetMaskingAnalyticsResultOutput) MaskingPolicyId() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetMaskingAnalyticsResult) *string { return v.MaskingPolicyId }).(pulumi.StringPtrOutput)
}

// The OCID of the target database.
func (o GetMaskingAnalyticsResultOutput) TargetId() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetMaskingAnalyticsResult) *string { return v.TargetId }).(pulumi.StringPtrOutput)
}

func init() {
	pulumi.RegisterOutputType(GetMaskingAnalyticsResultOutput{})
}
