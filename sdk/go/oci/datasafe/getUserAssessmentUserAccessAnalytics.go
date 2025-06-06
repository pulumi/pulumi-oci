// Code generated by pulumi-language-go DO NOT EDIT.
// *** WARNING: Do not edit by hand unless you're certain you know what you are doing! ***

package datasafe

import (
	"context"
	"reflect"

	"github.com/pulumi/pulumi-oci/sdk/v3/go/oci/internal"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This data source provides the list of User Assessment User Access Analytics in Oracle Cloud Infrastructure Data Safe service.
//
// Gets a list of aggregated user access analytics in the specified target in a compartment.
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
//			_, err := datasafe.GetUserAssessmentUserAccessAnalytics(ctx, &datasafe.GetUserAssessmentUserAccessAnalyticsArgs{
//				UserAssessmentId: testUserAssessment.Id,
//			}, nil)
//			if err != nil {
//				return err
//			}
//			return nil
//		})
//	}
//
// ```
func GetUserAssessmentUserAccessAnalytics(ctx *pulumi.Context, args *GetUserAssessmentUserAccessAnalyticsArgs, opts ...pulumi.InvokeOption) (*GetUserAssessmentUserAccessAnalyticsResult, error) {
	opts = internal.PkgInvokeDefaultOpts(opts)
	var rv GetUserAssessmentUserAccessAnalyticsResult
	err := ctx.Invoke("oci:DataSafe/getUserAssessmentUserAccessAnalytics:getUserAssessmentUserAccessAnalytics", args, &rv, opts...)
	if err != nil {
		return nil, err
	}
	return &rv, nil
}

// A collection of arguments for invoking getUserAssessmentUserAccessAnalytics.
type GetUserAssessmentUserAccessAnalyticsArgs struct {
	Filters []GetUserAssessmentUserAccessAnalyticsFilter `pulumi:"filters"`
	// The OCID of the user assessment.
	UserAssessmentId string `pulumi:"userAssessmentId"`
}

// A collection of values returned by getUserAssessmentUserAccessAnalytics.
type GetUserAssessmentUserAccessAnalyticsResult struct {
	Filters []GetUserAssessmentUserAccessAnalyticsFilter `pulumi:"filters"`
	// The provider-assigned unique ID for this managed resource.
	Id string `pulumi:"id"`
	// The list of user_access_analytics_collection.
	UserAccessAnalyticsCollections []GetUserAssessmentUserAccessAnalyticsUserAccessAnalyticsCollection `pulumi:"userAccessAnalyticsCollections"`
	UserAssessmentId               string                                                              `pulumi:"userAssessmentId"`
}

func GetUserAssessmentUserAccessAnalyticsOutput(ctx *pulumi.Context, args GetUserAssessmentUserAccessAnalyticsOutputArgs, opts ...pulumi.InvokeOption) GetUserAssessmentUserAccessAnalyticsResultOutput {
	return pulumi.ToOutputWithContext(ctx.Context(), args).
		ApplyT(func(v interface{}) (GetUserAssessmentUserAccessAnalyticsResultOutput, error) {
			args := v.(GetUserAssessmentUserAccessAnalyticsArgs)
			options := pulumi.InvokeOutputOptions{InvokeOptions: internal.PkgInvokeDefaultOpts(opts)}
			return ctx.InvokeOutput("oci:DataSafe/getUserAssessmentUserAccessAnalytics:getUserAssessmentUserAccessAnalytics", args, GetUserAssessmentUserAccessAnalyticsResultOutput{}, options).(GetUserAssessmentUserAccessAnalyticsResultOutput), nil
		}).(GetUserAssessmentUserAccessAnalyticsResultOutput)
}

// A collection of arguments for invoking getUserAssessmentUserAccessAnalytics.
type GetUserAssessmentUserAccessAnalyticsOutputArgs struct {
	Filters GetUserAssessmentUserAccessAnalyticsFilterArrayInput `pulumi:"filters"`
	// The OCID of the user assessment.
	UserAssessmentId pulumi.StringInput `pulumi:"userAssessmentId"`
}

func (GetUserAssessmentUserAccessAnalyticsOutputArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*GetUserAssessmentUserAccessAnalyticsArgs)(nil)).Elem()
}

// A collection of values returned by getUserAssessmentUserAccessAnalytics.
type GetUserAssessmentUserAccessAnalyticsResultOutput struct{ *pulumi.OutputState }

func (GetUserAssessmentUserAccessAnalyticsResultOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*GetUserAssessmentUserAccessAnalyticsResult)(nil)).Elem()
}

func (o GetUserAssessmentUserAccessAnalyticsResultOutput) ToGetUserAssessmentUserAccessAnalyticsResultOutput() GetUserAssessmentUserAccessAnalyticsResultOutput {
	return o
}

func (o GetUserAssessmentUserAccessAnalyticsResultOutput) ToGetUserAssessmentUserAccessAnalyticsResultOutputWithContext(ctx context.Context) GetUserAssessmentUserAccessAnalyticsResultOutput {
	return o
}

func (o GetUserAssessmentUserAccessAnalyticsResultOutput) Filters() GetUserAssessmentUserAccessAnalyticsFilterArrayOutput {
	return o.ApplyT(func(v GetUserAssessmentUserAccessAnalyticsResult) []GetUserAssessmentUserAccessAnalyticsFilter {
		return v.Filters
	}).(GetUserAssessmentUserAccessAnalyticsFilterArrayOutput)
}

// The provider-assigned unique ID for this managed resource.
func (o GetUserAssessmentUserAccessAnalyticsResultOutput) Id() pulumi.StringOutput {
	return o.ApplyT(func(v GetUserAssessmentUserAccessAnalyticsResult) string { return v.Id }).(pulumi.StringOutput)
}

// The list of user_access_analytics_collection.
func (o GetUserAssessmentUserAccessAnalyticsResultOutput) UserAccessAnalyticsCollections() GetUserAssessmentUserAccessAnalyticsUserAccessAnalyticsCollectionArrayOutput {
	return o.ApplyT(func(v GetUserAssessmentUserAccessAnalyticsResult) []GetUserAssessmentUserAccessAnalyticsUserAccessAnalyticsCollection {
		return v.UserAccessAnalyticsCollections
	}).(GetUserAssessmentUserAccessAnalyticsUserAccessAnalyticsCollectionArrayOutput)
}

func (o GetUserAssessmentUserAccessAnalyticsResultOutput) UserAssessmentId() pulumi.StringOutput {
	return o.ApplyT(func(v GetUserAssessmentUserAccessAnalyticsResult) string { return v.UserAssessmentId }).(pulumi.StringOutput)
}

func init() {
	pulumi.RegisterOutputType(GetUserAssessmentUserAccessAnalyticsResultOutput{})
}
