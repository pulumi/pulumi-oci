// Code generated by pulumi-language-go DO NOT EDIT.
// *** WARNING: Do not edit by hand unless you're certain you know what you are doing! ***

package loganalytics

import (
	"context"
	"reflect"

	"github.com/pulumi/pulumi-oci/sdk/v3/go/oci/internal"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This data source provides details about a specific Log Analytics Preference resource in Oracle Cloud Infrastructure Log Analytics service.
//
// Lists the tenant preferences such as DEFAULT_HOMEPAGE and collection properties.
//
// ## Example Usage
//
// ```go
// package main
//
// import (
//
//	"github.com/pulumi/pulumi-oci/sdk/v3/go/oci/loganalytics"
//	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
//
// )
//
//	func main() {
//		pulumi.Run(func(ctx *pulumi.Context) error {
//			_, err := loganalytics.GetLogAnalyticsPreference(ctx, &loganalytics.GetLogAnalyticsPreferenceArgs{
//				Namespace: logAnalyticsPreferenceNamespace,
//			}, nil)
//			if err != nil {
//				return err
//			}
//			return nil
//		})
//	}
//
// ```
func GetLogAnalyticsPreference(ctx *pulumi.Context, args *GetLogAnalyticsPreferenceArgs, opts ...pulumi.InvokeOption) (*GetLogAnalyticsPreferenceResult, error) {
	opts = internal.PkgInvokeDefaultOpts(opts)
	var rv GetLogAnalyticsPreferenceResult
	err := ctx.Invoke("oci:LogAnalytics/getLogAnalyticsPreference:getLogAnalyticsPreference", args, &rv, opts...)
	if err != nil {
		return nil, err
	}
	return &rv, nil
}

// A collection of arguments for invoking getLogAnalyticsPreference.
type GetLogAnalyticsPreferenceArgs struct {
	// The Logging Analytics namespace used for the request.
	Namespace string `pulumi:"namespace"`
}

// A collection of values returned by getLogAnalyticsPreference.
type GetLogAnalyticsPreferenceResult struct {
	// The provider-assigned unique ID for this managed resource.
	Id string `pulumi:"id"`
	// An array of tenant preferences.
	Items     []GetLogAnalyticsPreferenceItem `pulumi:"items"`
	Namespace string                          `pulumi:"namespace"`
}

func GetLogAnalyticsPreferenceOutput(ctx *pulumi.Context, args GetLogAnalyticsPreferenceOutputArgs, opts ...pulumi.InvokeOption) GetLogAnalyticsPreferenceResultOutput {
	return pulumi.ToOutputWithContext(ctx.Context(), args).
		ApplyT(func(v interface{}) (GetLogAnalyticsPreferenceResultOutput, error) {
			args := v.(GetLogAnalyticsPreferenceArgs)
			options := pulumi.InvokeOutputOptions{InvokeOptions: internal.PkgInvokeDefaultOpts(opts)}
			return ctx.InvokeOutput("oci:LogAnalytics/getLogAnalyticsPreference:getLogAnalyticsPreference", args, GetLogAnalyticsPreferenceResultOutput{}, options).(GetLogAnalyticsPreferenceResultOutput), nil
		}).(GetLogAnalyticsPreferenceResultOutput)
}

// A collection of arguments for invoking getLogAnalyticsPreference.
type GetLogAnalyticsPreferenceOutputArgs struct {
	// The Logging Analytics namespace used for the request.
	Namespace pulumi.StringInput `pulumi:"namespace"`
}

func (GetLogAnalyticsPreferenceOutputArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*GetLogAnalyticsPreferenceArgs)(nil)).Elem()
}

// A collection of values returned by getLogAnalyticsPreference.
type GetLogAnalyticsPreferenceResultOutput struct{ *pulumi.OutputState }

func (GetLogAnalyticsPreferenceResultOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*GetLogAnalyticsPreferenceResult)(nil)).Elem()
}

func (o GetLogAnalyticsPreferenceResultOutput) ToGetLogAnalyticsPreferenceResultOutput() GetLogAnalyticsPreferenceResultOutput {
	return o
}

func (o GetLogAnalyticsPreferenceResultOutput) ToGetLogAnalyticsPreferenceResultOutputWithContext(ctx context.Context) GetLogAnalyticsPreferenceResultOutput {
	return o
}

// The provider-assigned unique ID for this managed resource.
func (o GetLogAnalyticsPreferenceResultOutput) Id() pulumi.StringOutput {
	return o.ApplyT(func(v GetLogAnalyticsPreferenceResult) string { return v.Id }).(pulumi.StringOutput)
}

// An array of tenant preferences.
func (o GetLogAnalyticsPreferenceResultOutput) Items() GetLogAnalyticsPreferenceItemArrayOutput {
	return o.ApplyT(func(v GetLogAnalyticsPreferenceResult) []GetLogAnalyticsPreferenceItem { return v.Items }).(GetLogAnalyticsPreferenceItemArrayOutput)
}

func (o GetLogAnalyticsPreferenceResultOutput) Namespace() pulumi.StringOutput {
	return o.ApplyT(func(v GetLogAnalyticsPreferenceResult) string { return v.Namespace }).(pulumi.StringOutput)
}

func init() {
	pulumi.RegisterOutputType(GetLogAnalyticsPreferenceResultOutput{})
}
