// Code generated by pulumi-language-go DO NOT EDIT.
// *** WARNING: Do not edit by hand unless you're certain you know what you are doing! ***

package loganalytics

import (
	"context"
	"reflect"

	"github.com/pulumi/pulumi-oci/sdk/v3/go/oci/internal"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This data source provides details about a specific Namespace Rules Summary resource in Oracle Cloud Infrastructure Log Analytics service.
//
// Returns the count of detection rules in a compartment.
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
//			_, err := loganalytics.GetNamespaceRulesSummary(ctx, &loganalytics.GetNamespaceRulesSummaryArgs{
//				CompartmentId: compartmentId,
//				Namespace:     namespaceRulesSummaryNamespace,
//			}, nil)
//			if err != nil {
//				return err
//			}
//			return nil
//		})
//	}
//
// ```
func GetNamespaceRulesSummary(ctx *pulumi.Context, args *GetNamespaceRulesSummaryArgs, opts ...pulumi.InvokeOption) (*GetNamespaceRulesSummaryResult, error) {
	opts = internal.PkgInvokeDefaultOpts(opts)
	var rv GetNamespaceRulesSummaryResult
	err := ctx.Invoke("oci:LogAnalytics/getNamespaceRulesSummary:getNamespaceRulesSummary", args, &rv, opts...)
	if err != nil {
		return nil, err
	}
	return &rv, nil
}

// A collection of arguments for invoking getNamespaceRulesSummary.
type GetNamespaceRulesSummaryArgs struct {
	// The ID of the compartment in which to list resources.
	CompartmentId string `pulumi:"compartmentId"`
	// The Logging Analytics namespace used for the request.
	Namespace string `pulumi:"namespace"`
}

// A collection of values returned by getNamespaceRulesSummary.
type GetNamespaceRulesSummaryResult struct {
	CompartmentId string `pulumi:"compartmentId"`
	// The provider-assigned unique ID for this managed resource.
	Id string `pulumi:"id"`
	// The count of ingest time rules.
	IngestTimeRulesCount int    `pulumi:"ingestTimeRulesCount"`
	Namespace            string `pulumi:"namespace"`
	// The count of saved search rules.
	SavedSearchRulesCount int `pulumi:"savedSearchRulesCount"`
	// The total count of detection rules.
	TotalCount int `pulumi:"totalCount"`
}

func GetNamespaceRulesSummaryOutput(ctx *pulumi.Context, args GetNamespaceRulesSummaryOutputArgs, opts ...pulumi.InvokeOption) GetNamespaceRulesSummaryResultOutput {
	return pulumi.ToOutputWithContext(ctx.Context(), args).
		ApplyT(func(v interface{}) (GetNamespaceRulesSummaryResultOutput, error) {
			args := v.(GetNamespaceRulesSummaryArgs)
			options := pulumi.InvokeOutputOptions{InvokeOptions: internal.PkgInvokeDefaultOpts(opts)}
			return ctx.InvokeOutput("oci:LogAnalytics/getNamespaceRulesSummary:getNamespaceRulesSummary", args, GetNamespaceRulesSummaryResultOutput{}, options).(GetNamespaceRulesSummaryResultOutput), nil
		}).(GetNamespaceRulesSummaryResultOutput)
}

// A collection of arguments for invoking getNamespaceRulesSummary.
type GetNamespaceRulesSummaryOutputArgs struct {
	// The ID of the compartment in which to list resources.
	CompartmentId pulumi.StringInput `pulumi:"compartmentId"`
	// The Logging Analytics namespace used for the request.
	Namespace pulumi.StringInput `pulumi:"namespace"`
}

func (GetNamespaceRulesSummaryOutputArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*GetNamespaceRulesSummaryArgs)(nil)).Elem()
}

// A collection of values returned by getNamespaceRulesSummary.
type GetNamespaceRulesSummaryResultOutput struct{ *pulumi.OutputState }

func (GetNamespaceRulesSummaryResultOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*GetNamespaceRulesSummaryResult)(nil)).Elem()
}

func (o GetNamespaceRulesSummaryResultOutput) ToGetNamespaceRulesSummaryResultOutput() GetNamespaceRulesSummaryResultOutput {
	return o
}

func (o GetNamespaceRulesSummaryResultOutput) ToGetNamespaceRulesSummaryResultOutputWithContext(ctx context.Context) GetNamespaceRulesSummaryResultOutput {
	return o
}

func (o GetNamespaceRulesSummaryResultOutput) CompartmentId() pulumi.StringOutput {
	return o.ApplyT(func(v GetNamespaceRulesSummaryResult) string { return v.CompartmentId }).(pulumi.StringOutput)
}

// The provider-assigned unique ID for this managed resource.
func (o GetNamespaceRulesSummaryResultOutput) Id() pulumi.StringOutput {
	return o.ApplyT(func(v GetNamespaceRulesSummaryResult) string { return v.Id }).(pulumi.StringOutput)
}

// The count of ingest time rules.
func (o GetNamespaceRulesSummaryResultOutput) IngestTimeRulesCount() pulumi.IntOutput {
	return o.ApplyT(func(v GetNamespaceRulesSummaryResult) int { return v.IngestTimeRulesCount }).(pulumi.IntOutput)
}

func (o GetNamespaceRulesSummaryResultOutput) Namespace() pulumi.StringOutput {
	return o.ApplyT(func(v GetNamespaceRulesSummaryResult) string { return v.Namespace }).(pulumi.StringOutput)
}

// The count of saved search rules.
func (o GetNamespaceRulesSummaryResultOutput) SavedSearchRulesCount() pulumi.IntOutput {
	return o.ApplyT(func(v GetNamespaceRulesSummaryResult) int { return v.SavedSearchRulesCount }).(pulumi.IntOutput)
}

// The total count of detection rules.
func (o GetNamespaceRulesSummaryResultOutput) TotalCount() pulumi.IntOutput {
	return o.ApplyT(func(v GetNamespaceRulesSummaryResult) int { return v.TotalCount }).(pulumi.IntOutput)
}

func init() {
	pulumi.RegisterOutputType(GetNamespaceRulesSummaryResultOutput{})
}
