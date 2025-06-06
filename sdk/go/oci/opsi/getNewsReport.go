// Code generated by pulumi-language-go DO NOT EDIT.
// *** WARNING: Do not edit by hand unless you're certain you know what you are doing! ***

package opsi

import (
	"context"
	"reflect"

	"github.com/pulumi/pulumi-oci/sdk/v3/go/oci/internal"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This data source provides details about a specific News Report resource in Oracle Cloud Infrastructure Opsi service.
//
// Gets details of a news report.
//
// ## Example Usage
//
// ```go
// package main
//
// import (
//
//	"github.com/pulumi/pulumi-oci/sdk/v3/go/oci/opsi"
//	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
//
// )
//
//	func main() {
//		pulumi.Run(func(ctx *pulumi.Context) error {
//			_, err := opsi.GetNewsReport(ctx, &opsi.GetNewsReportArgs{
//				NewsReportId: testNewsReportOciOpsiNewsReport.Id,
//			}, nil)
//			if err != nil {
//				return err
//			}
//			return nil
//		})
//	}
//
// ```
func LookupNewsReport(ctx *pulumi.Context, args *LookupNewsReportArgs, opts ...pulumi.InvokeOption) (*LookupNewsReportResult, error) {
	opts = internal.PkgInvokeDefaultOpts(opts)
	var rv LookupNewsReportResult
	err := ctx.Invoke("oci:Opsi/getNewsReport:getNewsReport", args, &rv, opts...)
	if err != nil {
		return nil, err
	}
	return &rv, nil
}

// A collection of arguments for invoking getNewsReport.
type LookupNewsReportArgs struct {
	// Unique news report identifier.
	NewsReportId string `pulumi:"newsReportId"`
}

// A collection of values returned by getNewsReport.
type LookupNewsReportResult struct {
	// A flag to consider the resources within a given compartment and all sub-compartments.
	AreChildCompartmentsIncluded bool `pulumi:"areChildCompartmentsIncluded"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
	CompartmentId string `pulumi:"compartmentId"`
	// Content types that the news report can handle.
	ContentTypes []GetNewsReportContentType `pulumi:"contentTypes"`
	// Day of the week in which the news report will be sent if the frequency is set to WEEKLY.
	DayOfWeek string `pulumi:"dayOfWeek"`
	// Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
	DefinedTags map[string]string `pulumi:"definedTags"`
	// The description of the news report.
	Description string `pulumi:"description"`
	// Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
	FreeformTags map[string]string `pulumi:"freeformTags"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the news report resource.
	Id string `pulumi:"id"`
	// A message describing the current state in more detail. For example, can be used to provide actionable information for a resource in Failed state.
	LifecycleDetails string `pulumi:"lifecycleDetails"`
	// Language of the news report.
	Locale string `pulumi:"locale"`
	// Match rule used for tag filters.
	MatchRule string `pulumi:"matchRule"`
	// The news report name.
	Name string `pulumi:"name"`
	// News report frequency.
	NewsFrequency string `pulumi:"newsFrequency"`
	NewsReportId  string `pulumi:"newsReportId"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the ONS topic.
	OnsTopicId string `pulumi:"onsTopicId"`
	// The current state of the news report.
	State string `pulumi:"state"`
	// Indicates the status of a news report in Ops Insights.
	Status string `pulumi:"status"`
	// System tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"orcl-cloud.free-tier-retained": "true"}`
	SystemTags map[string]string `pulumi:"systemTags"`
	// List of tag filters; each filter composed by a namespace, key, and value. Example for defined tags - '<TagNamespace>.<TagKey>=<TagValue>'. Example for freeform tags - '<TagKey>=<TagValue>'.
	TagFilters []string `pulumi:"tagFilters"`
	// The time the the news report was first enabled. An RFC3339 formatted datetime string.
	TimeCreated string `pulumi:"timeCreated"`
	// The time the news report was updated. An RFC3339 formatted datetime string.
	TimeUpdated string `pulumi:"timeUpdated"`
}

func LookupNewsReportOutput(ctx *pulumi.Context, args LookupNewsReportOutputArgs, opts ...pulumi.InvokeOption) LookupNewsReportResultOutput {
	return pulumi.ToOutputWithContext(ctx.Context(), args).
		ApplyT(func(v interface{}) (LookupNewsReportResultOutput, error) {
			args := v.(LookupNewsReportArgs)
			options := pulumi.InvokeOutputOptions{InvokeOptions: internal.PkgInvokeDefaultOpts(opts)}
			return ctx.InvokeOutput("oci:Opsi/getNewsReport:getNewsReport", args, LookupNewsReportResultOutput{}, options).(LookupNewsReportResultOutput), nil
		}).(LookupNewsReportResultOutput)
}

// A collection of arguments for invoking getNewsReport.
type LookupNewsReportOutputArgs struct {
	// Unique news report identifier.
	NewsReportId pulumi.StringInput `pulumi:"newsReportId"`
}

func (LookupNewsReportOutputArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*LookupNewsReportArgs)(nil)).Elem()
}

// A collection of values returned by getNewsReport.
type LookupNewsReportResultOutput struct{ *pulumi.OutputState }

func (LookupNewsReportResultOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*LookupNewsReportResult)(nil)).Elem()
}

func (o LookupNewsReportResultOutput) ToLookupNewsReportResultOutput() LookupNewsReportResultOutput {
	return o
}

func (o LookupNewsReportResultOutput) ToLookupNewsReportResultOutputWithContext(ctx context.Context) LookupNewsReportResultOutput {
	return o
}

// A flag to consider the resources within a given compartment and all sub-compartments.
func (o LookupNewsReportResultOutput) AreChildCompartmentsIncluded() pulumi.BoolOutput {
	return o.ApplyT(func(v LookupNewsReportResult) bool { return v.AreChildCompartmentsIncluded }).(pulumi.BoolOutput)
}

// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
func (o LookupNewsReportResultOutput) CompartmentId() pulumi.StringOutput {
	return o.ApplyT(func(v LookupNewsReportResult) string { return v.CompartmentId }).(pulumi.StringOutput)
}

// Content types that the news report can handle.
func (o LookupNewsReportResultOutput) ContentTypes() GetNewsReportContentTypeArrayOutput {
	return o.ApplyT(func(v LookupNewsReportResult) []GetNewsReportContentType { return v.ContentTypes }).(GetNewsReportContentTypeArrayOutput)
}

// Day of the week in which the news report will be sent if the frequency is set to WEEKLY.
func (o LookupNewsReportResultOutput) DayOfWeek() pulumi.StringOutput {
	return o.ApplyT(func(v LookupNewsReportResult) string { return v.DayOfWeek }).(pulumi.StringOutput)
}

// Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
func (o LookupNewsReportResultOutput) DefinedTags() pulumi.StringMapOutput {
	return o.ApplyT(func(v LookupNewsReportResult) map[string]string { return v.DefinedTags }).(pulumi.StringMapOutput)
}

// The description of the news report.
func (o LookupNewsReportResultOutput) Description() pulumi.StringOutput {
	return o.ApplyT(func(v LookupNewsReportResult) string { return v.Description }).(pulumi.StringOutput)
}

// Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
func (o LookupNewsReportResultOutput) FreeformTags() pulumi.StringMapOutput {
	return o.ApplyT(func(v LookupNewsReportResult) map[string]string { return v.FreeformTags }).(pulumi.StringMapOutput)
}

// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the news report resource.
func (o LookupNewsReportResultOutput) Id() pulumi.StringOutput {
	return o.ApplyT(func(v LookupNewsReportResult) string { return v.Id }).(pulumi.StringOutput)
}

// A message describing the current state in more detail. For example, can be used to provide actionable information for a resource in Failed state.
func (o LookupNewsReportResultOutput) LifecycleDetails() pulumi.StringOutput {
	return o.ApplyT(func(v LookupNewsReportResult) string { return v.LifecycleDetails }).(pulumi.StringOutput)
}

// Language of the news report.
func (o LookupNewsReportResultOutput) Locale() pulumi.StringOutput {
	return o.ApplyT(func(v LookupNewsReportResult) string { return v.Locale }).(pulumi.StringOutput)
}

// Match rule used for tag filters.
func (o LookupNewsReportResultOutput) MatchRule() pulumi.StringOutput {
	return o.ApplyT(func(v LookupNewsReportResult) string { return v.MatchRule }).(pulumi.StringOutput)
}

// The news report name.
func (o LookupNewsReportResultOutput) Name() pulumi.StringOutput {
	return o.ApplyT(func(v LookupNewsReportResult) string { return v.Name }).(pulumi.StringOutput)
}

// News report frequency.
func (o LookupNewsReportResultOutput) NewsFrequency() pulumi.StringOutput {
	return o.ApplyT(func(v LookupNewsReportResult) string { return v.NewsFrequency }).(pulumi.StringOutput)
}

func (o LookupNewsReportResultOutput) NewsReportId() pulumi.StringOutput {
	return o.ApplyT(func(v LookupNewsReportResult) string { return v.NewsReportId }).(pulumi.StringOutput)
}

// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the ONS topic.
func (o LookupNewsReportResultOutput) OnsTopicId() pulumi.StringOutput {
	return o.ApplyT(func(v LookupNewsReportResult) string { return v.OnsTopicId }).(pulumi.StringOutput)
}

// The current state of the news report.
func (o LookupNewsReportResultOutput) State() pulumi.StringOutput {
	return o.ApplyT(func(v LookupNewsReportResult) string { return v.State }).(pulumi.StringOutput)
}

// Indicates the status of a news report in Ops Insights.
func (o LookupNewsReportResultOutput) Status() pulumi.StringOutput {
	return o.ApplyT(func(v LookupNewsReportResult) string { return v.Status }).(pulumi.StringOutput)
}

// System tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"orcl-cloud.free-tier-retained": "true"}`
func (o LookupNewsReportResultOutput) SystemTags() pulumi.StringMapOutput {
	return o.ApplyT(func(v LookupNewsReportResult) map[string]string { return v.SystemTags }).(pulumi.StringMapOutput)
}

// List of tag filters; each filter composed by a namespace, key, and value. Example for defined tags - '<TagNamespace>.<TagKey>=<TagValue>'. Example for freeform tags - '<TagKey>=<TagValue>'.
func (o LookupNewsReportResultOutput) TagFilters() pulumi.StringArrayOutput {
	return o.ApplyT(func(v LookupNewsReportResult) []string { return v.TagFilters }).(pulumi.StringArrayOutput)
}

// The time the the news report was first enabled. An RFC3339 formatted datetime string.
func (o LookupNewsReportResultOutput) TimeCreated() pulumi.StringOutput {
	return o.ApplyT(func(v LookupNewsReportResult) string { return v.TimeCreated }).(pulumi.StringOutput)
}

// The time the news report was updated. An RFC3339 formatted datetime string.
func (o LookupNewsReportResultOutput) TimeUpdated() pulumi.StringOutput {
	return o.ApplyT(func(v LookupNewsReportResult) string { return v.TimeUpdated }).(pulumi.StringOutput)
}

func init() {
	pulumi.RegisterOutputType(LookupNewsReportResultOutput{})
}
