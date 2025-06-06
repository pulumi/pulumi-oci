// Code generated by pulumi-language-go DO NOT EDIT.
// *** WARNING: Do not edit by hand unless you're certain you know what you are doing! ***

package datasafe

import (
	"context"
	"reflect"

	"github.com/pulumi/pulumi-oci/sdk/v3/go/oci/internal"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This data source provides details about a specific Security Assessment resource in Oracle Cloud Infrastructure Data Safe service.
//
// Gets the details of the specified security assessment.
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
//			_, err := datasafe.GetSecurityAssessment(ctx, &datasafe.GetSecurityAssessmentArgs{
//				SecurityAssessmentId: testSecurityAssessmentOciDataSafeSecurityAssessment.Id,
//			}, nil)
//			if err != nil {
//				return err
//			}
//			return nil
//		})
//	}
//
// ```
func LookupSecurityAssessment(ctx *pulumi.Context, args *LookupSecurityAssessmentArgs, opts ...pulumi.InvokeOption) (*LookupSecurityAssessmentResult, error) {
	opts = internal.PkgInvokeDefaultOpts(opts)
	var rv LookupSecurityAssessmentResult
	err := ctx.Invoke("oci:DataSafe/getSecurityAssessment:getSecurityAssessment", args, &rv, opts...)
	if err != nil {
		return nil, err
	}
	return &rv, nil
}

// A collection of arguments for invoking getSecurityAssessment.
type LookupSecurityAssessmentArgs struct {
	// The OCID of the security assessment.
	SecurityAssessmentId string `pulumi:"securityAssessmentId"`
}

// A collection of values returned by getSecurityAssessment.
type LookupSecurityAssessmentResult struct {
	// The OCID of the compartment that contains the security assessment.
	CompartmentId string `pulumi:"compartmentId"`
	// Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm) Example: `{"Operations.CostCenter": "42"}`
	DefinedTags map[string]string `pulumi:"definedTags"`
	// The description of the security assessment.
	Description string `pulumi:"description"`
	// The display name of the security assessment.
	DisplayName string `pulumi:"displayName"`
	// Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm)  Example: `{"Department": "Finance"}`
	FreeformTags map[string]string `pulumi:"freeformTags"`
	// The OCID of the security assessment.
	Id string `pulumi:"id"`
	// List containing maps as values. Example: `{"Operations": [ {"CostCenter": "42"} ] }`
	IgnoredAssessmentIds []string `pulumi:"ignoredAssessmentIds"`
	// List containing maps as values. Example: `{"Operations": [ {"CostCenter": "42"} ] }`
	IgnoredTargets []string `pulumi:"ignoredTargets"`
	// Indicates whether the assessment is scheduled to run.
	IsAssessmentScheduled bool `pulumi:"isAssessmentScheduled"`
	// Indicates whether or not the security assessment is set as a baseline. This is applicable only for saved security assessments.
	IsBaseline bool `pulumi:"isBaseline"`
	// Indicates whether or not the security assessment deviates from the baseline.
	IsDeviatedFromBaseline bool `pulumi:"isDeviatedFromBaseline"`
	// The OCID of the baseline against which the latest security assessment was compared.
	LastComparedBaselineId string `pulumi:"lastComparedBaselineId"`
	// Details about the current state of the security assessment.
	LifecycleDetails string `pulumi:"lifecycleDetails"`
	// The summary of findings for the security assessment.
	Link string `pulumi:"link"`
	// Schedule of the assessment that runs periodically in the specified format: - <version-string>;<version-specific-schedule>
	Schedule string `pulumi:"schedule"`
	// The OCID of the security assessment that is responsible for creating this scheduled save assessment.
	ScheduleSecurityAssessmentId string `pulumi:"scheduleSecurityAssessmentId"`
	SecurityAssessmentId         string `pulumi:"securityAssessmentId"`
	// The current state of the security assessment.
	State string `pulumi:"state"`
	// Statistics showing the number of findings for each category grouped by risk levels for all the targets in the specified security assessment.
	Statistics []GetSecurityAssessmentStatistic `pulumi:"statistics"`
	// System tags for this resource. Each key is predefined and scoped to a namespace. For more information, see Resource Tags. Example: `{"orcl-cloud.free-tier-retained": "true"}`
	SystemTags map[string]string `pulumi:"systemTags"`
	TargetId   string            `pulumi:"targetId"`
	// Array of database target OCIDs.
	TargetIds []string `pulumi:"targetIds"`
	// The version of the target database.
	TargetVersion string `pulumi:"targetVersion"`
	// The date and time the security assessment was created, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).
	TimeCreated string `pulumi:"timeCreated"`
	// The date and time the security assessment was last executed, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).
	TimeLastAssessed string `pulumi:"timeLastAssessed"`
	// The date and time the security assessment was last updated, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).
	TimeUpdated string `pulumi:"timeUpdated"`
	// Indicates whether the security assessment was created by system or by a user.
	TriggeredBy string `pulumi:"triggeredBy"`
	// The type of this security assessment. The possible types are:
	Type string `pulumi:"type"`
}

func LookupSecurityAssessmentOutput(ctx *pulumi.Context, args LookupSecurityAssessmentOutputArgs, opts ...pulumi.InvokeOption) LookupSecurityAssessmentResultOutput {
	return pulumi.ToOutputWithContext(ctx.Context(), args).
		ApplyT(func(v interface{}) (LookupSecurityAssessmentResultOutput, error) {
			args := v.(LookupSecurityAssessmentArgs)
			options := pulumi.InvokeOutputOptions{InvokeOptions: internal.PkgInvokeDefaultOpts(opts)}
			return ctx.InvokeOutput("oci:DataSafe/getSecurityAssessment:getSecurityAssessment", args, LookupSecurityAssessmentResultOutput{}, options).(LookupSecurityAssessmentResultOutput), nil
		}).(LookupSecurityAssessmentResultOutput)
}

// A collection of arguments for invoking getSecurityAssessment.
type LookupSecurityAssessmentOutputArgs struct {
	// The OCID of the security assessment.
	SecurityAssessmentId pulumi.StringInput `pulumi:"securityAssessmentId"`
}

func (LookupSecurityAssessmentOutputArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*LookupSecurityAssessmentArgs)(nil)).Elem()
}

// A collection of values returned by getSecurityAssessment.
type LookupSecurityAssessmentResultOutput struct{ *pulumi.OutputState }

func (LookupSecurityAssessmentResultOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*LookupSecurityAssessmentResult)(nil)).Elem()
}

func (o LookupSecurityAssessmentResultOutput) ToLookupSecurityAssessmentResultOutput() LookupSecurityAssessmentResultOutput {
	return o
}

func (o LookupSecurityAssessmentResultOutput) ToLookupSecurityAssessmentResultOutputWithContext(ctx context.Context) LookupSecurityAssessmentResultOutput {
	return o
}

// The OCID of the compartment that contains the security assessment.
func (o LookupSecurityAssessmentResultOutput) CompartmentId() pulumi.StringOutput {
	return o.ApplyT(func(v LookupSecurityAssessmentResult) string { return v.CompartmentId }).(pulumi.StringOutput)
}

// Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm) Example: `{"Operations.CostCenter": "42"}`
func (o LookupSecurityAssessmentResultOutput) DefinedTags() pulumi.StringMapOutput {
	return o.ApplyT(func(v LookupSecurityAssessmentResult) map[string]string { return v.DefinedTags }).(pulumi.StringMapOutput)
}

// The description of the security assessment.
func (o LookupSecurityAssessmentResultOutput) Description() pulumi.StringOutput {
	return o.ApplyT(func(v LookupSecurityAssessmentResult) string { return v.Description }).(pulumi.StringOutput)
}

// The display name of the security assessment.
func (o LookupSecurityAssessmentResultOutput) DisplayName() pulumi.StringOutput {
	return o.ApplyT(func(v LookupSecurityAssessmentResult) string { return v.DisplayName }).(pulumi.StringOutput)
}

// Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm)  Example: `{"Department": "Finance"}`
func (o LookupSecurityAssessmentResultOutput) FreeformTags() pulumi.StringMapOutput {
	return o.ApplyT(func(v LookupSecurityAssessmentResult) map[string]string { return v.FreeformTags }).(pulumi.StringMapOutput)
}

// The OCID of the security assessment.
func (o LookupSecurityAssessmentResultOutput) Id() pulumi.StringOutput {
	return o.ApplyT(func(v LookupSecurityAssessmentResult) string { return v.Id }).(pulumi.StringOutput)
}

// List containing maps as values. Example: `{"Operations": [ {"CostCenter": "42"} ] }`
func (o LookupSecurityAssessmentResultOutput) IgnoredAssessmentIds() pulumi.StringArrayOutput {
	return o.ApplyT(func(v LookupSecurityAssessmentResult) []string { return v.IgnoredAssessmentIds }).(pulumi.StringArrayOutput)
}

// List containing maps as values. Example: `{"Operations": [ {"CostCenter": "42"} ] }`
func (o LookupSecurityAssessmentResultOutput) IgnoredTargets() pulumi.StringArrayOutput {
	return o.ApplyT(func(v LookupSecurityAssessmentResult) []string { return v.IgnoredTargets }).(pulumi.StringArrayOutput)
}

// Indicates whether the assessment is scheduled to run.
func (o LookupSecurityAssessmentResultOutput) IsAssessmentScheduled() pulumi.BoolOutput {
	return o.ApplyT(func(v LookupSecurityAssessmentResult) bool { return v.IsAssessmentScheduled }).(pulumi.BoolOutput)
}

// Indicates whether or not the security assessment is set as a baseline. This is applicable only for saved security assessments.
func (o LookupSecurityAssessmentResultOutput) IsBaseline() pulumi.BoolOutput {
	return o.ApplyT(func(v LookupSecurityAssessmentResult) bool { return v.IsBaseline }).(pulumi.BoolOutput)
}

// Indicates whether or not the security assessment deviates from the baseline.
func (o LookupSecurityAssessmentResultOutput) IsDeviatedFromBaseline() pulumi.BoolOutput {
	return o.ApplyT(func(v LookupSecurityAssessmentResult) bool { return v.IsDeviatedFromBaseline }).(pulumi.BoolOutput)
}

// The OCID of the baseline against which the latest security assessment was compared.
func (o LookupSecurityAssessmentResultOutput) LastComparedBaselineId() pulumi.StringOutput {
	return o.ApplyT(func(v LookupSecurityAssessmentResult) string { return v.LastComparedBaselineId }).(pulumi.StringOutput)
}

// Details about the current state of the security assessment.
func (o LookupSecurityAssessmentResultOutput) LifecycleDetails() pulumi.StringOutput {
	return o.ApplyT(func(v LookupSecurityAssessmentResult) string { return v.LifecycleDetails }).(pulumi.StringOutput)
}

// The summary of findings for the security assessment.
func (o LookupSecurityAssessmentResultOutput) Link() pulumi.StringOutput {
	return o.ApplyT(func(v LookupSecurityAssessmentResult) string { return v.Link }).(pulumi.StringOutput)
}

// Schedule of the assessment that runs periodically in the specified format: - <version-string>;<version-specific-schedule>
func (o LookupSecurityAssessmentResultOutput) Schedule() pulumi.StringOutput {
	return o.ApplyT(func(v LookupSecurityAssessmentResult) string { return v.Schedule }).(pulumi.StringOutput)
}

// The OCID of the security assessment that is responsible for creating this scheduled save assessment.
func (o LookupSecurityAssessmentResultOutput) ScheduleSecurityAssessmentId() pulumi.StringOutput {
	return o.ApplyT(func(v LookupSecurityAssessmentResult) string { return v.ScheduleSecurityAssessmentId }).(pulumi.StringOutput)
}

func (o LookupSecurityAssessmentResultOutput) SecurityAssessmentId() pulumi.StringOutput {
	return o.ApplyT(func(v LookupSecurityAssessmentResult) string { return v.SecurityAssessmentId }).(pulumi.StringOutput)
}

// The current state of the security assessment.
func (o LookupSecurityAssessmentResultOutput) State() pulumi.StringOutput {
	return o.ApplyT(func(v LookupSecurityAssessmentResult) string { return v.State }).(pulumi.StringOutput)
}

// Statistics showing the number of findings for each category grouped by risk levels for all the targets in the specified security assessment.
func (o LookupSecurityAssessmentResultOutput) Statistics() GetSecurityAssessmentStatisticArrayOutput {
	return o.ApplyT(func(v LookupSecurityAssessmentResult) []GetSecurityAssessmentStatistic { return v.Statistics }).(GetSecurityAssessmentStatisticArrayOutput)
}

// System tags for this resource. Each key is predefined and scoped to a namespace. For more information, see Resource Tags. Example: `{"orcl-cloud.free-tier-retained": "true"}`
func (o LookupSecurityAssessmentResultOutput) SystemTags() pulumi.StringMapOutput {
	return o.ApplyT(func(v LookupSecurityAssessmentResult) map[string]string { return v.SystemTags }).(pulumi.StringMapOutput)
}

func (o LookupSecurityAssessmentResultOutput) TargetId() pulumi.StringOutput {
	return o.ApplyT(func(v LookupSecurityAssessmentResult) string { return v.TargetId }).(pulumi.StringOutput)
}

// Array of database target OCIDs.
func (o LookupSecurityAssessmentResultOutput) TargetIds() pulumi.StringArrayOutput {
	return o.ApplyT(func(v LookupSecurityAssessmentResult) []string { return v.TargetIds }).(pulumi.StringArrayOutput)
}

// The version of the target database.
func (o LookupSecurityAssessmentResultOutput) TargetVersion() pulumi.StringOutput {
	return o.ApplyT(func(v LookupSecurityAssessmentResult) string { return v.TargetVersion }).(pulumi.StringOutput)
}

// The date and time the security assessment was created, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).
func (o LookupSecurityAssessmentResultOutput) TimeCreated() pulumi.StringOutput {
	return o.ApplyT(func(v LookupSecurityAssessmentResult) string { return v.TimeCreated }).(pulumi.StringOutput)
}

// The date and time the security assessment was last executed, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).
func (o LookupSecurityAssessmentResultOutput) TimeLastAssessed() pulumi.StringOutput {
	return o.ApplyT(func(v LookupSecurityAssessmentResult) string { return v.TimeLastAssessed }).(pulumi.StringOutput)
}

// The date and time the security assessment was last updated, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).
func (o LookupSecurityAssessmentResultOutput) TimeUpdated() pulumi.StringOutput {
	return o.ApplyT(func(v LookupSecurityAssessmentResult) string { return v.TimeUpdated }).(pulumi.StringOutput)
}

// Indicates whether the security assessment was created by system or by a user.
func (o LookupSecurityAssessmentResultOutput) TriggeredBy() pulumi.StringOutput {
	return o.ApplyT(func(v LookupSecurityAssessmentResult) string { return v.TriggeredBy }).(pulumi.StringOutput)
}

// The type of this security assessment. The possible types are:
func (o LookupSecurityAssessmentResultOutput) Type() pulumi.StringOutput {
	return o.ApplyT(func(v LookupSecurityAssessmentResult) string { return v.Type }).(pulumi.StringOutput)
}

func init() {
	pulumi.RegisterOutputType(LookupSecurityAssessmentResultOutput{})
}
