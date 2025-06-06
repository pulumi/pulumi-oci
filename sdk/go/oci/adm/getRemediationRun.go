// Code generated by pulumi-language-go DO NOT EDIT.
// *** WARNING: Do not edit by hand unless you're certain you know what you are doing! ***

package adm

import (
	"context"
	"reflect"

	"github.com/pulumi/pulumi-oci/sdk/v3/go/oci/internal"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This data source provides details about a specific Remediation Run resource in Oracle Cloud Infrastructure Adm service.
//
// Returns the details of the specified remediation run.
//
// ## Example Usage
//
// ```go
// package main
//
// import (
//
//	"github.com/pulumi/pulumi-oci/sdk/v3/go/oci/adm"
//	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
//
// )
//
//	func main() {
//		pulumi.Run(func(ctx *pulumi.Context) error {
//			_, err := adm.GetRemediationRun(ctx, &adm.GetRemediationRunArgs{
//				RemediationRunId: testRemediationRunOciAdmRemediationRun.Id,
//			}, nil)
//			if err != nil {
//				return err
//			}
//			return nil
//		})
//	}
//
// ```
func LookupRemediationRun(ctx *pulumi.Context, args *LookupRemediationRunArgs, opts ...pulumi.InvokeOption) (*LookupRemediationRunResult, error) {
	opts = internal.PkgInvokeDefaultOpts(opts)
	var rv LookupRemediationRunResult
	err := ctx.Invoke("oci:Adm/getRemediationRun:getRemediationRun", args, &rv, opts...)
	if err != nil {
		return nil, err
	}
	return &rv, nil
}

// A collection of arguments for invoking getRemediationRun.
type LookupRemediationRunArgs struct {
	// Unique Remediation Run identifier path parameter.
	RemediationRunId string `pulumi:"remediationRunId"`
}

// A collection of values returned by getRemediationRun.
type LookupRemediationRunResult struct {
	// The compartment Oracle Cloud Identifier ([OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm)) of the remediation run.
	CompartmentId string `pulumi:"compartmentId"`
	// The type of the current stage of the remediation run.
	CurrentStageType string `pulumi:"currentStageType"`
	// Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
	DefinedTags map[string]string `pulumi:"definedTags"`
	// The name of the remediation run.
	DisplayName string `pulumi:"displayName"`
	// Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
	FreeformTags map[string]string `pulumi:"freeformTags"`
	// The Oracle Cloud Identifier ([OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm)) of the remediation run.
	Id string `pulumi:"id"`
	// The Oracle Cloud Identifier ([OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm)) of the Remediation Recipe.
	RemediationRecipeId string `pulumi:"remediationRecipeId"`
	RemediationRunId    string `pulumi:"remediationRunId"`
	// The source that triggered the Remediation Recipe.
	RemediationRunSource string `pulumi:"remediationRunSource"`
	// The list of remediation run stage summaries.
	Stages []GetRemediationRunStage `pulumi:"stages"`
	// The current lifecycle state of the remediation run.
	State string `pulumi:"state"`
	// Usage of system tag keys. These predefined keys are scoped to namespaces. Example: `{"orcl-cloud.free-tier-retained": "true"}`
	SystemTags map[string]string `pulumi:"systemTags"`
	// The creation date and time of the remediation run (formatted according to [RFC3339](https://datatracker.ietf.org/doc/html/rfc3339)).
	TimeCreated string `pulumi:"timeCreated"`
	// The date and time of the finish of the remediation run (formatted according to [RFC3339](https://datatracker.ietf.org/doc/html/rfc3339)).
	TimeFinished string `pulumi:"timeFinished"`
	// The date and time of the start of the remediation run (formatted according to [RFC3339](https://datatracker.ietf.org/doc/html/rfc3339)).
	TimeStarted string `pulumi:"timeStarted"`
	// The date and time the remediation run was last updated (formatted according to [RFC3339](https://datatracker.ietf.org/doc/html/rfc3339)).
	TimeUpdated string `pulumi:"timeUpdated"`
}

func LookupRemediationRunOutput(ctx *pulumi.Context, args LookupRemediationRunOutputArgs, opts ...pulumi.InvokeOption) LookupRemediationRunResultOutput {
	return pulumi.ToOutputWithContext(ctx.Context(), args).
		ApplyT(func(v interface{}) (LookupRemediationRunResultOutput, error) {
			args := v.(LookupRemediationRunArgs)
			options := pulumi.InvokeOutputOptions{InvokeOptions: internal.PkgInvokeDefaultOpts(opts)}
			return ctx.InvokeOutput("oci:Adm/getRemediationRun:getRemediationRun", args, LookupRemediationRunResultOutput{}, options).(LookupRemediationRunResultOutput), nil
		}).(LookupRemediationRunResultOutput)
}

// A collection of arguments for invoking getRemediationRun.
type LookupRemediationRunOutputArgs struct {
	// Unique Remediation Run identifier path parameter.
	RemediationRunId pulumi.StringInput `pulumi:"remediationRunId"`
}

func (LookupRemediationRunOutputArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*LookupRemediationRunArgs)(nil)).Elem()
}

// A collection of values returned by getRemediationRun.
type LookupRemediationRunResultOutput struct{ *pulumi.OutputState }

func (LookupRemediationRunResultOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*LookupRemediationRunResult)(nil)).Elem()
}

func (o LookupRemediationRunResultOutput) ToLookupRemediationRunResultOutput() LookupRemediationRunResultOutput {
	return o
}

func (o LookupRemediationRunResultOutput) ToLookupRemediationRunResultOutputWithContext(ctx context.Context) LookupRemediationRunResultOutput {
	return o
}

// The compartment Oracle Cloud Identifier ([OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm)) of the remediation run.
func (o LookupRemediationRunResultOutput) CompartmentId() pulumi.StringOutput {
	return o.ApplyT(func(v LookupRemediationRunResult) string { return v.CompartmentId }).(pulumi.StringOutput)
}

// The type of the current stage of the remediation run.
func (o LookupRemediationRunResultOutput) CurrentStageType() pulumi.StringOutput {
	return o.ApplyT(func(v LookupRemediationRunResult) string { return v.CurrentStageType }).(pulumi.StringOutput)
}

// Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
func (o LookupRemediationRunResultOutput) DefinedTags() pulumi.StringMapOutput {
	return o.ApplyT(func(v LookupRemediationRunResult) map[string]string { return v.DefinedTags }).(pulumi.StringMapOutput)
}

// The name of the remediation run.
func (o LookupRemediationRunResultOutput) DisplayName() pulumi.StringOutput {
	return o.ApplyT(func(v LookupRemediationRunResult) string { return v.DisplayName }).(pulumi.StringOutput)
}

// Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
func (o LookupRemediationRunResultOutput) FreeformTags() pulumi.StringMapOutput {
	return o.ApplyT(func(v LookupRemediationRunResult) map[string]string { return v.FreeformTags }).(pulumi.StringMapOutput)
}

// The Oracle Cloud Identifier ([OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm)) of the remediation run.
func (o LookupRemediationRunResultOutput) Id() pulumi.StringOutput {
	return o.ApplyT(func(v LookupRemediationRunResult) string { return v.Id }).(pulumi.StringOutput)
}

// The Oracle Cloud Identifier ([OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm)) of the Remediation Recipe.
func (o LookupRemediationRunResultOutput) RemediationRecipeId() pulumi.StringOutput {
	return o.ApplyT(func(v LookupRemediationRunResult) string { return v.RemediationRecipeId }).(pulumi.StringOutput)
}

func (o LookupRemediationRunResultOutput) RemediationRunId() pulumi.StringOutput {
	return o.ApplyT(func(v LookupRemediationRunResult) string { return v.RemediationRunId }).(pulumi.StringOutput)
}

// The source that triggered the Remediation Recipe.
func (o LookupRemediationRunResultOutput) RemediationRunSource() pulumi.StringOutput {
	return o.ApplyT(func(v LookupRemediationRunResult) string { return v.RemediationRunSource }).(pulumi.StringOutput)
}

// The list of remediation run stage summaries.
func (o LookupRemediationRunResultOutput) Stages() GetRemediationRunStageArrayOutput {
	return o.ApplyT(func(v LookupRemediationRunResult) []GetRemediationRunStage { return v.Stages }).(GetRemediationRunStageArrayOutput)
}

// The current lifecycle state of the remediation run.
func (o LookupRemediationRunResultOutput) State() pulumi.StringOutput {
	return o.ApplyT(func(v LookupRemediationRunResult) string { return v.State }).(pulumi.StringOutput)
}

// Usage of system tag keys. These predefined keys are scoped to namespaces. Example: `{"orcl-cloud.free-tier-retained": "true"}`
func (o LookupRemediationRunResultOutput) SystemTags() pulumi.StringMapOutput {
	return o.ApplyT(func(v LookupRemediationRunResult) map[string]string { return v.SystemTags }).(pulumi.StringMapOutput)
}

// The creation date and time of the remediation run (formatted according to [RFC3339](https://datatracker.ietf.org/doc/html/rfc3339)).
func (o LookupRemediationRunResultOutput) TimeCreated() pulumi.StringOutput {
	return o.ApplyT(func(v LookupRemediationRunResult) string { return v.TimeCreated }).(pulumi.StringOutput)
}

// The date and time of the finish of the remediation run (formatted according to [RFC3339](https://datatracker.ietf.org/doc/html/rfc3339)).
func (o LookupRemediationRunResultOutput) TimeFinished() pulumi.StringOutput {
	return o.ApplyT(func(v LookupRemediationRunResult) string { return v.TimeFinished }).(pulumi.StringOutput)
}

// The date and time of the start of the remediation run (formatted according to [RFC3339](https://datatracker.ietf.org/doc/html/rfc3339)).
func (o LookupRemediationRunResultOutput) TimeStarted() pulumi.StringOutput {
	return o.ApplyT(func(v LookupRemediationRunResult) string { return v.TimeStarted }).(pulumi.StringOutput)
}

// The date and time the remediation run was last updated (formatted according to [RFC3339](https://datatracker.ietf.org/doc/html/rfc3339)).
func (o LookupRemediationRunResultOutput) TimeUpdated() pulumi.StringOutput {
	return o.ApplyT(func(v LookupRemediationRunResult) string { return v.TimeUpdated }).(pulumi.StringOutput)
}

func init() {
	pulumi.RegisterOutputType(LookupRemediationRunResultOutput{})
}
