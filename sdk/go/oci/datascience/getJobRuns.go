// Code generated by the Pulumi Terraform Bridge (tfgen) Tool DO NOT EDIT.
// *** WARNING: Do not edit by hand unless you're certain you know what you are doing! ***

package datascience

import (
	"context"
	"reflect"

	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This data source provides the list of Job Runs in Oracle Cloud Infrastructure Data Science service.
//
// List out job runs.
//
// ## Example Usage
//
// ```go
// package main
//
// import (
//
//	"github.com/pulumi/pulumi-oci/sdk/go/oci/DataScience"
//	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
//
// )
//
//	func main() {
//		pulumi.Run(func(ctx *pulumi.Context) error {
//			_, err := DataScience.GetJobRuns(ctx, &datascience.GetJobRunsArgs{
//				CompartmentId: _var.Compartment_id,
//				CreatedBy:     pulumi.StringRef(_var.Job_run_created_by),
//				DisplayName:   pulumi.StringRef(_var.Job_run_display_name),
//				Id:            pulumi.StringRef(_var.Job_run_id),
//				JobId:         pulumi.StringRef(oci_datascience_job.Test_job.Id),
//				State:         pulumi.StringRef(_var.Job_run_state),
//			}, nil)
//			if err != nil {
//				return err
//			}
//			return nil
//		})
//	}
//
// ```
func GetJobRuns(ctx *pulumi.Context, args *GetJobRunsArgs, opts ...pulumi.InvokeOption) (*GetJobRunsResult, error) {
	var rv GetJobRunsResult
	err := ctx.Invoke("oci:DataScience/getJobRuns:getJobRuns", args, &rv, opts...)
	if err != nil {
		return nil, err
	}
	return &rv, nil
}

// A collection of arguments for invoking getJobRuns.
type GetJobRunsArgs struct {
	// <b>Filter</b> results by the [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
	CompartmentId string `pulumi:"compartmentId"`
	// <b>Filter</b> results by the [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the user who created the resource.
	CreatedBy *string `pulumi:"createdBy"`
	// <b>Filter</b> results by its user-friendly name.
	DisplayName *string            `pulumi:"displayName"`
	Filters     []GetJobRunsFilter `pulumi:"filters"`
	// <b>Filter</b> results by [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm). Must be an OCID of the correct type for the resource type.
	Id *string `pulumi:"id"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the job.
	JobId *string `pulumi:"jobId"`
	// <b>Filter</b> results by the specified lifecycle state. Must be a valid state for the resource type.
	State *string `pulumi:"state"`
}

// A collection of values returned by getJobRuns.
type GetJobRunsResult struct {
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment where you want to create the job.
	CompartmentId string `pulumi:"compartmentId"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the user who created the job run.
	CreatedBy *string `pulumi:"createdBy"`
	// A user-friendly display name for the resource.
	DisplayName *string            `pulumi:"displayName"`
	Filters     []GetJobRunsFilter `pulumi:"filters"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the job run.
	Id *string `pulumi:"id"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the job run.
	JobId *string `pulumi:"jobId"`
	// The list of job_runs.
	JobRuns []GetJobRunsJobRun `pulumi:"jobRuns"`
	// The state of the job run.
	State *string `pulumi:"state"`
}

func GetJobRunsOutput(ctx *pulumi.Context, args GetJobRunsOutputArgs, opts ...pulumi.InvokeOption) GetJobRunsResultOutput {
	return pulumi.ToOutputWithContext(context.Background(), args).
		ApplyT(func(v interface{}) (GetJobRunsResult, error) {
			args := v.(GetJobRunsArgs)
			r, err := GetJobRuns(ctx, &args, opts...)
			var s GetJobRunsResult
			if r != nil {
				s = *r
			}
			return s, err
		}).(GetJobRunsResultOutput)
}

// A collection of arguments for invoking getJobRuns.
type GetJobRunsOutputArgs struct {
	// <b>Filter</b> results by the [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
	CompartmentId pulumi.StringInput `pulumi:"compartmentId"`
	// <b>Filter</b> results by the [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the user who created the resource.
	CreatedBy pulumi.StringPtrInput `pulumi:"createdBy"`
	// <b>Filter</b> results by its user-friendly name.
	DisplayName pulumi.StringPtrInput      `pulumi:"displayName"`
	Filters     GetJobRunsFilterArrayInput `pulumi:"filters"`
	// <b>Filter</b> results by [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm). Must be an OCID of the correct type for the resource type.
	Id pulumi.StringPtrInput `pulumi:"id"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the job.
	JobId pulumi.StringPtrInput `pulumi:"jobId"`
	// <b>Filter</b> results by the specified lifecycle state. Must be a valid state for the resource type.
	State pulumi.StringPtrInput `pulumi:"state"`
}

func (GetJobRunsOutputArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*GetJobRunsArgs)(nil)).Elem()
}

// A collection of values returned by getJobRuns.
type GetJobRunsResultOutput struct{ *pulumi.OutputState }

func (GetJobRunsResultOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*GetJobRunsResult)(nil)).Elem()
}

func (o GetJobRunsResultOutput) ToGetJobRunsResultOutput() GetJobRunsResultOutput {
	return o
}

func (o GetJobRunsResultOutput) ToGetJobRunsResultOutputWithContext(ctx context.Context) GetJobRunsResultOutput {
	return o
}

// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment where you want to create the job.
func (o GetJobRunsResultOutput) CompartmentId() pulumi.StringOutput {
	return o.ApplyT(func(v GetJobRunsResult) string { return v.CompartmentId }).(pulumi.StringOutput)
}

// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the user who created the job run.
func (o GetJobRunsResultOutput) CreatedBy() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetJobRunsResult) *string { return v.CreatedBy }).(pulumi.StringPtrOutput)
}

// A user-friendly display name for the resource.
func (o GetJobRunsResultOutput) DisplayName() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetJobRunsResult) *string { return v.DisplayName }).(pulumi.StringPtrOutput)
}

func (o GetJobRunsResultOutput) Filters() GetJobRunsFilterArrayOutput {
	return o.ApplyT(func(v GetJobRunsResult) []GetJobRunsFilter { return v.Filters }).(GetJobRunsFilterArrayOutput)
}

// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the job run.
func (o GetJobRunsResultOutput) Id() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetJobRunsResult) *string { return v.Id }).(pulumi.StringPtrOutput)
}

// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the job run.
func (o GetJobRunsResultOutput) JobId() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetJobRunsResult) *string { return v.JobId }).(pulumi.StringPtrOutput)
}

// The list of job_runs.
func (o GetJobRunsResultOutput) JobRuns() GetJobRunsJobRunArrayOutput {
	return o.ApplyT(func(v GetJobRunsResult) []GetJobRunsJobRun { return v.JobRuns }).(GetJobRunsJobRunArrayOutput)
}

// The state of the job run.
func (o GetJobRunsResultOutput) State() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetJobRunsResult) *string { return v.State }).(pulumi.StringPtrOutput)
}

func init() {
	pulumi.RegisterOutputType(GetJobRunsResultOutput{})
}