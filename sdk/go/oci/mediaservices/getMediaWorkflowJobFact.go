// Code generated by the Pulumi Terraform Bridge (tfgen) Tool DO NOT EDIT.
// *** WARNING: Do not edit by hand unless you're certain you know what you are doing! ***

package mediaservices

import (
	"context"
	"reflect"

	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This data source provides details about a specific Media Workflow Job Fact resource in Oracle Cloud Infrastructure Media Services service.
//
// Get the MediaWorkflowJobFact identified by the mediaWorkflowJobId and Fact ID.
//
// ## Example Usage
//
// ```go
// package main
//
// import (
//
//	"github.com/pulumi/pulumi-oci/sdk/go/oci/MediaServices"
//	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
//
// )
//
//	func main() {
//		pulumi.Run(func(ctx *pulumi.Context) error {
//			_, err := MediaServices.GetMediaWorkflowJobFact(ctx, &mediaservices.GetMediaWorkflowJobFactArgs{
//				Key:                _var.Media_workflow_job_fact_key,
//				MediaWorkflowJobId: oci_media_services_media_workflow_job.Test_media_workflow_job.Id,
//			}, nil)
//			if err != nil {
//				return err
//			}
//			return nil
//		})
//	}
//
// ```
func GetMediaWorkflowJobFact(ctx *pulumi.Context, args *GetMediaWorkflowJobFactArgs, opts ...pulumi.InvokeOption) (*GetMediaWorkflowJobFactResult, error) {
	var rv GetMediaWorkflowJobFactResult
	err := ctx.Invoke("oci:MediaServices/getMediaWorkflowJobFact:getMediaWorkflowJobFact", args, &rv, opts...)
	if err != nil {
		return nil, err
	}
	return &rv, nil
}

// A collection of arguments for invoking getMediaWorkflowJobFact.
type GetMediaWorkflowJobFactArgs struct {
	// Identifier of the MediaWorkflowJobFact within a MediaWorkflowJob.
	Key string `pulumi:"key"`
	// Unique MediaWorkflowJob identifier.
	MediaWorkflowJobId string `pulumi:"mediaWorkflowJobId"`
}

// A collection of values returned by getMediaWorkflowJobFact.
type GetMediaWorkflowJobFactResult struct {
	// The body of the detail captured as JSON.
	Detail string `pulumi:"detail"`
	// The provider-assigned unique ID for this managed resource.
	Id string `pulumi:"id"`
	// System generated serial number to uniquely identify a detail in order within a MediaWorkflowJob.
	Key string `pulumi:"key"`
	// Reference to the parent job.
	MediaWorkflowJobId string `pulumi:"mediaWorkflowJobId"`
	// Unique name. It is read-only and generated for the fact.
	Name string `pulumi:"name"`
	// The type of information contained in this detail.
	Type string `pulumi:"type"`
}

func GetMediaWorkflowJobFactOutput(ctx *pulumi.Context, args GetMediaWorkflowJobFactOutputArgs, opts ...pulumi.InvokeOption) GetMediaWorkflowJobFactResultOutput {
	return pulumi.ToOutputWithContext(context.Background(), args).
		ApplyT(func(v interface{}) (GetMediaWorkflowJobFactResult, error) {
			args := v.(GetMediaWorkflowJobFactArgs)
			r, err := GetMediaWorkflowJobFact(ctx, &args, opts...)
			var s GetMediaWorkflowJobFactResult
			if r != nil {
				s = *r
			}
			return s, err
		}).(GetMediaWorkflowJobFactResultOutput)
}

// A collection of arguments for invoking getMediaWorkflowJobFact.
type GetMediaWorkflowJobFactOutputArgs struct {
	// Identifier of the MediaWorkflowJobFact within a MediaWorkflowJob.
	Key pulumi.StringInput `pulumi:"key"`
	// Unique MediaWorkflowJob identifier.
	MediaWorkflowJobId pulumi.StringInput `pulumi:"mediaWorkflowJobId"`
}

func (GetMediaWorkflowJobFactOutputArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*GetMediaWorkflowJobFactArgs)(nil)).Elem()
}

// A collection of values returned by getMediaWorkflowJobFact.
type GetMediaWorkflowJobFactResultOutput struct{ *pulumi.OutputState }

func (GetMediaWorkflowJobFactResultOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*GetMediaWorkflowJobFactResult)(nil)).Elem()
}

func (o GetMediaWorkflowJobFactResultOutput) ToGetMediaWorkflowJobFactResultOutput() GetMediaWorkflowJobFactResultOutput {
	return o
}

func (o GetMediaWorkflowJobFactResultOutput) ToGetMediaWorkflowJobFactResultOutputWithContext(ctx context.Context) GetMediaWorkflowJobFactResultOutput {
	return o
}

// The body of the detail captured as JSON.
func (o GetMediaWorkflowJobFactResultOutput) Detail() pulumi.StringOutput {
	return o.ApplyT(func(v GetMediaWorkflowJobFactResult) string { return v.Detail }).(pulumi.StringOutput)
}

// The provider-assigned unique ID for this managed resource.
func (o GetMediaWorkflowJobFactResultOutput) Id() pulumi.StringOutput {
	return o.ApplyT(func(v GetMediaWorkflowJobFactResult) string { return v.Id }).(pulumi.StringOutput)
}

// System generated serial number to uniquely identify a detail in order within a MediaWorkflowJob.
func (o GetMediaWorkflowJobFactResultOutput) Key() pulumi.StringOutput {
	return o.ApplyT(func(v GetMediaWorkflowJobFactResult) string { return v.Key }).(pulumi.StringOutput)
}

// Reference to the parent job.
func (o GetMediaWorkflowJobFactResultOutput) MediaWorkflowJobId() pulumi.StringOutput {
	return o.ApplyT(func(v GetMediaWorkflowJobFactResult) string { return v.MediaWorkflowJobId }).(pulumi.StringOutput)
}

// Unique name. It is read-only and generated for the fact.
func (o GetMediaWorkflowJobFactResultOutput) Name() pulumi.StringOutput {
	return o.ApplyT(func(v GetMediaWorkflowJobFactResult) string { return v.Name }).(pulumi.StringOutput)
}

// The type of information contained in this detail.
func (o GetMediaWorkflowJobFactResultOutput) Type() pulumi.StringOutput {
	return o.ApplyT(func(v GetMediaWorkflowJobFactResult) string { return v.Type }).(pulumi.StringOutput)
}

func init() {
	pulumi.RegisterOutputType(GetMediaWorkflowJobFactResultOutput{})
}