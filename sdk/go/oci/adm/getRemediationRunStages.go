// Code generated by the Pulumi Terraform Bridge (tfgen) Tool DO NOT EDIT.
// *** WARNING: Do not edit by hand unless you're certain you know what you are doing! ***

package adm

import (
	"context"
	"reflect"

	"github.com/pulumi/pulumi-oci/sdk/go/oci/internal"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumix"
)

// This data source provides the list of Remediation Run Stages in Oracle Cloud Infrastructure Adm service.
//
// Returns a list of Remediation Run Stages based on the specified query parameters and Remediation Run identifier.
//
// ## Example Usage
//
// ```go
// package main
//
// import (
//
//	"github.com/pulumi/pulumi-oci/sdk/go/oci/Adm"
//	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
//
// )
//
//	func main() {
//		pulumi.Run(func(ctx *pulumi.Context) error {
//			_, err := Adm.GetRemediationRunStages(ctx, &adm.GetRemediationRunStagesArgs{
//				RemediationRunId: oci_adm_remediation_run.Test_remediation_run.Id,
//				Status:           pulumi.StringRef(_var.Remediation_run_stage_status),
//				Type:             pulumi.StringRef(_var.Remediation_run_stage_type),
//			}, nil)
//			if err != nil {
//				return err
//			}
//			return nil
//		})
//	}
//
// ```
func GetRemediationRunStages(ctx *pulumi.Context, args *GetRemediationRunStagesArgs, opts ...pulumi.InvokeOption) (*GetRemediationRunStagesResult, error) {
	opts = internal.PkgInvokeDefaultOpts(opts)
	var rv GetRemediationRunStagesResult
	err := ctx.Invoke("oci:Adm/getRemediationRunStages:getRemediationRunStages", args, &rv, opts...)
	if err != nil {
		return nil, err
	}
	return &rv, nil
}

// A collection of arguments for invoking getRemediationRunStages.
type GetRemediationRunStagesArgs struct {
	Filters []GetRemediationRunStagesFilter `pulumi:"filters"`
	// Unique Remediation Run identifier path parameter.
	RemediationRunId string `pulumi:"remediationRunId"`
	// A filter to return only Stages that match the specified status.
	Status *string `pulumi:"status"`
	// A filter to return only Stages that match the specified type.
	Type *string `pulumi:"type"`
}

// A collection of values returned by getRemediationRunStages.
type GetRemediationRunStagesResult struct {
	Filters []GetRemediationRunStagesFilter `pulumi:"filters"`
	// The provider-assigned unique ID for this managed resource.
	Id string `pulumi:"id"`
	// The Oracle Cloud identifier ([OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm)) of the remediation run.
	RemediationRunId string `pulumi:"remediationRunId"`
	// The list of remediation_run_stage_collection.
	RemediationRunStageCollections []GetRemediationRunStagesRemediationRunStageCollection `pulumi:"remediationRunStageCollections"`
	// The current status of a remediation run stage.
	Status *string `pulumi:"status"`
	// The type of the remediation run stage.
	Type *string `pulumi:"type"`
}

func GetRemediationRunStagesOutput(ctx *pulumi.Context, args GetRemediationRunStagesOutputArgs, opts ...pulumi.InvokeOption) GetRemediationRunStagesResultOutput {
	return pulumi.ToOutputWithContext(context.Background(), args).
		ApplyT(func(v interface{}) (GetRemediationRunStagesResult, error) {
			args := v.(GetRemediationRunStagesArgs)
			r, err := GetRemediationRunStages(ctx, &args, opts...)
			var s GetRemediationRunStagesResult
			if r != nil {
				s = *r
			}
			return s, err
		}).(GetRemediationRunStagesResultOutput)
}

// A collection of arguments for invoking getRemediationRunStages.
type GetRemediationRunStagesOutputArgs struct {
	Filters GetRemediationRunStagesFilterArrayInput `pulumi:"filters"`
	// Unique Remediation Run identifier path parameter.
	RemediationRunId pulumi.StringInput `pulumi:"remediationRunId"`
	// A filter to return only Stages that match the specified status.
	Status pulumi.StringPtrInput `pulumi:"status"`
	// A filter to return only Stages that match the specified type.
	Type pulumi.StringPtrInput `pulumi:"type"`
}

func (GetRemediationRunStagesOutputArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*GetRemediationRunStagesArgs)(nil)).Elem()
}

// A collection of values returned by getRemediationRunStages.
type GetRemediationRunStagesResultOutput struct{ *pulumi.OutputState }

func (GetRemediationRunStagesResultOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*GetRemediationRunStagesResult)(nil)).Elem()
}

func (o GetRemediationRunStagesResultOutput) ToGetRemediationRunStagesResultOutput() GetRemediationRunStagesResultOutput {
	return o
}

func (o GetRemediationRunStagesResultOutput) ToGetRemediationRunStagesResultOutputWithContext(ctx context.Context) GetRemediationRunStagesResultOutput {
	return o
}

func (o GetRemediationRunStagesResultOutput) ToOutput(ctx context.Context) pulumix.Output[GetRemediationRunStagesResult] {
	return pulumix.Output[GetRemediationRunStagesResult]{
		OutputState: o.OutputState,
	}
}

func (o GetRemediationRunStagesResultOutput) Filters() GetRemediationRunStagesFilterArrayOutput {
	return o.ApplyT(func(v GetRemediationRunStagesResult) []GetRemediationRunStagesFilter { return v.Filters }).(GetRemediationRunStagesFilterArrayOutput)
}

// The provider-assigned unique ID for this managed resource.
func (o GetRemediationRunStagesResultOutput) Id() pulumi.StringOutput {
	return o.ApplyT(func(v GetRemediationRunStagesResult) string { return v.Id }).(pulumi.StringOutput)
}

// The Oracle Cloud identifier ([OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm)) of the remediation run.
func (o GetRemediationRunStagesResultOutput) RemediationRunId() pulumi.StringOutput {
	return o.ApplyT(func(v GetRemediationRunStagesResult) string { return v.RemediationRunId }).(pulumi.StringOutput)
}

// The list of remediation_run_stage_collection.
func (o GetRemediationRunStagesResultOutput) RemediationRunStageCollections() GetRemediationRunStagesRemediationRunStageCollectionArrayOutput {
	return o.ApplyT(func(v GetRemediationRunStagesResult) []GetRemediationRunStagesRemediationRunStageCollection {
		return v.RemediationRunStageCollections
	}).(GetRemediationRunStagesRemediationRunStageCollectionArrayOutput)
}

// The current status of a remediation run stage.
func (o GetRemediationRunStagesResultOutput) Status() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetRemediationRunStagesResult) *string { return v.Status }).(pulumi.StringPtrOutput)
}

// The type of the remediation run stage.
func (o GetRemediationRunStagesResultOutput) Type() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetRemediationRunStagesResult) *string { return v.Type }).(pulumi.StringPtrOutput)
}

func init() {
	pulumi.RegisterOutputType(GetRemediationRunStagesResultOutput{})
}