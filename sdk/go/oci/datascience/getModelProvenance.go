// Code generated by the Pulumi Terraform Bridge (tfgen) Tool DO NOT EDIT.
// *** WARNING: Do not edit by hand unless you're certain you know what you are doing! ***

package datascience

import (
	"context"
	"reflect"

	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This data source provides details about a specific Model Provenance resource in Oracle Cloud Infrastructure Data Science service.
//
// Gets provenance information for specified model.
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
//			_, err := DataScience.GetModelProvenance(ctx, &datascience.GetModelProvenanceArgs{
//				ModelId: oci_datascience_model.Test_model.Id,
//			}, nil)
//			if err != nil {
//				return err
//			}
//			return nil
//		})
//	}
//
// ```
func LookupModelProvenance(ctx *pulumi.Context, args *LookupModelProvenanceArgs, opts ...pulumi.InvokeOption) (*LookupModelProvenanceResult, error) {
	var rv LookupModelProvenanceResult
	err := ctx.Invoke("oci:DataScience/getModelProvenance:getModelProvenance", args, &rv, opts...)
	if err != nil {
		return nil, err
	}
	return &rv, nil
}

// A collection of arguments for invoking getModelProvenance.
type LookupModelProvenanceArgs struct {
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the model.
	ModelId string `pulumi:"modelId"`
}

// A collection of values returned by getModelProvenance.
type LookupModelProvenanceResult struct {
	// For model reproducibility purposes. Branch of the git repository associated with model training.
	GitBranch string `pulumi:"gitBranch"`
	// For model reproducibility purposes. Commit ID of the git repository associated with model training.
	GitCommit string `pulumi:"gitCommit"`
	Id        string `pulumi:"id"`
	ModelId   string `pulumi:"modelId"`
	// For model reproducibility purposes. URL of the git repository associated with model training.
	RepositoryUrl string `pulumi:"repositoryUrl"`
	// For model reproducibility purposes. Path to model artifacts.
	ScriptDir string `pulumi:"scriptDir"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of a training session(Job or NotebookSession) in which the model was trained. It is used for model reproducibility purposes.
	TrainingId string `pulumi:"trainingId"`
	// For model reproducibility purposes. Path to the python script or notebook in which the model was trained."
	TrainingScript string `pulumi:"trainingScript"`
}

func LookupModelProvenanceOutput(ctx *pulumi.Context, args LookupModelProvenanceOutputArgs, opts ...pulumi.InvokeOption) LookupModelProvenanceResultOutput {
	return pulumi.ToOutputWithContext(context.Background(), args).
		ApplyT(func(v interface{}) (LookupModelProvenanceResult, error) {
			args := v.(LookupModelProvenanceArgs)
			r, err := LookupModelProvenance(ctx, &args, opts...)
			var s LookupModelProvenanceResult
			if r != nil {
				s = *r
			}
			return s, err
		}).(LookupModelProvenanceResultOutput)
}

// A collection of arguments for invoking getModelProvenance.
type LookupModelProvenanceOutputArgs struct {
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the model.
	ModelId pulumi.StringInput `pulumi:"modelId"`
}

func (LookupModelProvenanceOutputArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*LookupModelProvenanceArgs)(nil)).Elem()
}

// A collection of values returned by getModelProvenance.
type LookupModelProvenanceResultOutput struct{ *pulumi.OutputState }

func (LookupModelProvenanceResultOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*LookupModelProvenanceResult)(nil)).Elem()
}

func (o LookupModelProvenanceResultOutput) ToLookupModelProvenanceResultOutput() LookupModelProvenanceResultOutput {
	return o
}

func (o LookupModelProvenanceResultOutput) ToLookupModelProvenanceResultOutputWithContext(ctx context.Context) LookupModelProvenanceResultOutput {
	return o
}

// For model reproducibility purposes. Branch of the git repository associated with model training.
func (o LookupModelProvenanceResultOutput) GitBranch() pulumi.StringOutput {
	return o.ApplyT(func(v LookupModelProvenanceResult) string { return v.GitBranch }).(pulumi.StringOutput)
}

// For model reproducibility purposes. Commit ID of the git repository associated with model training.
func (o LookupModelProvenanceResultOutput) GitCommit() pulumi.StringOutput {
	return o.ApplyT(func(v LookupModelProvenanceResult) string { return v.GitCommit }).(pulumi.StringOutput)
}

func (o LookupModelProvenanceResultOutput) Id() pulumi.StringOutput {
	return o.ApplyT(func(v LookupModelProvenanceResult) string { return v.Id }).(pulumi.StringOutput)
}

func (o LookupModelProvenanceResultOutput) ModelId() pulumi.StringOutput {
	return o.ApplyT(func(v LookupModelProvenanceResult) string { return v.ModelId }).(pulumi.StringOutput)
}

// For model reproducibility purposes. URL of the git repository associated with model training.
func (o LookupModelProvenanceResultOutput) RepositoryUrl() pulumi.StringOutput {
	return o.ApplyT(func(v LookupModelProvenanceResult) string { return v.RepositoryUrl }).(pulumi.StringOutput)
}

// For model reproducibility purposes. Path to model artifacts.
func (o LookupModelProvenanceResultOutput) ScriptDir() pulumi.StringOutput {
	return o.ApplyT(func(v LookupModelProvenanceResult) string { return v.ScriptDir }).(pulumi.StringOutput)
}

// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of a training session(Job or NotebookSession) in which the model was trained. It is used for model reproducibility purposes.
func (o LookupModelProvenanceResultOutput) TrainingId() pulumi.StringOutput {
	return o.ApplyT(func(v LookupModelProvenanceResult) string { return v.TrainingId }).(pulumi.StringOutput)
}

// For model reproducibility purposes. Path to the python script or notebook in which the model was trained."
func (o LookupModelProvenanceResultOutput) TrainingScript() pulumi.StringOutput {
	return o.ApplyT(func(v LookupModelProvenanceResult) string { return v.TrainingScript }).(pulumi.StringOutput)
}

func init() {
	pulumi.RegisterOutputType(LookupModelProvenanceResultOutput{})
}