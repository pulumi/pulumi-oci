// Code generated by pulumi-language-go DO NOT EDIT.
// *** WARNING: Do not edit by hand unless you're certain you know what you are doing! ***

package devops

import (
	"context"
	"reflect"

	"github.com/pulumi/pulumi-oci/sdk/v3/go/oci/internal"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This data source provides the list of Build Pipeline Stages in Oracle Cloud Infrastructure Devops service.
//
// Returns a list of all stages in a compartment or build pipeline.
//
// ## Example Usage
//
// ```go
// package main
//
// import (
//
//	"github.com/pulumi/pulumi-oci/sdk/v3/go/oci/devops"
//	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
//
// )
//
//	func main() {
//		pulumi.Run(func(ctx *pulumi.Context) error {
//			_, err := devops.GetBuildPipelineStages(ctx, &devops.GetBuildPipelineStagesArgs{
//				BuildPipelineId: pulumi.StringRef(testBuildPipeline.Id),
//				CompartmentId:   pulumi.StringRef(compartmentId),
//				DisplayName:     pulumi.StringRef(buildPipelineStageDisplayName),
//				Id:              pulumi.StringRef(buildPipelineStageId),
//				State:           pulumi.StringRef(buildPipelineStageState),
//			}, nil)
//			if err != nil {
//				return err
//			}
//			return nil
//		})
//	}
//
// ```
func GetBuildPipelineStages(ctx *pulumi.Context, args *GetBuildPipelineStagesArgs, opts ...pulumi.InvokeOption) (*GetBuildPipelineStagesResult, error) {
	opts = internal.PkgInvokeDefaultOpts(opts)
	var rv GetBuildPipelineStagesResult
	err := ctx.Invoke("oci:DevOps/getBuildPipelineStages:getBuildPipelineStages", args, &rv, opts...)
	if err != nil {
		return nil, err
	}
	return &rv, nil
}

// A collection of arguments for invoking getBuildPipelineStages.
type GetBuildPipelineStagesArgs struct {
	// The OCID of the parent build pipeline.
	BuildPipelineId *string `pulumi:"buildPipelineId"`
	// The OCID of the compartment in which to list resources.
	CompartmentId *string `pulumi:"compartmentId"`
	// A filter to return only resources that match the entire display name given.
	DisplayName *string                        `pulumi:"displayName"`
	Filters     []GetBuildPipelineStagesFilter `pulumi:"filters"`
	// Unique identifier or OCID for listing a single resource by ID.
	Id *string `pulumi:"id"`
	// A filter to return the stages that matches the given lifecycle state.
	State *string `pulumi:"state"`
}

// A collection of values returned by getBuildPipelineStages.
type GetBuildPipelineStagesResult struct {
	// The OCID of the build pipeline.
	BuildPipelineId *string `pulumi:"buildPipelineId"`
	// The list of build_pipeline_stage_collection.
	BuildPipelineStageCollections []GetBuildPipelineStagesBuildPipelineStageCollection `pulumi:"buildPipelineStageCollections"`
	// The OCID of the compartment where the pipeline is created.
	CompartmentId *string `pulumi:"compartmentId"`
	// Stage display name, which can be renamed and is not necessarily unique. Avoid entering confidential information.
	DisplayName *string                        `pulumi:"displayName"`
	Filters     []GetBuildPipelineStagesFilter `pulumi:"filters"`
	// Unique identifier that is immutable on creation.
	Id *string `pulumi:"id"`
	// The current state of the stage.
	State *string `pulumi:"state"`
}

func GetBuildPipelineStagesOutput(ctx *pulumi.Context, args GetBuildPipelineStagesOutputArgs, opts ...pulumi.InvokeOption) GetBuildPipelineStagesResultOutput {
	return pulumi.ToOutputWithContext(ctx.Context(), args).
		ApplyT(func(v interface{}) (GetBuildPipelineStagesResultOutput, error) {
			args := v.(GetBuildPipelineStagesArgs)
			options := pulumi.InvokeOutputOptions{InvokeOptions: internal.PkgInvokeDefaultOpts(opts)}
			return ctx.InvokeOutput("oci:DevOps/getBuildPipelineStages:getBuildPipelineStages", args, GetBuildPipelineStagesResultOutput{}, options).(GetBuildPipelineStagesResultOutput), nil
		}).(GetBuildPipelineStagesResultOutput)
}

// A collection of arguments for invoking getBuildPipelineStages.
type GetBuildPipelineStagesOutputArgs struct {
	// The OCID of the parent build pipeline.
	BuildPipelineId pulumi.StringPtrInput `pulumi:"buildPipelineId"`
	// The OCID of the compartment in which to list resources.
	CompartmentId pulumi.StringPtrInput `pulumi:"compartmentId"`
	// A filter to return only resources that match the entire display name given.
	DisplayName pulumi.StringPtrInput                  `pulumi:"displayName"`
	Filters     GetBuildPipelineStagesFilterArrayInput `pulumi:"filters"`
	// Unique identifier or OCID for listing a single resource by ID.
	Id pulumi.StringPtrInput `pulumi:"id"`
	// A filter to return the stages that matches the given lifecycle state.
	State pulumi.StringPtrInput `pulumi:"state"`
}

func (GetBuildPipelineStagesOutputArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*GetBuildPipelineStagesArgs)(nil)).Elem()
}

// A collection of values returned by getBuildPipelineStages.
type GetBuildPipelineStagesResultOutput struct{ *pulumi.OutputState }

func (GetBuildPipelineStagesResultOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*GetBuildPipelineStagesResult)(nil)).Elem()
}

func (o GetBuildPipelineStagesResultOutput) ToGetBuildPipelineStagesResultOutput() GetBuildPipelineStagesResultOutput {
	return o
}

func (o GetBuildPipelineStagesResultOutput) ToGetBuildPipelineStagesResultOutputWithContext(ctx context.Context) GetBuildPipelineStagesResultOutput {
	return o
}

// The OCID of the build pipeline.
func (o GetBuildPipelineStagesResultOutput) BuildPipelineId() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetBuildPipelineStagesResult) *string { return v.BuildPipelineId }).(pulumi.StringPtrOutput)
}

// The list of build_pipeline_stage_collection.
func (o GetBuildPipelineStagesResultOutput) BuildPipelineStageCollections() GetBuildPipelineStagesBuildPipelineStageCollectionArrayOutput {
	return o.ApplyT(func(v GetBuildPipelineStagesResult) []GetBuildPipelineStagesBuildPipelineStageCollection {
		return v.BuildPipelineStageCollections
	}).(GetBuildPipelineStagesBuildPipelineStageCollectionArrayOutput)
}

// The OCID of the compartment where the pipeline is created.
func (o GetBuildPipelineStagesResultOutput) CompartmentId() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetBuildPipelineStagesResult) *string { return v.CompartmentId }).(pulumi.StringPtrOutput)
}

// Stage display name, which can be renamed and is not necessarily unique. Avoid entering confidential information.
func (o GetBuildPipelineStagesResultOutput) DisplayName() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetBuildPipelineStagesResult) *string { return v.DisplayName }).(pulumi.StringPtrOutput)
}

func (o GetBuildPipelineStagesResultOutput) Filters() GetBuildPipelineStagesFilterArrayOutput {
	return o.ApplyT(func(v GetBuildPipelineStagesResult) []GetBuildPipelineStagesFilter { return v.Filters }).(GetBuildPipelineStagesFilterArrayOutput)
}

// Unique identifier that is immutable on creation.
func (o GetBuildPipelineStagesResultOutput) Id() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetBuildPipelineStagesResult) *string { return v.Id }).(pulumi.StringPtrOutput)
}

// The current state of the stage.
func (o GetBuildPipelineStagesResultOutput) State() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetBuildPipelineStagesResult) *string { return v.State }).(pulumi.StringPtrOutput)
}

func init() {
	pulumi.RegisterOutputType(GetBuildPipelineStagesResultOutput{})
}
