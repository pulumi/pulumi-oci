// Code generated by pulumi-language-go DO NOT EDIT.
// *** WARNING: Do not edit by hand unless you're certain you know what you are doing! ***

package datascience

import (
	"context"
	"reflect"

	"errors"
	"github.com/pulumi/pulumi-oci/sdk/v3/go/oci/internal"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This resource provides the Model Provenance resource in Oracle Cloud Infrastructure Data Science service.
//
// Creates provenance information for the specified model.
//
// ## Example Usage
//
// ```go
// package main
//
// import (
//
//	"github.com/pulumi/pulumi-oci/sdk/v3/go/oci/datascience"
//	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
//
// )
//
//	func main() {
//		pulumi.Run(func(ctx *pulumi.Context) error {
//			_, err := datascience.NewModelProvenance(ctx, "test_model_provenance", &datascience.ModelProvenanceArgs{
//				ModelId:        pulumi.Any(testModel.Id),
//				GitBranch:      pulumi.Any(modelProvenanceGitBranch),
//				GitCommit:      pulumi.Any(modelProvenanceGitCommit),
//				RepositoryUrl:  pulumi.Any(modelProvenanceRepositoryUrl),
//				ScriptDir:      pulumi.Any(modelProvenanceScriptDir),
//				TrainingId:     pulumi.Any(testTraining.Id),
//				TrainingScript: pulumi.Any(modelProvenanceTrainingScript),
//			})
//			if err != nil {
//				return err
//			}
//			return nil
//		})
//	}
//
// ```
//
// ## Import
//
// ModelProvenances can be imported using the `id`, e.g.
//
// ```sh
// $ pulumi import oci:DataScience/modelProvenance:ModelProvenance test_model_provenance "models/{modelId}/provenance"
// ```
type ModelProvenance struct {
	pulumi.CustomResourceState

	// (Updatable) For model reproducibility purposes. Branch of the git repository associated with model training.
	GitBranch pulumi.StringOutput `pulumi:"gitBranch"`
	// (Updatable) For model reproducibility purposes. Commit ID of the git repository associated with model training.
	GitCommit pulumi.StringOutput `pulumi:"gitCommit"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the model.
	ModelId pulumi.StringOutput `pulumi:"modelId"`
	// (Updatable) For model reproducibility purposes. URL of the git repository associated with model training.
	RepositoryUrl pulumi.StringOutput `pulumi:"repositoryUrl"`
	// (Updatable) For model reproducibility purposes. Path to model artifacts.
	ScriptDir pulumi.StringOutput `pulumi:"scriptDir"`
	// (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of a training session(Job or NotebookSession) in which the model was trained. It is used for model reproducibility purposes.
	TrainingId pulumi.StringOutput `pulumi:"trainingId"`
	// (Updatable) For model reproducibility purposes. Path to the python script or notebook in which the model was trained."
	//
	// ** IMPORTANT **
	// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
	TrainingScript pulumi.StringOutput `pulumi:"trainingScript"`
}

// NewModelProvenance registers a new resource with the given unique name, arguments, and options.
func NewModelProvenance(ctx *pulumi.Context,
	name string, args *ModelProvenanceArgs, opts ...pulumi.ResourceOption) (*ModelProvenance, error) {
	if args == nil {
		return nil, errors.New("missing one or more required arguments")
	}

	if args.ModelId == nil {
		return nil, errors.New("invalid value for required argument 'ModelId'")
	}
	opts = internal.PkgResourceDefaultOpts(opts)
	var resource ModelProvenance
	err := ctx.RegisterResource("oci:DataScience/modelProvenance:ModelProvenance", name, args, &resource, opts...)
	if err != nil {
		return nil, err
	}
	return &resource, nil
}

// GetModelProvenance gets an existing ModelProvenance resource's state with the given name, ID, and optional
// state properties that are used to uniquely qualify the lookup (nil if not required).
func GetModelProvenance(ctx *pulumi.Context,
	name string, id pulumi.IDInput, state *ModelProvenanceState, opts ...pulumi.ResourceOption) (*ModelProvenance, error) {
	var resource ModelProvenance
	err := ctx.ReadResource("oci:DataScience/modelProvenance:ModelProvenance", name, id, state, &resource, opts...)
	if err != nil {
		return nil, err
	}
	return &resource, nil
}

// Input properties used for looking up and filtering ModelProvenance resources.
type modelProvenanceState struct {
	// (Updatable) For model reproducibility purposes. Branch of the git repository associated with model training.
	GitBranch *string `pulumi:"gitBranch"`
	// (Updatable) For model reproducibility purposes. Commit ID of the git repository associated with model training.
	GitCommit *string `pulumi:"gitCommit"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the model.
	ModelId *string `pulumi:"modelId"`
	// (Updatable) For model reproducibility purposes. URL of the git repository associated with model training.
	RepositoryUrl *string `pulumi:"repositoryUrl"`
	// (Updatable) For model reproducibility purposes. Path to model artifacts.
	ScriptDir *string `pulumi:"scriptDir"`
	// (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of a training session(Job or NotebookSession) in which the model was trained. It is used for model reproducibility purposes.
	TrainingId *string `pulumi:"trainingId"`
	// (Updatable) For model reproducibility purposes. Path to the python script or notebook in which the model was trained."
	//
	// ** IMPORTANT **
	// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
	TrainingScript *string `pulumi:"trainingScript"`
}

type ModelProvenanceState struct {
	// (Updatable) For model reproducibility purposes. Branch of the git repository associated with model training.
	GitBranch pulumi.StringPtrInput
	// (Updatable) For model reproducibility purposes. Commit ID of the git repository associated with model training.
	GitCommit pulumi.StringPtrInput
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the model.
	ModelId pulumi.StringPtrInput
	// (Updatable) For model reproducibility purposes. URL of the git repository associated with model training.
	RepositoryUrl pulumi.StringPtrInput
	// (Updatable) For model reproducibility purposes. Path to model artifacts.
	ScriptDir pulumi.StringPtrInput
	// (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of a training session(Job or NotebookSession) in which the model was trained. It is used for model reproducibility purposes.
	TrainingId pulumi.StringPtrInput
	// (Updatable) For model reproducibility purposes. Path to the python script or notebook in which the model was trained."
	//
	// ** IMPORTANT **
	// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
	TrainingScript pulumi.StringPtrInput
}

func (ModelProvenanceState) ElementType() reflect.Type {
	return reflect.TypeOf((*modelProvenanceState)(nil)).Elem()
}

type modelProvenanceArgs struct {
	// (Updatable) For model reproducibility purposes. Branch of the git repository associated with model training.
	GitBranch *string `pulumi:"gitBranch"`
	// (Updatable) For model reproducibility purposes. Commit ID of the git repository associated with model training.
	GitCommit *string `pulumi:"gitCommit"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the model.
	ModelId string `pulumi:"modelId"`
	// (Updatable) For model reproducibility purposes. URL of the git repository associated with model training.
	RepositoryUrl *string `pulumi:"repositoryUrl"`
	// (Updatable) For model reproducibility purposes. Path to model artifacts.
	ScriptDir *string `pulumi:"scriptDir"`
	// (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of a training session(Job or NotebookSession) in which the model was trained. It is used for model reproducibility purposes.
	TrainingId *string `pulumi:"trainingId"`
	// (Updatable) For model reproducibility purposes. Path to the python script or notebook in which the model was trained."
	//
	// ** IMPORTANT **
	// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
	TrainingScript *string `pulumi:"trainingScript"`
}

// The set of arguments for constructing a ModelProvenance resource.
type ModelProvenanceArgs struct {
	// (Updatable) For model reproducibility purposes. Branch of the git repository associated with model training.
	GitBranch pulumi.StringPtrInput
	// (Updatable) For model reproducibility purposes. Commit ID of the git repository associated with model training.
	GitCommit pulumi.StringPtrInput
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the model.
	ModelId pulumi.StringInput
	// (Updatable) For model reproducibility purposes. URL of the git repository associated with model training.
	RepositoryUrl pulumi.StringPtrInput
	// (Updatable) For model reproducibility purposes. Path to model artifacts.
	ScriptDir pulumi.StringPtrInput
	// (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of a training session(Job or NotebookSession) in which the model was trained. It is used for model reproducibility purposes.
	TrainingId pulumi.StringPtrInput
	// (Updatable) For model reproducibility purposes. Path to the python script or notebook in which the model was trained."
	//
	// ** IMPORTANT **
	// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
	TrainingScript pulumi.StringPtrInput
}

func (ModelProvenanceArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*modelProvenanceArgs)(nil)).Elem()
}

type ModelProvenanceInput interface {
	pulumi.Input

	ToModelProvenanceOutput() ModelProvenanceOutput
	ToModelProvenanceOutputWithContext(ctx context.Context) ModelProvenanceOutput
}

func (*ModelProvenance) ElementType() reflect.Type {
	return reflect.TypeOf((**ModelProvenance)(nil)).Elem()
}

func (i *ModelProvenance) ToModelProvenanceOutput() ModelProvenanceOutput {
	return i.ToModelProvenanceOutputWithContext(context.Background())
}

func (i *ModelProvenance) ToModelProvenanceOutputWithContext(ctx context.Context) ModelProvenanceOutput {
	return pulumi.ToOutputWithContext(ctx, i).(ModelProvenanceOutput)
}

// ModelProvenanceArrayInput is an input type that accepts ModelProvenanceArray and ModelProvenanceArrayOutput values.
// You can construct a concrete instance of `ModelProvenanceArrayInput` via:
//
//	ModelProvenanceArray{ ModelProvenanceArgs{...} }
type ModelProvenanceArrayInput interface {
	pulumi.Input

	ToModelProvenanceArrayOutput() ModelProvenanceArrayOutput
	ToModelProvenanceArrayOutputWithContext(context.Context) ModelProvenanceArrayOutput
}

type ModelProvenanceArray []ModelProvenanceInput

func (ModelProvenanceArray) ElementType() reflect.Type {
	return reflect.TypeOf((*[]*ModelProvenance)(nil)).Elem()
}

func (i ModelProvenanceArray) ToModelProvenanceArrayOutput() ModelProvenanceArrayOutput {
	return i.ToModelProvenanceArrayOutputWithContext(context.Background())
}

func (i ModelProvenanceArray) ToModelProvenanceArrayOutputWithContext(ctx context.Context) ModelProvenanceArrayOutput {
	return pulumi.ToOutputWithContext(ctx, i).(ModelProvenanceArrayOutput)
}

// ModelProvenanceMapInput is an input type that accepts ModelProvenanceMap and ModelProvenanceMapOutput values.
// You can construct a concrete instance of `ModelProvenanceMapInput` via:
//
//	ModelProvenanceMap{ "key": ModelProvenanceArgs{...} }
type ModelProvenanceMapInput interface {
	pulumi.Input

	ToModelProvenanceMapOutput() ModelProvenanceMapOutput
	ToModelProvenanceMapOutputWithContext(context.Context) ModelProvenanceMapOutput
}

type ModelProvenanceMap map[string]ModelProvenanceInput

func (ModelProvenanceMap) ElementType() reflect.Type {
	return reflect.TypeOf((*map[string]*ModelProvenance)(nil)).Elem()
}

func (i ModelProvenanceMap) ToModelProvenanceMapOutput() ModelProvenanceMapOutput {
	return i.ToModelProvenanceMapOutputWithContext(context.Background())
}

func (i ModelProvenanceMap) ToModelProvenanceMapOutputWithContext(ctx context.Context) ModelProvenanceMapOutput {
	return pulumi.ToOutputWithContext(ctx, i).(ModelProvenanceMapOutput)
}

type ModelProvenanceOutput struct{ *pulumi.OutputState }

func (ModelProvenanceOutput) ElementType() reflect.Type {
	return reflect.TypeOf((**ModelProvenance)(nil)).Elem()
}

func (o ModelProvenanceOutput) ToModelProvenanceOutput() ModelProvenanceOutput {
	return o
}

func (o ModelProvenanceOutput) ToModelProvenanceOutputWithContext(ctx context.Context) ModelProvenanceOutput {
	return o
}

// (Updatable) For model reproducibility purposes. Branch of the git repository associated with model training.
func (o ModelProvenanceOutput) GitBranch() pulumi.StringOutput {
	return o.ApplyT(func(v *ModelProvenance) pulumi.StringOutput { return v.GitBranch }).(pulumi.StringOutput)
}

// (Updatable) For model reproducibility purposes. Commit ID of the git repository associated with model training.
func (o ModelProvenanceOutput) GitCommit() pulumi.StringOutput {
	return o.ApplyT(func(v *ModelProvenance) pulumi.StringOutput { return v.GitCommit }).(pulumi.StringOutput)
}

// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the model.
func (o ModelProvenanceOutput) ModelId() pulumi.StringOutput {
	return o.ApplyT(func(v *ModelProvenance) pulumi.StringOutput { return v.ModelId }).(pulumi.StringOutput)
}

// (Updatable) For model reproducibility purposes. URL of the git repository associated with model training.
func (o ModelProvenanceOutput) RepositoryUrl() pulumi.StringOutput {
	return o.ApplyT(func(v *ModelProvenance) pulumi.StringOutput { return v.RepositoryUrl }).(pulumi.StringOutput)
}

// (Updatable) For model reproducibility purposes. Path to model artifacts.
func (o ModelProvenanceOutput) ScriptDir() pulumi.StringOutput {
	return o.ApplyT(func(v *ModelProvenance) pulumi.StringOutput { return v.ScriptDir }).(pulumi.StringOutput)
}

// (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of a training session(Job or NotebookSession) in which the model was trained. It is used for model reproducibility purposes.
func (o ModelProvenanceOutput) TrainingId() pulumi.StringOutput {
	return o.ApplyT(func(v *ModelProvenance) pulumi.StringOutput { return v.TrainingId }).(pulumi.StringOutput)
}

// (Updatable) For model reproducibility purposes. Path to the python script or notebook in which the model was trained."
//
// ** IMPORTANT **
// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
func (o ModelProvenanceOutput) TrainingScript() pulumi.StringOutput {
	return o.ApplyT(func(v *ModelProvenance) pulumi.StringOutput { return v.TrainingScript }).(pulumi.StringOutput)
}

type ModelProvenanceArrayOutput struct{ *pulumi.OutputState }

func (ModelProvenanceArrayOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*[]*ModelProvenance)(nil)).Elem()
}

func (o ModelProvenanceArrayOutput) ToModelProvenanceArrayOutput() ModelProvenanceArrayOutput {
	return o
}

func (o ModelProvenanceArrayOutput) ToModelProvenanceArrayOutputWithContext(ctx context.Context) ModelProvenanceArrayOutput {
	return o
}

func (o ModelProvenanceArrayOutput) Index(i pulumi.IntInput) ModelProvenanceOutput {
	return pulumi.All(o, i).ApplyT(func(vs []interface{}) *ModelProvenance {
		return vs[0].([]*ModelProvenance)[vs[1].(int)]
	}).(ModelProvenanceOutput)
}

type ModelProvenanceMapOutput struct{ *pulumi.OutputState }

func (ModelProvenanceMapOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*map[string]*ModelProvenance)(nil)).Elem()
}

func (o ModelProvenanceMapOutput) ToModelProvenanceMapOutput() ModelProvenanceMapOutput {
	return o
}

func (o ModelProvenanceMapOutput) ToModelProvenanceMapOutputWithContext(ctx context.Context) ModelProvenanceMapOutput {
	return o
}

func (o ModelProvenanceMapOutput) MapIndex(k pulumi.StringInput) ModelProvenanceOutput {
	return pulumi.All(o, k).ApplyT(func(vs []interface{}) *ModelProvenance {
		return vs[0].(map[string]*ModelProvenance)[vs[1].(string)]
	}).(ModelProvenanceOutput)
}

func init() {
	pulumi.RegisterInputType(reflect.TypeOf((*ModelProvenanceInput)(nil)).Elem(), &ModelProvenance{})
	pulumi.RegisterInputType(reflect.TypeOf((*ModelProvenanceArrayInput)(nil)).Elem(), ModelProvenanceArray{})
	pulumi.RegisterInputType(reflect.TypeOf((*ModelProvenanceMapInput)(nil)).Elem(), ModelProvenanceMap{})
	pulumi.RegisterOutputType(ModelProvenanceOutput{})
	pulumi.RegisterOutputType(ModelProvenanceArrayOutput{})
	pulumi.RegisterOutputType(ModelProvenanceMapOutput{})
}
