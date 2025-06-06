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

// This resource provides the Pipeline resource in Oracle Cloud Infrastructure Data Science service.
//
// Creates a new Pipeline.
//
// ## Import
//
// Pipelines can be imported using the `id`, e.g.
//
// ```sh
// $ pulumi import oci:DataScience/pipeline:Pipeline test_pipeline "id"
// ```
type Pipeline struct {
	pulumi.CustomResourceState

	// (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment where you want to create the pipeline.
	CompartmentId pulumi.StringOutput `pulumi:"compartmentId"`
	// (Updatable) The configuration details of a pipeline.
	ConfigurationDetails PipelineConfigurationDetailsOutput `pulumi:"configurationDetails"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the user who created the pipeline.
	CreatedBy pulumi.StringOutput `pulumi:"createdBy"`
	// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. See [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Operations.CostCenter": "42"}`
	DefinedTags               pulumi.StringMapOutput `pulumi:"definedTags"`
	DeleteRelatedPipelineRuns pulumi.BoolPtrOutput   `pulumi:"deleteRelatedPipelineRuns"`
	// (Updatable) A short description of the pipeline.
	Description pulumi.StringOutput `pulumi:"description"`
	// (Updatable) A user-friendly display name for the resource.
	DisplayName pulumi.StringOutput `pulumi:"displayName"`
	// (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. See [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Department": "Finance"}`
	FreeformTags pulumi.StringMapOutput `pulumi:"freeformTags"`
	// (Updatable) The infrastructure configuration details of a pipeline or a step.
	InfrastructureConfigurationDetails PipelineInfrastructureConfigurationDetailsOutput `pulumi:"infrastructureConfigurationDetails"`
	// A message describing the current state in more detail. For example, can be used to provide actionable information for a resource in 'Failed' state.
	LifecycleDetails pulumi.StringOutput `pulumi:"lifecycleDetails"`
	// (Updatable) The pipeline log configuration details.
	LogConfigurationDetails PipelineLogConfigurationDetailsOutput `pulumi:"logConfigurationDetails"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the project to associate the pipeline with.
	ProjectId pulumi.StringOutput `pulumi:"projectId"`
	// The current state of the pipeline.
	State         pulumi.StringOutput             `pulumi:"state"`
	StepArtifacts PipelineStepArtifactArrayOutput `pulumi:"stepArtifacts"`
	// (Updatable) Array of step details for each step.
	StepDetails PipelineStepDetailArrayOutput `pulumi:"stepDetails"`
	// (Updatable) The storage mount details to mount to the instance running the pipeline step.
	StorageMountConfigurationDetailsLists PipelineStorageMountConfigurationDetailsListArrayOutput `pulumi:"storageMountConfigurationDetailsLists"`
	// Usage of system tag keys. These predefined keys are scoped to namespaces. Example: `{"orcl-cloud.free-tier-retained": "true"}`
	SystemTags pulumi.StringMapOutput `pulumi:"systemTags"`
	// The date and time the resource was created in the timestamp format defined by [RFC3339](https://tools.ietf.org/html/rfc3339). Example: 2020-08-06T21:10:29.41Z
	TimeCreated pulumi.StringOutput `pulumi:"timeCreated"`
	// The date and time the resource was updated in the timestamp format defined by [RFC3339](https://tools.ietf.org/html/rfc3339). Example: 2020-08-06T21:10:29.41Z
	TimeUpdated pulumi.StringOutput `pulumi:"timeUpdated"`
}

// NewPipeline registers a new resource with the given unique name, arguments, and options.
func NewPipeline(ctx *pulumi.Context,
	name string, args *PipelineArgs, opts ...pulumi.ResourceOption) (*Pipeline, error) {
	if args == nil {
		return nil, errors.New("missing one or more required arguments")
	}

	if args.CompartmentId == nil {
		return nil, errors.New("invalid value for required argument 'CompartmentId'")
	}
	if args.ProjectId == nil {
		return nil, errors.New("invalid value for required argument 'ProjectId'")
	}
	if args.StepDetails == nil {
		return nil, errors.New("invalid value for required argument 'StepDetails'")
	}
	opts = internal.PkgResourceDefaultOpts(opts)
	var resource Pipeline
	err := ctx.RegisterResource("oci:DataScience/pipeline:Pipeline", name, args, &resource, opts...)
	if err != nil {
		return nil, err
	}
	return &resource, nil
}

// GetPipeline gets an existing Pipeline resource's state with the given name, ID, and optional
// state properties that are used to uniquely qualify the lookup (nil if not required).
func GetPipeline(ctx *pulumi.Context,
	name string, id pulumi.IDInput, state *PipelineState, opts ...pulumi.ResourceOption) (*Pipeline, error) {
	var resource Pipeline
	err := ctx.ReadResource("oci:DataScience/pipeline:Pipeline", name, id, state, &resource, opts...)
	if err != nil {
		return nil, err
	}
	return &resource, nil
}

// Input properties used for looking up and filtering Pipeline resources.
type pipelineState struct {
	// (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment where you want to create the pipeline.
	CompartmentId *string `pulumi:"compartmentId"`
	// (Updatable) The configuration details of a pipeline.
	ConfigurationDetails *PipelineConfigurationDetails `pulumi:"configurationDetails"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the user who created the pipeline.
	CreatedBy *string `pulumi:"createdBy"`
	// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. See [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Operations.CostCenter": "42"}`
	DefinedTags               map[string]string `pulumi:"definedTags"`
	DeleteRelatedPipelineRuns *bool             `pulumi:"deleteRelatedPipelineRuns"`
	// (Updatable) A short description of the pipeline.
	Description *string `pulumi:"description"`
	// (Updatable) A user-friendly display name for the resource.
	DisplayName *string `pulumi:"displayName"`
	// (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. See [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Department": "Finance"}`
	FreeformTags map[string]string `pulumi:"freeformTags"`
	// (Updatable) The infrastructure configuration details of a pipeline or a step.
	InfrastructureConfigurationDetails *PipelineInfrastructureConfigurationDetails `pulumi:"infrastructureConfigurationDetails"`
	// A message describing the current state in more detail. For example, can be used to provide actionable information for a resource in 'Failed' state.
	LifecycleDetails *string `pulumi:"lifecycleDetails"`
	// (Updatable) The pipeline log configuration details.
	LogConfigurationDetails *PipelineLogConfigurationDetails `pulumi:"logConfigurationDetails"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the project to associate the pipeline with.
	ProjectId *string `pulumi:"projectId"`
	// The current state of the pipeline.
	State         *string                `pulumi:"state"`
	StepArtifacts []PipelineStepArtifact `pulumi:"stepArtifacts"`
	// (Updatable) Array of step details for each step.
	StepDetails []PipelineStepDetail `pulumi:"stepDetails"`
	// (Updatable) The storage mount details to mount to the instance running the pipeline step.
	StorageMountConfigurationDetailsLists []PipelineStorageMountConfigurationDetailsList `pulumi:"storageMountConfigurationDetailsLists"`
	// Usage of system tag keys. These predefined keys are scoped to namespaces. Example: `{"orcl-cloud.free-tier-retained": "true"}`
	SystemTags map[string]string `pulumi:"systemTags"`
	// The date and time the resource was created in the timestamp format defined by [RFC3339](https://tools.ietf.org/html/rfc3339). Example: 2020-08-06T21:10:29.41Z
	TimeCreated *string `pulumi:"timeCreated"`
	// The date and time the resource was updated in the timestamp format defined by [RFC3339](https://tools.ietf.org/html/rfc3339). Example: 2020-08-06T21:10:29.41Z
	TimeUpdated *string `pulumi:"timeUpdated"`
}

type PipelineState struct {
	// (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment where you want to create the pipeline.
	CompartmentId pulumi.StringPtrInput
	// (Updatable) The configuration details of a pipeline.
	ConfigurationDetails PipelineConfigurationDetailsPtrInput
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the user who created the pipeline.
	CreatedBy pulumi.StringPtrInput
	// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. See [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Operations.CostCenter": "42"}`
	DefinedTags               pulumi.StringMapInput
	DeleteRelatedPipelineRuns pulumi.BoolPtrInput
	// (Updatable) A short description of the pipeline.
	Description pulumi.StringPtrInput
	// (Updatable) A user-friendly display name for the resource.
	DisplayName pulumi.StringPtrInput
	// (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. See [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Department": "Finance"}`
	FreeformTags pulumi.StringMapInput
	// (Updatable) The infrastructure configuration details of a pipeline or a step.
	InfrastructureConfigurationDetails PipelineInfrastructureConfigurationDetailsPtrInput
	// A message describing the current state in more detail. For example, can be used to provide actionable information for a resource in 'Failed' state.
	LifecycleDetails pulumi.StringPtrInput
	// (Updatable) The pipeline log configuration details.
	LogConfigurationDetails PipelineLogConfigurationDetailsPtrInput
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the project to associate the pipeline with.
	ProjectId pulumi.StringPtrInput
	// The current state of the pipeline.
	State         pulumi.StringPtrInput
	StepArtifacts PipelineStepArtifactArrayInput
	// (Updatable) Array of step details for each step.
	StepDetails PipelineStepDetailArrayInput
	// (Updatable) The storage mount details to mount to the instance running the pipeline step.
	StorageMountConfigurationDetailsLists PipelineStorageMountConfigurationDetailsListArrayInput
	// Usage of system tag keys. These predefined keys are scoped to namespaces. Example: `{"orcl-cloud.free-tier-retained": "true"}`
	SystemTags pulumi.StringMapInput
	// The date and time the resource was created in the timestamp format defined by [RFC3339](https://tools.ietf.org/html/rfc3339). Example: 2020-08-06T21:10:29.41Z
	TimeCreated pulumi.StringPtrInput
	// The date and time the resource was updated in the timestamp format defined by [RFC3339](https://tools.ietf.org/html/rfc3339). Example: 2020-08-06T21:10:29.41Z
	TimeUpdated pulumi.StringPtrInput
}

func (PipelineState) ElementType() reflect.Type {
	return reflect.TypeOf((*pipelineState)(nil)).Elem()
}

type pipelineArgs struct {
	// (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment where you want to create the pipeline.
	CompartmentId string `pulumi:"compartmentId"`
	// (Updatable) The configuration details of a pipeline.
	ConfigurationDetails *PipelineConfigurationDetails `pulumi:"configurationDetails"`
	// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. See [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Operations.CostCenter": "42"}`
	DefinedTags               map[string]string `pulumi:"definedTags"`
	DeleteRelatedPipelineRuns *bool             `pulumi:"deleteRelatedPipelineRuns"`
	// (Updatable) A short description of the pipeline.
	Description *string `pulumi:"description"`
	// (Updatable) A user-friendly display name for the resource.
	DisplayName *string `pulumi:"displayName"`
	// (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. See [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Department": "Finance"}`
	FreeformTags map[string]string `pulumi:"freeformTags"`
	// (Updatable) The infrastructure configuration details of a pipeline or a step.
	InfrastructureConfigurationDetails *PipelineInfrastructureConfigurationDetails `pulumi:"infrastructureConfigurationDetails"`
	// (Updatable) The pipeline log configuration details.
	LogConfigurationDetails *PipelineLogConfigurationDetails `pulumi:"logConfigurationDetails"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the project to associate the pipeline with.
	ProjectId     string                 `pulumi:"projectId"`
	StepArtifacts []PipelineStepArtifact `pulumi:"stepArtifacts"`
	// (Updatable) Array of step details for each step.
	StepDetails []PipelineStepDetail `pulumi:"stepDetails"`
	// (Updatable) The storage mount details to mount to the instance running the pipeline step.
	StorageMountConfigurationDetailsLists []PipelineStorageMountConfigurationDetailsList `pulumi:"storageMountConfigurationDetailsLists"`
}

// The set of arguments for constructing a Pipeline resource.
type PipelineArgs struct {
	// (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment where you want to create the pipeline.
	CompartmentId pulumi.StringInput
	// (Updatable) The configuration details of a pipeline.
	ConfigurationDetails PipelineConfigurationDetailsPtrInput
	// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. See [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Operations.CostCenter": "42"}`
	DefinedTags               pulumi.StringMapInput
	DeleteRelatedPipelineRuns pulumi.BoolPtrInput
	// (Updatable) A short description of the pipeline.
	Description pulumi.StringPtrInput
	// (Updatable) A user-friendly display name for the resource.
	DisplayName pulumi.StringPtrInput
	// (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. See [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Department": "Finance"}`
	FreeformTags pulumi.StringMapInput
	// (Updatable) The infrastructure configuration details of a pipeline or a step.
	InfrastructureConfigurationDetails PipelineInfrastructureConfigurationDetailsPtrInput
	// (Updatable) The pipeline log configuration details.
	LogConfigurationDetails PipelineLogConfigurationDetailsPtrInput
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the project to associate the pipeline with.
	ProjectId     pulumi.StringInput
	StepArtifacts PipelineStepArtifactArrayInput
	// (Updatable) Array of step details for each step.
	StepDetails PipelineStepDetailArrayInput
	// (Updatable) The storage mount details to mount to the instance running the pipeline step.
	StorageMountConfigurationDetailsLists PipelineStorageMountConfigurationDetailsListArrayInput
}

func (PipelineArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*pipelineArgs)(nil)).Elem()
}

type PipelineInput interface {
	pulumi.Input

	ToPipelineOutput() PipelineOutput
	ToPipelineOutputWithContext(ctx context.Context) PipelineOutput
}

func (*Pipeline) ElementType() reflect.Type {
	return reflect.TypeOf((**Pipeline)(nil)).Elem()
}

func (i *Pipeline) ToPipelineOutput() PipelineOutput {
	return i.ToPipelineOutputWithContext(context.Background())
}

func (i *Pipeline) ToPipelineOutputWithContext(ctx context.Context) PipelineOutput {
	return pulumi.ToOutputWithContext(ctx, i).(PipelineOutput)
}

// PipelineArrayInput is an input type that accepts PipelineArray and PipelineArrayOutput values.
// You can construct a concrete instance of `PipelineArrayInput` via:
//
//	PipelineArray{ PipelineArgs{...} }
type PipelineArrayInput interface {
	pulumi.Input

	ToPipelineArrayOutput() PipelineArrayOutput
	ToPipelineArrayOutputWithContext(context.Context) PipelineArrayOutput
}

type PipelineArray []PipelineInput

func (PipelineArray) ElementType() reflect.Type {
	return reflect.TypeOf((*[]*Pipeline)(nil)).Elem()
}

func (i PipelineArray) ToPipelineArrayOutput() PipelineArrayOutput {
	return i.ToPipelineArrayOutputWithContext(context.Background())
}

func (i PipelineArray) ToPipelineArrayOutputWithContext(ctx context.Context) PipelineArrayOutput {
	return pulumi.ToOutputWithContext(ctx, i).(PipelineArrayOutput)
}

// PipelineMapInput is an input type that accepts PipelineMap and PipelineMapOutput values.
// You can construct a concrete instance of `PipelineMapInput` via:
//
//	PipelineMap{ "key": PipelineArgs{...} }
type PipelineMapInput interface {
	pulumi.Input

	ToPipelineMapOutput() PipelineMapOutput
	ToPipelineMapOutputWithContext(context.Context) PipelineMapOutput
}

type PipelineMap map[string]PipelineInput

func (PipelineMap) ElementType() reflect.Type {
	return reflect.TypeOf((*map[string]*Pipeline)(nil)).Elem()
}

func (i PipelineMap) ToPipelineMapOutput() PipelineMapOutput {
	return i.ToPipelineMapOutputWithContext(context.Background())
}

func (i PipelineMap) ToPipelineMapOutputWithContext(ctx context.Context) PipelineMapOutput {
	return pulumi.ToOutputWithContext(ctx, i).(PipelineMapOutput)
}

type PipelineOutput struct{ *pulumi.OutputState }

func (PipelineOutput) ElementType() reflect.Type {
	return reflect.TypeOf((**Pipeline)(nil)).Elem()
}

func (o PipelineOutput) ToPipelineOutput() PipelineOutput {
	return o
}

func (o PipelineOutput) ToPipelineOutputWithContext(ctx context.Context) PipelineOutput {
	return o
}

// (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment where you want to create the pipeline.
func (o PipelineOutput) CompartmentId() pulumi.StringOutput {
	return o.ApplyT(func(v *Pipeline) pulumi.StringOutput { return v.CompartmentId }).(pulumi.StringOutput)
}

// (Updatable) The configuration details of a pipeline.
func (o PipelineOutput) ConfigurationDetails() PipelineConfigurationDetailsOutput {
	return o.ApplyT(func(v *Pipeline) PipelineConfigurationDetailsOutput { return v.ConfigurationDetails }).(PipelineConfigurationDetailsOutput)
}

// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the user who created the pipeline.
func (o PipelineOutput) CreatedBy() pulumi.StringOutput {
	return o.ApplyT(func(v *Pipeline) pulumi.StringOutput { return v.CreatedBy }).(pulumi.StringOutput)
}

// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. See [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Operations.CostCenter": "42"}`
func (o PipelineOutput) DefinedTags() pulumi.StringMapOutput {
	return o.ApplyT(func(v *Pipeline) pulumi.StringMapOutput { return v.DefinedTags }).(pulumi.StringMapOutput)
}

func (o PipelineOutput) DeleteRelatedPipelineRuns() pulumi.BoolPtrOutput {
	return o.ApplyT(func(v *Pipeline) pulumi.BoolPtrOutput { return v.DeleteRelatedPipelineRuns }).(pulumi.BoolPtrOutput)
}

// (Updatable) A short description of the pipeline.
func (o PipelineOutput) Description() pulumi.StringOutput {
	return o.ApplyT(func(v *Pipeline) pulumi.StringOutput { return v.Description }).(pulumi.StringOutput)
}

// (Updatable) A user-friendly display name for the resource.
func (o PipelineOutput) DisplayName() pulumi.StringOutput {
	return o.ApplyT(func(v *Pipeline) pulumi.StringOutput { return v.DisplayName }).(pulumi.StringOutput)
}

// (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. See [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Department": "Finance"}`
func (o PipelineOutput) FreeformTags() pulumi.StringMapOutput {
	return o.ApplyT(func(v *Pipeline) pulumi.StringMapOutput { return v.FreeformTags }).(pulumi.StringMapOutput)
}

// (Updatable) The infrastructure configuration details of a pipeline or a step.
func (o PipelineOutput) InfrastructureConfigurationDetails() PipelineInfrastructureConfigurationDetailsOutput {
	return o.ApplyT(func(v *Pipeline) PipelineInfrastructureConfigurationDetailsOutput {
		return v.InfrastructureConfigurationDetails
	}).(PipelineInfrastructureConfigurationDetailsOutput)
}

// A message describing the current state in more detail. For example, can be used to provide actionable information for a resource in 'Failed' state.
func (o PipelineOutput) LifecycleDetails() pulumi.StringOutput {
	return o.ApplyT(func(v *Pipeline) pulumi.StringOutput { return v.LifecycleDetails }).(pulumi.StringOutput)
}

// (Updatable) The pipeline log configuration details.
func (o PipelineOutput) LogConfigurationDetails() PipelineLogConfigurationDetailsOutput {
	return o.ApplyT(func(v *Pipeline) PipelineLogConfigurationDetailsOutput { return v.LogConfigurationDetails }).(PipelineLogConfigurationDetailsOutput)
}

// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the project to associate the pipeline with.
func (o PipelineOutput) ProjectId() pulumi.StringOutput {
	return o.ApplyT(func(v *Pipeline) pulumi.StringOutput { return v.ProjectId }).(pulumi.StringOutput)
}

// The current state of the pipeline.
func (o PipelineOutput) State() pulumi.StringOutput {
	return o.ApplyT(func(v *Pipeline) pulumi.StringOutput { return v.State }).(pulumi.StringOutput)
}

func (o PipelineOutput) StepArtifacts() PipelineStepArtifactArrayOutput {
	return o.ApplyT(func(v *Pipeline) PipelineStepArtifactArrayOutput { return v.StepArtifacts }).(PipelineStepArtifactArrayOutput)
}

// (Updatable) Array of step details for each step.
func (o PipelineOutput) StepDetails() PipelineStepDetailArrayOutput {
	return o.ApplyT(func(v *Pipeline) PipelineStepDetailArrayOutput { return v.StepDetails }).(PipelineStepDetailArrayOutput)
}

// (Updatable) The storage mount details to mount to the instance running the pipeline step.
func (o PipelineOutput) StorageMountConfigurationDetailsLists() PipelineStorageMountConfigurationDetailsListArrayOutput {
	return o.ApplyT(func(v *Pipeline) PipelineStorageMountConfigurationDetailsListArrayOutput {
		return v.StorageMountConfigurationDetailsLists
	}).(PipelineStorageMountConfigurationDetailsListArrayOutput)
}

// Usage of system tag keys. These predefined keys are scoped to namespaces. Example: `{"orcl-cloud.free-tier-retained": "true"}`
func (o PipelineOutput) SystemTags() pulumi.StringMapOutput {
	return o.ApplyT(func(v *Pipeline) pulumi.StringMapOutput { return v.SystemTags }).(pulumi.StringMapOutput)
}

// The date and time the resource was created in the timestamp format defined by [RFC3339](https://tools.ietf.org/html/rfc3339). Example: 2020-08-06T21:10:29.41Z
func (o PipelineOutput) TimeCreated() pulumi.StringOutput {
	return o.ApplyT(func(v *Pipeline) pulumi.StringOutput { return v.TimeCreated }).(pulumi.StringOutput)
}

// The date and time the resource was updated in the timestamp format defined by [RFC3339](https://tools.ietf.org/html/rfc3339). Example: 2020-08-06T21:10:29.41Z
func (o PipelineOutput) TimeUpdated() pulumi.StringOutput {
	return o.ApplyT(func(v *Pipeline) pulumi.StringOutput { return v.TimeUpdated }).(pulumi.StringOutput)
}

type PipelineArrayOutput struct{ *pulumi.OutputState }

func (PipelineArrayOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*[]*Pipeline)(nil)).Elem()
}

func (o PipelineArrayOutput) ToPipelineArrayOutput() PipelineArrayOutput {
	return o
}

func (o PipelineArrayOutput) ToPipelineArrayOutputWithContext(ctx context.Context) PipelineArrayOutput {
	return o
}

func (o PipelineArrayOutput) Index(i pulumi.IntInput) PipelineOutput {
	return pulumi.All(o, i).ApplyT(func(vs []interface{}) *Pipeline {
		return vs[0].([]*Pipeline)[vs[1].(int)]
	}).(PipelineOutput)
}

type PipelineMapOutput struct{ *pulumi.OutputState }

func (PipelineMapOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*map[string]*Pipeline)(nil)).Elem()
}

func (o PipelineMapOutput) ToPipelineMapOutput() PipelineMapOutput {
	return o
}

func (o PipelineMapOutput) ToPipelineMapOutputWithContext(ctx context.Context) PipelineMapOutput {
	return o
}

func (o PipelineMapOutput) MapIndex(k pulumi.StringInput) PipelineOutput {
	return pulumi.All(o, k).ApplyT(func(vs []interface{}) *Pipeline {
		return vs[0].(map[string]*Pipeline)[vs[1].(string)]
	}).(PipelineOutput)
}

func init() {
	pulumi.RegisterInputType(reflect.TypeOf((*PipelineInput)(nil)).Elem(), &Pipeline{})
	pulumi.RegisterInputType(reflect.TypeOf((*PipelineArrayInput)(nil)).Elem(), PipelineArray{})
	pulumi.RegisterInputType(reflect.TypeOf((*PipelineMapInput)(nil)).Elem(), PipelineMap{})
	pulumi.RegisterOutputType(PipelineOutput{})
	pulumi.RegisterOutputType(PipelineArrayOutput{})
	pulumi.RegisterOutputType(PipelineMapOutput{})
}
