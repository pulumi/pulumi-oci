// Code generated by the Pulumi Terraform Bridge (tfgen) Tool DO NOT EDIT.
// *** WARNING: Do not edit by hand unless you're certain you know what you are doing! ***

package devops

import (
	"context"
	"reflect"

	"github.com/pkg/errors"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This resource provides the Deployment resource in Oracle Cloud Infrastructure Devops service.
//
// Creates a new deployment.
//
// ## Import
//
// Deployments can be imported using the `id`, e.g.
//
// ```sh
//
//	$ pulumi import oci:DevOps/deployment:Deployment test_deployment "id"
//
// ```
type Deployment struct {
	pulumi.CustomResourceState

	// The OCID of a compartment.
	CompartmentId pulumi.StringOutput `pulumi:"compartmentId"`
	// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. See [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"foo-namespace.bar-key": "value"}`
	DefinedTags pulumi.MapOutput `pulumi:"definedTags"`
	// Specifies the list of artifact override arguments at the time of deployment.
	DeployArtifactOverrideArguments DeploymentDeployArtifactOverrideArgumentsOutput `pulumi:"deployArtifactOverrideArguments"`
	// List of all artifacts used in the pipeline.
	DeployPipelineArtifacts DeploymentDeployPipelineArtifactArrayOutput `pulumi:"deployPipelineArtifacts"`
	// List of all environments used in the pipeline.
	DeployPipelineEnvironments DeploymentDeployPipelineEnvironmentArrayOutput `pulumi:"deployPipelineEnvironments"`
	// The OCID of a pipeline.
	DeployPipelineId pulumi.StringOutput `pulumi:"deployPipelineId"`
	// Specifies the OCID of the stage to be redeployed.
	DeployStageId pulumi.StringOutput `pulumi:"deployStageId"`
	// Specifies list of arguments passed along with the deployment.
	DeploymentArguments DeploymentDeploymentArgumentsOutput `pulumi:"deploymentArguments"`
	// The execution progress details of a deployment.
	DeploymentExecutionProgresses DeploymentDeploymentExecutionProgressArrayOutput `pulumi:"deploymentExecutionProgresses"`
	// (Updatable) Specifies type for this deployment.
	DeploymentType pulumi.StringOutput `pulumi:"deploymentType"`
	// (Updatable) Deployment display name. Avoid entering confidential information.
	DisplayName pulumi.StringOutput `pulumi:"displayName"`
	// (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only.  See [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"bar-key": "value"}`
	FreeformTags pulumi.MapOutput `pulumi:"freeformTags"`
	// A message describing the current state in more detail. For example, can be used to provide actionable information for a resource in Failed state.
	LifecycleDetails pulumi.StringOutput `pulumi:"lifecycleDetails"`
	// Specifies the OCID of the previous deployment to be redeployed.
	PreviousDeploymentId pulumi.StringOutput `pulumi:"previousDeploymentId"`
	// The OCID of a project.
	ProjectId pulumi.StringOutput `pulumi:"projectId"`
	// The current state of the deployment.
	State pulumi.StringOutput `pulumi:"state"`
	// Usage of system tag keys. These predefined keys are scoped to namespaces. See [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"orcl-cloud.free-tier-retained": "true"}`
	SystemTags pulumi.MapOutput `pulumi:"systemTags"`
	// Time the deployment was created. Format defined by [RFC3339](https://datatracker.ietf.org/doc/html/rfc3339).
	TimeCreated pulumi.StringOutput `pulumi:"timeCreated"`
	// Time the deployment was updated. Format defined by [RFC3339](https://datatracker.ietf.org/doc/html/rfc3339).
	TimeUpdated pulumi.StringOutput `pulumi:"timeUpdated"`
}

// NewDeployment registers a new resource with the given unique name, arguments, and options.
func NewDeployment(ctx *pulumi.Context,
	name string, args *DeploymentArgs, opts ...pulumi.ResourceOption) (*Deployment, error) {
	if args == nil {
		return nil, errors.New("missing one or more required arguments")
	}

	if args.DeployPipelineId == nil {
		return nil, errors.New("invalid value for required argument 'DeployPipelineId'")
	}
	if args.DeploymentType == nil {
		return nil, errors.New("invalid value for required argument 'DeploymentType'")
	}
	var resource Deployment
	err := ctx.RegisterResource("oci:DevOps/deployment:Deployment", name, args, &resource, opts...)
	if err != nil {
		return nil, err
	}
	return &resource, nil
}

// GetDeployment gets an existing Deployment resource's state with the given name, ID, and optional
// state properties that are used to uniquely qualify the lookup (nil if not required).
func GetDeployment(ctx *pulumi.Context,
	name string, id pulumi.IDInput, state *DeploymentState, opts ...pulumi.ResourceOption) (*Deployment, error) {
	var resource Deployment
	err := ctx.ReadResource("oci:DevOps/deployment:Deployment", name, id, state, &resource, opts...)
	if err != nil {
		return nil, err
	}
	return &resource, nil
}

// Input properties used for looking up and filtering Deployment resources.
type deploymentState struct {
	// The OCID of a compartment.
	CompartmentId *string `pulumi:"compartmentId"`
	// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. See [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"foo-namespace.bar-key": "value"}`
	DefinedTags map[string]interface{} `pulumi:"definedTags"`
	// Specifies the list of artifact override arguments at the time of deployment.
	DeployArtifactOverrideArguments *DeploymentDeployArtifactOverrideArguments `pulumi:"deployArtifactOverrideArguments"`
	// List of all artifacts used in the pipeline.
	DeployPipelineArtifacts []DeploymentDeployPipelineArtifact `pulumi:"deployPipelineArtifacts"`
	// List of all environments used in the pipeline.
	DeployPipelineEnvironments []DeploymentDeployPipelineEnvironment `pulumi:"deployPipelineEnvironments"`
	// The OCID of a pipeline.
	DeployPipelineId *string `pulumi:"deployPipelineId"`
	// Specifies the OCID of the stage to be redeployed.
	DeployStageId *string `pulumi:"deployStageId"`
	// Specifies list of arguments passed along with the deployment.
	DeploymentArguments *DeploymentDeploymentArguments `pulumi:"deploymentArguments"`
	// The execution progress details of a deployment.
	DeploymentExecutionProgresses []DeploymentDeploymentExecutionProgress `pulumi:"deploymentExecutionProgresses"`
	// (Updatable) Specifies type for this deployment.
	DeploymentType *string `pulumi:"deploymentType"`
	// (Updatable) Deployment display name. Avoid entering confidential information.
	DisplayName *string `pulumi:"displayName"`
	// (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only.  See [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"bar-key": "value"}`
	FreeformTags map[string]interface{} `pulumi:"freeformTags"`
	// A message describing the current state in more detail. For example, can be used to provide actionable information for a resource in Failed state.
	LifecycleDetails *string `pulumi:"lifecycleDetails"`
	// Specifies the OCID of the previous deployment to be redeployed.
	PreviousDeploymentId *string `pulumi:"previousDeploymentId"`
	// The OCID of a project.
	ProjectId *string `pulumi:"projectId"`
	// The current state of the deployment.
	State *string `pulumi:"state"`
	// Usage of system tag keys. These predefined keys are scoped to namespaces. See [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"orcl-cloud.free-tier-retained": "true"}`
	SystemTags map[string]interface{} `pulumi:"systemTags"`
	// Time the deployment was created. Format defined by [RFC3339](https://datatracker.ietf.org/doc/html/rfc3339).
	TimeCreated *string `pulumi:"timeCreated"`
	// Time the deployment was updated. Format defined by [RFC3339](https://datatracker.ietf.org/doc/html/rfc3339).
	TimeUpdated *string `pulumi:"timeUpdated"`
}

type DeploymentState struct {
	// The OCID of a compartment.
	CompartmentId pulumi.StringPtrInput
	// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. See [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"foo-namespace.bar-key": "value"}`
	DefinedTags pulumi.MapInput
	// Specifies the list of artifact override arguments at the time of deployment.
	DeployArtifactOverrideArguments DeploymentDeployArtifactOverrideArgumentsPtrInput
	// List of all artifacts used in the pipeline.
	DeployPipelineArtifacts DeploymentDeployPipelineArtifactArrayInput
	// List of all environments used in the pipeline.
	DeployPipelineEnvironments DeploymentDeployPipelineEnvironmentArrayInput
	// The OCID of a pipeline.
	DeployPipelineId pulumi.StringPtrInput
	// Specifies the OCID of the stage to be redeployed.
	DeployStageId pulumi.StringPtrInput
	// Specifies list of arguments passed along with the deployment.
	DeploymentArguments DeploymentDeploymentArgumentsPtrInput
	// The execution progress details of a deployment.
	DeploymentExecutionProgresses DeploymentDeploymentExecutionProgressArrayInput
	// (Updatable) Specifies type for this deployment.
	DeploymentType pulumi.StringPtrInput
	// (Updatable) Deployment display name. Avoid entering confidential information.
	DisplayName pulumi.StringPtrInput
	// (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only.  See [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"bar-key": "value"}`
	FreeformTags pulumi.MapInput
	// A message describing the current state in more detail. For example, can be used to provide actionable information for a resource in Failed state.
	LifecycleDetails pulumi.StringPtrInput
	// Specifies the OCID of the previous deployment to be redeployed.
	PreviousDeploymentId pulumi.StringPtrInput
	// The OCID of a project.
	ProjectId pulumi.StringPtrInput
	// The current state of the deployment.
	State pulumi.StringPtrInput
	// Usage of system tag keys. These predefined keys are scoped to namespaces. See [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"orcl-cloud.free-tier-retained": "true"}`
	SystemTags pulumi.MapInput
	// Time the deployment was created. Format defined by [RFC3339](https://datatracker.ietf.org/doc/html/rfc3339).
	TimeCreated pulumi.StringPtrInput
	// Time the deployment was updated. Format defined by [RFC3339](https://datatracker.ietf.org/doc/html/rfc3339).
	TimeUpdated pulumi.StringPtrInput
}

func (DeploymentState) ElementType() reflect.Type {
	return reflect.TypeOf((*deploymentState)(nil)).Elem()
}

type deploymentArgs struct {
	// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. See [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"foo-namespace.bar-key": "value"}`
	DefinedTags map[string]interface{} `pulumi:"definedTags"`
	// Specifies the list of artifact override arguments at the time of deployment.
	DeployArtifactOverrideArguments *DeploymentDeployArtifactOverrideArguments `pulumi:"deployArtifactOverrideArguments"`
	// The OCID of a pipeline.
	DeployPipelineId string `pulumi:"deployPipelineId"`
	// Specifies the OCID of the stage to be redeployed.
	DeployStageId *string `pulumi:"deployStageId"`
	// Specifies list of arguments passed along with the deployment.
	DeploymentArguments *DeploymentDeploymentArguments `pulumi:"deploymentArguments"`
	// (Updatable) Specifies type for this deployment.
	DeploymentType string `pulumi:"deploymentType"`
	// (Updatable) Deployment display name. Avoid entering confidential information.
	DisplayName *string `pulumi:"displayName"`
	// (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only.  See [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"bar-key": "value"}`
	FreeformTags map[string]interface{} `pulumi:"freeformTags"`
	// Specifies the OCID of the previous deployment to be redeployed.
	PreviousDeploymentId *string `pulumi:"previousDeploymentId"`
}

// The set of arguments for constructing a Deployment resource.
type DeploymentArgs struct {
	// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. See [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"foo-namespace.bar-key": "value"}`
	DefinedTags pulumi.MapInput
	// Specifies the list of artifact override arguments at the time of deployment.
	DeployArtifactOverrideArguments DeploymentDeployArtifactOverrideArgumentsPtrInput
	// The OCID of a pipeline.
	DeployPipelineId pulumi.StringInput
	// Specifies the OCID of the stage to be redeployed.
	DeployStageId pulumi.StringPtrInput
	// Specifies list of arguments passed along with the deployment.
	DeploymentArguments DeploymentDeploymentArgumentsPtrInput
	// (Updatable) Specifies type for this deployment.
	DeploymentType pulumi.StringInput
	// (Updatable) Deployment display name. Avoid entering confidential information.
	DisplayName pulumi.StringPtrInput
	// (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only.  See [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"bar-key": "value"}`
	FreeformTags pulumi.MapInput
	// Specifies the OCID of the previous deployment to be redeployed.
	PreviousDeploymentId pulumi.StringPtrInput
}

func (DeploymentArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*deploymentArgs)(nil)).Elem()
}

type DeploymentInput interface {
	pulumi.Input

	ToDeploymentOutput() DeploymentOutput
	ToDeploymentOutputWithContext(ctx context.Context) DeploymentOutput
}

func (*Deployment) ElementType() reflect.Type {
	return reflect.TypeOf((**Deployment)(nil)).Elem()
}

func (i *Deployment) ToDeploymentOutput() DeploymentOutput {
	return i.ToDeploymentOutputWithContext(context.Background())
}

func (i *Deployment) ToDeploymentOutputWithContext(ctx context.Context) DeploymentOutput {
	return pulumi.ToOutputWithContext(ctx, i).(DeploymentOutput)
}

// DeploymentArrayInput is an input type that accepts DeploymentArray and DeploymentArrayOutput values.
// You can construct a concrete instance of `DeploymentArrayInput` via:
//
//	DeploymentArray{ DeploymentArgs{...} }
type DeploymentArrayInput interface {
	pulumi.Input

	ToDeploymentArrayOutput() DeploymentArrayOutput
	ToDeploymentArrayOutputWithContext(context.Context) DeploymentArrayOutput
}

type DeploymentArray []DeploymentInput

func (DeploymentArray) ElementType() reflect.Type {
	return reflect.TypeOf((*[]*Deployment)(nil)).Elem()
}

func (i DeploymentArray) ToDeploymentArrayOutput() DeploymentArrayOutput {
	return i.ToDeploymentArrayOutputWithContext(context.Background())
}

func (i DeploymentArray) ToDeploymentArrayOutputWithContext(ctx context.Context) DeploymentArrayOutput {
	return pulumi.ToOutputWithContext(ctx, i).(DeploymentArrayOutput)
}

// DeploymentMapInput is an input type that accepts DeploymentMap and DeploymentMapOutput values.
// You can construct a concrete instance of `DeploymentMapInput` via:
//
//	DeploymentMap{ "key": DeploymentArgs{...} }
type DeploymentMapInput interface {
	pulumi.Input

	ToDeploymentMapOutput() DeploymentMapOutput
	ToDeploymentMapOutputWithContext(context.Context) DeploymentMapOutput
}

type DeploymentMap map[string]DeploymentInput

func (DeploymentMap) ElementType() reflect.Type {
	return reflect.TypeOf((*map[string]*Deployment)(nil)).Elem()
}

func (i DeploymentMap) ToDeploymentMapOutput() DeploymentMapOutput {
	return i.ToDeploymentMapOutputWithContext(context.Background())
}

func (i DeploymentMap) ToDeploymentMapOutputWithContext(ctx context.Context) DeploymentMapOutput {
	return pulumi.ToOutputWithContext(ctx, i).(DeploymentMapOutput)
}

type DeploymentOutput struct{ *pulumi.OutputState }

func (DeploymentOutput) ElementType() reflect.Type {
	return reflect.TypeOf((**Deployment)(nil)).Elem()
}

func (o DeploymentOutput) ToDeploymentOutput() DeploymentOutput {
	return o
}

func (o DeploymentOutput) ToDeploymentOutputWithContext(ctx context.Context) DeploymentOutput {
	return o
}

// The OCID of a compartment.
func (o DeploymentOutput) CompartmentId() pulumi.StringOutput {
	return o.ApplyT(func(v *Deployment) pulumi.StringOutput { return v.CompartmentId }).(pulumi.StringOutput)
}

// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. See [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"foo-namespace.bar-key": "value"}`
func (o DeploymentOutput) DefinedTags() pulumi.MapOutput {
	return o.ApplyT(func(v *Deployment) pulumi.MapOutput { return v.DefinedTags }).(pulumi.MapOutput)
}

// Specifies the list of artifact override arguments at the time of deployment.
func (o DeploymentOutput) DeployArtifactOverrideArguments() DeploymentDeployArtifactOverrideArgumentsOutput {
	return o.ApplyT(func(v *Deployment) DeploymentDeployArtifactOverrideArgumentsOutput {
		return v.DeployArtifactOverrideArguments
	}).(DeploymentDeployArtifactOverrideArgumentsOutput)
}

// List of all artifacts used in the pipeline.
func (o DeploymentOutput) DeployPipelineArtifacts() DeploymentDeployPipelineArtifactArrayOutput {
	return o.ApplyT(func(v *Deployment) DeploymentDeployPipelineArtifactArrayOutput { return v.DeployPipelineArtifacts }).(DeploymentDeployPipelineArtifactArrayOutput)
}

// List of all environments used in the pipeline.
func (o DeploymentOutput) DeployPipelineEnvironments() DeploymentDeployPipelineEnvironmentArrayOutput {
	return o.ApplyT(func(v *Deployment) DeploymentDeployPipelineEnvironmentArrayOutput {
		return v.DeployPipelineEnvironments
	}).(DeploymentDeployPipelineEnvironmentArrayOutput)
}

// The OCID of a pipeline.
func (o DeploymentOutput) DeployPipelineId() pulumi.StringOutput {
	return o.ApplyT(func(v *Deployment) pulumi.StringOutput { return v.DeployPipelineId }).(pulumi.StringOutput)
}

// Specifies the OCID of the stage to be redeployed.
func (o DeploymentOutput) DeployStageId() pulumi.StringOutput {
	return o.ApplyT(func(v *Deployment) pulumi.StringOutput { return v.DeployStageId }).(pulumi.StringOutput)
}

// Specifies list of arguments passed along with the deployment.
func (o DeploymentOutput) DeploymentArguments() DeploymentDeploymentArgumentsOutput {
	return o.ApplyT(func(v *Deployment) DeploymentDeploymentArgumentsOutput { return v.DeploymentArguments }).(DeploymentDeploymentArgumentsOutput)
}

// The execution progress details of a deployment.
func (o DeploymentOutput) DeploymentExecutionProgresses() DeploymentDeploymentExecutionProgressArrayOutput {
	return o.ApplyT(func(v *Deployment) DeploymentDeploymentExecutionProgressArrayOutput {
		return v.DeploymentExecutionProgresses
	}).(DeploymentDeploymentExecutionProgressArrayOutput)
}

// (Updatable) Specifies type for this deployment.
func (o DeploymentOutput) DeploymentType() pulumi.StringOutput {
	return o.ApplyT(func(v *Deployment) pulumi.StringOutput { return v.DeploymentType }).(pulumi.StringOutput)
}

// (Updatable) Deployment display name. Avoid entering confidential information.
func (o DeploymentOutput) DisplayName() pulumi.StringOutput {
	return o.ApplyT(func(v *Deployment) pulumi.StringOutput { return v.DisplayName }).(pulumi.StringOutput)
}

// (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only.  See [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"bar-key": "value"}`
func (o DeploymentOutput) FreeformTags() pulumi.MapOutput {
	return o.ApplyT(func(v *Deployment) pulumi.MapOutput { return v.FreeformTags }).(pulumi.MapOutput)
}

// A message describing the current state in more detail. For example, can be used to provide actionable information for a resource in Failed state.
func (o DeploymentOutput) LifecycleDetails() pulumi.StringOutput {
	return o.ApplyT(func(v *Deployment) pulumi.StringOutput { return v.LifecycleDetails }).(pulumi.StringOutput)
}

// Specifies the OCID of the previous deployment to be redeployed.
func (o DeploymentOutput) PreviousDeploymentId() pulumi.StringOutput {
	return o.ApplyT(func(v *Deployment) pulumi.StringOutput { return v.PreviousDeploymentId }).(pulumi.StringOutput)
}

// The OCID of a project.
func (o DeploymentOutput) ProjectId() pulumi.StringOutput {
	return o.ApplyT(func(v *Deployment) pulumi.StringOutput { return v.ProjectId }).(pulumi.StringOutput)
}

// The current state of the deployment.
func (o DeploymentOutput) State() pulumi.StringOutput {
	return o.ApplyT(func(v *Deployment) pulumi.StringOutput { return v.State }).(pulumi.StringOutput)
}

// Usage of system tag keys. These predefined keys are scoped to namespaces. See [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"orcl-cloud.free-tier-retained": "true"}`
func (o DeploymentOutput) SystemTags() pulumi.MapOutput {
	return o.ApplyT(func(v *Deployment) pulumi.MapOutput { return v.SystemTags }).(pulumi.MapOutput)
}

// Time the deployment was created. Format defined by [RFC3339](https://datatracker.ietf.org/doc/html/rfc3339).
func (o DeploymentOutput) TimeCreated() pulumi.StringOutput {
	return o.ApplyT(func(v *Deployment) pulumi.StringOutput { return v.TimeCreated }).(pulumi.StringOutput)
}

// Time the deployment was updated. Format defined by [RFC3339](https://datatracker.ietf.org/doc/html/rfc3339).
func (o DeploymentOutput) TimeUpdated() pulumi.StringOutput {
	return o.ApplyT(func(v *Deployment) pulumi.StringOutput { return v.TimeUpdated }).(pulumi.StringOutput)
}

type DeploymentArrayOutput struct{ *pulumi.OutputState }

func (DeploymentArrayOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*[]*Deployment)(nil)).Elem()
}

func (o DeploymentArrayOutput) ToDeploymentArrayOutput() DeploymentArrayOutput {
	return o
}

func (o DeploymentArrayOutput) ToDeploymentArrayOutputWithContext(ctx context.Context) DeploymentArrayOutput {
	return o
}

func (o DeploymentArrayOutput) Index(i pulumi.IntInput) DeploymentOutput {
	return pulumi.All(o, i).ApplyT(func(vs []interface{}) *Deployment {
		return vs[0].([]*Deployment)[vs[1].(int)]
	}).(DeploymentOutput)
}

type DeploymentMapOutput struct{ *pulumi.OutputState }

func (DeploymentMapOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*map[string]*Deployment)(nil)).Elem()
}

func (o DeploymentMapOutput) ToDeploymentMapOutput() DeploymentMapOutput {
	return o
}

func (o DeploymentMapOutput) ToDeploymentMapOutputWithContext(ctx context.Context) DeploymentMapOutput {
	return o
}

func (o DeploymentMapOutput) MapIndex(k pulumi.StringInput) DeploymentOutput {
	return pulumi.All(o, k).ApplyT(func(vs []interface{}) *Deployment {
		return vs[0].(map[string]*Deployment)[vs[1].(string)]
	}).(DeploymentOutput)
}

func init() {
	pulumi.RegisterInputType(reflect.TypeOf((*DeploymentInput)(nil)).Elem(), &Deployment{})
	pulumi.RegisterInputType(reflect.TypeOf((*DeploymentArrayInput)(nil)).Elem(), DeploymentArray{})
	pulumi.RegisterInputType(reflect.TypeOf((*DeploymentMapInput)(nil)).Elem(), DeploymentMap{})
	pulumi.RegisterOutputType(DeploymentOutput{})
	pulumi.RegisterOutputType(DeploymentArrayOutput{})
	pulumi.RegisterOutputType(DeploymentMapOutput{})
}