// Code generated by pulumi-language-go DO NOT EDIT.
// *** WARNING: Do not edit by hand unless you're certain you know what you are doing! ***

package mediaservices

import (
	"context"
	"reflect"

	"errors"
	"github.com/pulumi/pulumi-oci/sdk/v3/go/oci/internal"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This resource provides the Media Workflow Job resource in Oracle Cloud Infrastructure Media Services service.
//
// Run the MediaWorkflow according to the given mediaWorkflow definition and configuration.
//
// ## Example Usage
//
// ```go
// package main
//
// import (
//
//	"github.com/pulumi/pulumi-oci/sdk/v3/go/oci/mediaservices"
//	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
//
// )
//
//	func main() {
//		pulumi.Run(func(ctx *pulumi.Context) error {
//			_, err := mediaservices.NewMediaWorkflowJob(ctx, "test_media_workflow_job", &mediaservices.MediaWorkflowJobArgs{
//				CompartmentId:          pulumi.Any(compartmentId),
//				WorkflowIdentifierType: pulumi.Any(mediaWorkflowJobWorkflowIdentifierType),
//				DefinedTags: pulumi.StringMap{
//					"foo-namespace.bar-key": pulumi.String("value"),
//				},
//				DisplayName: pulumi.Any(mediaWorkflowJobDisplayName),
//				FreeformTags: pulumi.StringMap{
//					"bar-key": pulumi.String("value"),
//				},
//				Locks: mediaservices.MediaWorkflowJobLockArray{
//					&mediaservices.MediaWorkflowJobLockArgs{
//						CompartmentId:     pulumi.Any(compartmentId),
//						Type:              pulumi.Any(mediaWorkflowJobLocksType),
//						Message:           pulumi.Any(mediaWorkflowJobLocksMessage),
//						RelatedResourceId: pulumi.Any(testResource.Id),
//						TimeCreated:       pulumi.Any(mediaWorkflowJobLocksTimeCreated),
//					},
//				},
//				MediaWorkflowConfigurationIds: pulumi.Any(mediaWorkflowJobMediaWorkflowConfigurationIds),
//				MediaWorkflowId:               pulumi.Any(testMediaWorkflow.Id),
//				MediaWorkflowName:             pulumi.Any(testMediaWorkflow.Name),
//				Parameters:                    pulumi.Any(mediaWorkflowJobParameters),
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
// MediaWorkflowJobs can be imported using the `id`, e.g.
//
// ```sh
// $ pulumi import oci:MediaServices/mediaWorkflowJob:MediaWorkflowJob test_media_workflow_job "id"
// ```
type MediaWorkflowJob struct {
	pulumi.CustomResourceState

	// (Updatable) ID of the compartment in which the job should be created.
	CompartmentId pulumi.StringOutput `pulumi:"compartmentId"`
	// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
	DefinedTags pulumi.StringMapOutput `pulumi:"definedTags"`
	// (Updatable) Name of the Media Workflow Job. Does not have to be unique. Avoid entering confidential information.
	DisplayName pulumi.StringOutput `pulumi:"displayName"`
	// (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
	FreeformTags   pulumi.StringMapOutput `pulumi:"freeformTags"`
	IsLockOverride pulumi.BoolOutput      `pulumi:"isLockOverride"`
	// The lifecycle details of MediaWorkflowJob task.
	LifecycleDetails pulumi.StringOutput `pulumi:"lifecycleDetails"`
	// Locks associated with this resource.
	Locks MediaWorkflowJobLockArrayOutput `pulumi:"locks"`
	// Configurations to be applied to this run of the workflow.
	MediaWorkflowConfigurationIds pulumi.StringArrayOutput `pulumi:"mediaWorkflowConfigurationIds"`
	// OCID of the MediaWorkflow that should be run.
	MediaWorkflowId pulumi.StringOutput `pulumi:"mediaWorkflowId"`
	// Name of the system MediaWorkflow that should be run.
	MediaWorkflowName pulumi.StringOutput `pulumi:"mediaWorkflowName"`
	// A list of JobOutput for the workflowJob.
	Outputs MediaWorkflowJobOutputTypeArrayOutput `pulumi:"outputs"`
	// Parameters that override parameters specified in MediaWorkflowTaskDeclarations, the MediaWorkflow, the MediaWorkflow's MediaWorkflowConfigurations and the MediaWorkflowConfigurations of this MediaWorkflowJob. The parameters are given as JSON. The top level and 2nd level elements must be JSON objects (vs arrays, scalars, etc). The top level keys refer to a task's key and the 2nd level keys refer to a parameter's name.
	Parameters pulumi.StringOutput `pulumi:"parameters"`
	// A JSON representation of the job as it will be run by the system. All the task declarations, configurations and parameters are merged. Parameter values are all fully resolved.
	Runnable pulumi.StringOutput `pulumi:"runnable"`
	// The current state of the MediaWorkflowJob task.
	State pulumi.StringOutput `pulumi:"state"`
	// Usage of system tag keys. These predefined keys are scoped to namespaces. Example: `{"orcl-cloud.free-tier-retained": "true"}`
	SystemTags pulumi.StringMapOutput `pulumi:"systemTags"`
	// Status of each task.
	TaskLifecycleStates MediaWorkflowJobTaskLifecycleStateArrayOutput `pulumi:"taskLifecycleStates"`
	// Creation time of the job. An RFC3339 formatted datetime string.
	TimeCreated pulumi.StringOutput `pulumi:"timeCreated"`
	// Time when the job finished. An RFC3339 formatted datetime string.
	TimeEnded pulumi.StringOutput `pulumi:"timeEnded"`
	// Time when the job started to execute. An RFC3339 formatted datetime string.
	TimeStarted pulumi.StringOutput `pulumi:"timeStarted"`
	// Updated time of the job. An RFC3339 formatted datetime string.
	TimeUpdated pulumi.StringOutput `pulumi:"timeUpdated"`
	// Discriminate identification of a workflow by name versus a workflow by ID.
	//
	// ** IMPORTANT **
	// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
	WorkflowIdentifierType pulumi.StringOutput `pulumi:"workflowIdentifierType"`
}

// NewMediaWorkflowJob registers a new resource with the given unique name, arguments, and options.
func NewMediaWorkflowJob(ctx *pulumi.Context,
	name string, args *MediaWorkflowJobArgs, opts ...pulumi.ResourceOption) (*MediaWorkflowJob, error) {
	if args == nil {
		return nil, errors.New("missing one or more required arguments")
	}

	if args.CompartmentId == nil {
		return nil, errors.New("invalid value for required argument 'CompartmentId'")
	}
	if args.WorkflowIdentifierType == nil {
		return nil, errors.New("invalid value for required argument 'WorkflowIdentifierType'")
	}
	opts = internal.PkgResourceDefaultOpts(opts)
	var resource MediaWorkflowJob
	err := ctx.RegisterResource("oci:MediaServices/mediaWorkflowJob:MediaWorkflowJob", name, args, &resource, opts...)
	if err != nil {
		return nil, err
	}
	return &resource, nil
}

// GetMediaWorkflowJob gets an existing MediaWorkflowJob resource's state with the given name, ID, and optional
// state properties that are used to uniquely qualify the lookup (nil if not required).
func GetMediaWorkflowJob(ctx *pulumi.Context,
	name string, id pulumi.IDInput, state *MediaWorkflowJobState, opts ...pulumi.ResourceOption) (*MediaWorkflowJob, error) {
	var resource MediaWorkflowJob
	err := ctx.ReadResource("oci:MediaServices/mediaWorkflowJob:MediaWorkflowJob", name, id, state, &resource, opts...)
	if err != nil {
		return nil, err
	}
	return &resource, nil
}

// Input properties used for looking up and filtering MediaWorkflowJob resources.
type mediaWorkflowJobState struct {
	// (Updatable) ID of the compartment in which the job should be created.
	CompartmentId *string `pulumi:"compartmentId"`
	// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
	DefinedTags map[string]string `pulumi:"definedTags"`
	// (Updatable) Name of the Media Workflow Job. Does not have to be unique. Avoid entering confidential information.
	DisplayName *string `pulumi:"displayName"`
	// (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
	FreeformTags   map[string]string `pulumi:"freeformTags"`
	IsLockOverride *bool             `pulumi:"isLockOverride"`
	// The lifecycle details of MediaWorkflowJob task.
	LifecycleDetails *string `pulumi:"lifecycleDetails"`
	// Locks associated with this resource.
	Locks []MediaWorkflowJobLock `pulumi:"locks"`
	// Configurations to be applied to this run of the workflow.
	MediaWorkflowConfigurationIds []string `pulumi:"mediaWorkflowConfigurationIds"`
	// OCID of the MediaWorkflow that should be run.
	MediaWorkflowId *string `pulumi:"mediaWorkflowId"`
	// Name of the system MediaWorkflow that should be run.
	MediaWorkflowName *string `pulumi:"mediaWorkflowName"`
	// A list of JobOutput for the workflowJob.
	Outputs []MediaWorkflowJobOutputType `pulumi:"outputs"`
	// Parameters that override parameters specified in MediaWorkflowTaskDeclarations, the MediaWorkflow, the MediaWorkflow's MediaWorkflowConfigurations and the MediaWorkflowConfigurations of this MediaWorkflowJob. The parameters are given as JSON. The top level and 2nd level elements must be JSON objects (vs arrays, scalars, etc). The top level keys refer to a task's key and the 2nd level keys refer to a parameter's name.
	Parameters *string `pulumi:"parameters"`
	// A JSON representation of the job as it will be run by the system. All the task declarations, configurations and parameters are merged. Parameter values are all fully resolved.
	Runnable *string `pulumi:"runnable"`
	// The current state of the MediaWorkflowJob task.
	State *string `pulumi:"state"`
	// Usage of system tag keys. These predefined keys are scoped to namespaces. Example: `{"orcl-cloud.free-tier-retained": "true"}`
	SystemTags map[string]string `pulumi:"systemTags"`
	// Status of each task.
	TaskLifecycleStates []MediaWorkflowJobTaskLifecycleState `pulumi:"taskLifecycleStates"`
	// Creation time of the job. An RFC3339 formatted datetime string.
	TimeCreated *string `pulumi:"timeCreated"`
	// Time when the job finished. An RFC3339 formatted datetime string.
	TimeEnded *string `pulumi:"timeEnded"`
	// Time when the job started to execute. An RFC3339 formatted datetime string.
	TimeStarted *string `pulumi:"timeStarted"`
	// Updated time of the job. An RFC3339 formatted datetime string.
	TimeUpdated *string `pulumi:"timeUpdated"`
	// Discriminate identification of a workflow by name versus a workflow by ID.
	//
	// ** IMPORTANT **
	// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
	WorkflowIdentifierType *string `pulumi:"workflowIdentifierType"`
}

type MediaWorkflowJobState struct {
	// (Updatable) ID of the compartment in which the job should be created.
	CompartmentId pulumi.StringPtrInput
	// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
	DefinedTags pulumi.StringMapInput
	// (Updatable) Name of the Media Workflow Job. Does not have to be unique. Avoid entering confidential information.
	DisplayName pulumi.StringPtrInput
	// (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
	FreeformTags   pulumi.StringMapInput
	IsLockOverride pulumi.BoolPtrInput
	// The lifecycle details of MediaWorkflowJob task.
	LifecycleDetails pulumi.StringPtrInput
	// Locks associated with this resource.
	Locks MediaWorkflowJobLockArrayInput
	// Configurations to be applied to this run of the workflow.
	MediaWorkflowConfigurationIds pulumi.StringArrayInput
	// OCID of the MediaWorkflow that should be run.
	MediaWorkflowId pulumi.StringPtrInput
	// Name of the system MediaWorkflow that should be run.
	MediaWorkflowName pulumi.StringPtrInput
	// A list of JobOutput for the workflowJob.
	Outputs MediaWorkflowJobOutputTypeArrayInput
	// Parameters that override parameters specified in MediaWorkflowTaskDeclarations, the MediaWorkflow, the MediaWorkflow's MediaWorkflowConfigurations and the MediaWorkflowConfigurations of this MediaWorkflowJob. The parameters are given as JSON. The top level and 2nd level elements must be JSON objects (vs arrays, scalars, etc). The top level keys refer to a task's key and the 2nd level keys refer to a parameter's name.
	Parameters pulumi.StringPtrInput
	// A JSON representation of the job as it will be run by the system. All the task declarations, configurations and parameters are merged. Parameter values are all fully resolved.
	Runnable pulumi.StringPtrInput
	// The current state of the MediaWorkflowJob task.
	State pulumi.StringPtrInput
	// Usage of system tag keys. These predefined keys are scoped to namespaces. Example: `{"orcl-cloud.free-tier-retained": "true"}`
	SystemTags pulumi.StringMapInput
	// Status of each task.
	TaskLifecycleStates MediaWorkflowJobTaskLifecycleStateArrayInput
	// Creation time of the job. An RFC3339 formatted datetime string.
	TimeCreated pulumi.StringPtrInput
	// Time when the job finished. An RFC3339 formatted datetime string.
	TimeEnded pulumi.StringPtrInput
	// Time when the job started to execute. An RFC3339 formatted datetime string.
	TimeStarted pulumi.StringPtrInput
	// Updated time of the job. An RFC3339 formatted datetime string.
	TimeUpdated pulumi.StringPtrInput
	// Discriminate identification of a workflow by name versus a workflow by ID.
	//
	// ** IMPORTANT **
	// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
	WorkflowIdentifierType pulumi.StringPtrInput
}

func (MediaWorkflowJobState) ElementType() reflect.Type {
	return reflect.TypeOf((*mediaWorkflowJobState)(nil)).Elem()
}

type mediaWorkflowJobArgs struct {
	// (Updatable) ID of the compartment in which the job should be created.
	CompartmentId string `pulumi:"compartmentId"`
	// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
	DefinedTags map[string]string `pulumi:"definedTags"`
	// (Updatable) Name of the Media Workflow Job. Does not have to be unique. Avoid entering confidential information.
	DisplayName *string `pulumi:"displayName"`
	// (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
	FreeformTags   map[string]string `pulumi:"freeformTags"`
	IsLockOverride *bool             `pulumi:"isLockOverride"`
	// Locks associated with this resource.
	Locks []MediaWorkflowJobLock `pulumi:"locks"`
	// Configurations to be applied to this run of the workflow.
	MediaWorkflowConfigurationIds []string `pulumi:"mediaWorkflowConfigurationIds"`
	// OCID of the MediaWorkflow that should be run.
	MediaWorkflowId *string `pulumi:"mediaWorkflowId"`
	// Name of the system MediaWorkflow that should be run.
	MediaWorkflowName *string `pulumi:"mediaWorkflowName"`
	// Parameters that override parameters specified in MediaWorkflowTaskDeclarations, the MediaWorkflow, the MediaWorkflow's MediaWorkflowConfigurations and the MediaWorkflowConfigurations of this MediaWorkflowJob. The parameters are given as JSON. The top level and 2nd level elements must be JSON objects (vs arrays, scalars, etc). The top level keys refer to a task's key and the 2nd level keys refer to a parameter's name.
	Parameters *string `pulumi:"parameters"`
	// Discriminate identification of a workflow by name versus a workflow by ID.
	//
	// ** IMPORTANT **
	// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
	WorkflowIdentifierType string `pulumi:"workflowIdentifierType"`
}

// The set of arguments for constructing a MediaWorkflowJob resource.
type MediaWorkflowJobArgs struct {
	// (Updatable) ID of the compartment in which the job should be created.
	CompartmentId pulumi.StringInput
	// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
	DefinedTags pulumi.StringMapInput
	// (Updatable) Name of the Media Workflow Job. Does not have to be unique. Avoid entering confidential information.
	DisplayName pulumi.StringPtrInput
	// (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
	FreeformTags   pulumi.StringMapInput
	IsLockOverride pulumi.BoolPtrInput
	// Locks associated with this resource.
	Locks MediaWorkflowJobLockArrayInput
	// Configurations to be applied to this run of the workflow.
	MediaWorkflowConfigurationIds pulumi.StringArrayInput
	// OCID of the MediaWorkflow that should be run.
	MediaWorkflowId pulumi.StringPtrInput
	// Name of the system MediaWorkflow that should be run.
	MediaWorkflowName pulumi.StringPtrInput
	// Parameters that override parameters specified in MediaWorkflowTaskDeclarations, the MediaWorkflow, the MediaWorkflow's MediaWorkflowConfigurations and the MediaWorkflowConfigurations of this MediaWorkflowJob. The parameters are given as JSON. The top level and 2nd level elements must be JSON objects (vs arrays, scalars, etc). The top level keys refer to a task's key and the 2nd level keys refer to a parameter's name.
	Parameters pulumi.StringPtrInput
	// Discriminate identification of a workflow by name versus a workflow by ID.
	//
	// ** IMPORTANT **
	// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
	WorkflowIdentifierType pulumi.StringInput
}

func (MediaWorkflowJobArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*mediaWorkflowJobArgs)(nil)).Elem()
}

type MediaWorkflowJobInput interface {
	pulumi.Input

	ToMediaWorkflowJobOutput() MediaWorkflowJobOutput
	ToMediaWorkflowJobOutputWithContext(ctx context.Context) MediaWorkflowJobOutput
}

func (*MediaWorkflowJob) ElementType() reflect.Type {
	return reflect.TypeOf((**MediaWorkflowJob)(nil)).Elem()
}

func (i *MediaWorkflowJob) ToMediaWorkflowJobOutput() MediaWorkflowJobOutput {
	return i.ToMediaWorkflowJobOutputWithContext(context.Background())
}

func (i *MediaWorkflowJob) ToMediaWorkflowJobOutputWithContext(ctx context.Context) MediaWorkflowJobOutput {
	return pulumi.ToOutputWithContext(ctx, i).(MediaWorkflowJobOutput)
}

// MediaWorkflowJobArrayInput is an input type that accepts MediaWorkflowJobArray and MediaWorkflowJobArrayOutput values.
// You can construct a concrete instance of `MediaWorkflowJobArrayInput` via:
//
//	MediaWorkflowJobArray{ MediaWorkflowJobArgs{...} }
type MediaWorkflowJobArrayInput interface {
	pulumi.Input

	ToMediaWorkflowJobArrayOutput() MediaWorkflowJobArrayOutput
	ToMediaWorkflowJobArrayOutputWithContext(context.Context) MediaWorkflowJobArrayOutput
}

type MediaWorkflowJobArray []MediaWorkflowJobInput

func (MediaWorkflowJobArray) ElementType() reflect.Type {
	return reflect.TypeOf((*[]*MediaWorkflowJob)(nil)).Elem()
}

func (i MediaWorkflowJobArray) ToMediaWorkflowJobArrayOutput() MediaWorkflowJobArrayOutput {
	return i.ToMediaWorkflowJobArrayOutputWithContext(context.Background())
}

func (i MediaWorkflowJobArray) ToMediaWorkflowJobArrayOutputWithContext(ctx context.Context) MediaWorkflowJobArrayOutput {
	return pulumi.ToOutputWithContext(ctx, i).(MediaWorkflowJobArrayOutput)
}

// MediaWorkflowJobMapInput is an input type that accepts MediaWorkflowJobMap and MediaWorkflowJobMapOutput values.
// You can construct a concrete instance of `MediaWorkflowJobMapInput` via:
//
//	MediaWorkflowJobMap{ "key": MediaWorkflowJobArgs{...} }
type MediaWorkflowJobMapInput interface {
	pulumi.Input

	ToMediaWorkflowJobMapOutput() MediaWorkflowJobMapOutput
	ToMediaWorkflowJobMapOutputWithContext(context.Context) MediaWorkflowJobMapOutput
}

type MediaWorkflowJobMap map[string]MediaWorkflowJobInput

func (MediaWorkflowJobMap) ElementType() reflect.Type {
	return reflect.TypeOf((*map[string]*MediaWorkflowJob)(nil)).Elem()
}

func (i MediaWorkflowJobMap) ToMediaWorkflowJobMapOutput() MediaWorkflowJobMapOutput {
	return i.ToMediaWorkflowJobMapOutputWithContext(context.Background())
}

func (i MediaWorkflowJobMap) ToMediaWorkflowJobMapOutputWithContext(ctx context.Context) MediaWorkflowJobMapOutput {
	return pulumi.ToOutputWithContext(ctx, i).(MediaWorkflowJobMapOutput)
}

type MediaWorkflowJobOutput struct{ *pulumi.OutputState }

func (MediaWorkflowJobOutput) ElementType() reflect.Type {
	return reflect.TypeOf((**MediaWorkflowJob)(nil)).Elem()
}

func (o MediaWorkflowJobOutput) ToMediaWorkflowJobOutput() MediaWorkflowJobOutput {
	return o
}

func (o MediaWorkflowJobOutput) ToMediaWorkflowJobOutputWithContext(ctx context.Context) MediaWorkflowJobOutput {
	return o
}

// (Updatable) ID of the compartment in which the job should be created.
func (o MediaWorkflowJobOutput) CompartmentId() pulumi.StringOutput {
	return o.ApplyT(func(v *MediaWorkflowJob) pulumi.StringOutput { return v.CompartmentId }).(pulumi.StringOutput)
}

// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
func (o MediaWorkflowJobOutput) DefinedTags() pulumi.StringMapOutput {
	return o.ApplyT(func(v *MediaWorkflowJob) pulumi.StringMapOutput { return v.DefinedTags }).(pulumi.StringMapOutput)
}

// (Updatable) Name of the Media Workflow Job. Does not have to be unique. Avoid entering confidential information.
func (o MediaWorkflowJobOutput) DisplayName() pulumi.StringOutput {
	return o.ApplyT(func(v *MediaWorkflowJob) pulumi.StringOutput { return v.DisplayName }).(pulumi.StringOutput)
}

// (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
func (o MediaWorkflowJobOutput) FreeformTags() pulumi.StringMapOutput {
	return o.ApplyT(func(v *MediaWorkflowJob) pulumi.StringMapOutput { return v.FreeformTags }).(pulumi.StringMapOutput)
}

func (o MediaWorkflowJobOutput) IsLockOverride() pulumi.BoolOutput {
	return o.ApplyT(func(v *MediaWorkflowJob) pulumi.BoolOutput { return v.IsLockOverride }).(pulumi.BoolOutput)
}

// The lifecycle details of MediaWorkflowJob task.
func (o MediaWorkflowJobOutput) LifecycleDetails() pulumi.StringOutput {
	return o.ApplyT(func(v *MediaWorkflowJob) pulumi.StringOutput { return v.LifecycleDetails }).(pulumi.StringOutput)
}

// Locks associated with this resource.
func (o MediaWorkflowJobOutput) Locks() MediaWorkflowJobLockArrayOutput {
	return o.ApplyT(func(v *MediaWorkflowJob) MediaWorkflowJobLockArrayOutput { return v.Locks }).(MediaWorkflowJobLockArrayOutput)
}

// Configurations to be applied to this run of the workflow.
func (o MediaWorkflowJobOutput) MediaWorkflowConfigurationIds() pulumi.StringArrayOutput {
	return o.ApplyT(func(v *MediaWorkflowJob) pulumi.StringArrayOutput { return v.MediaWorkflowConfigurationIds }).(pulumi.StringArrayOutput)
}

// OCID of the MediaWorkflow that should be run.
func (o MediaWorkflowJobOutput) MediaWorkflowId() pulumi.StringOutput {
	return o.ApplyT(func(v *MediaWorkflowJob) pulumi.StringOutput { return v.MediaWorkflowId }).(pulumi.StringOutput)
}

// Name of the system MediaWorkflow that should be run.
func (o MediaWorkflowJobOutput) MediaWorkflowName() pulumi.StringOutput {
	return o.ApplyT(func(v *MediaWorkflowJob) pulumi.StringOutput { return v.MediaWorkflowName }).(pulumi.StringOutput)
}

// A list of JobOutput for the workflowJob.
func (o MediaWorkflowJobOutput) Outputs() MediaWorkflowJobOutputTypeArrayOutput {
	return o.ApplyT(func(v *MediaWorkflowJob) MediaWorkflowJobOutputTypeArrayOutput { return v.Outputs }).(MediaWorkflowJobOutputTypeArrayOutput)
}

// Parameters that override parameters specified in MediaWorkflowTaskDeclarations, the MediaWorkflow, the MediaWorkflow's MediaWorkflowConfigurations and the MediaWorkflowConfigurations of this MediaWorkflowJob. The parameters are given as JSON. The top level and 2nd level elements must be JSON objects (vs arrays, scalars, etc). The top level keys refer to a task's key and the 2nd level keys refer to a parameter's name.
func (o MediaWorkflowJobOutput) Parameters() pulumi.StringOutput {
	return o.ApplyT(func(v *MediaWorkflowJob) pulumi.StringOutput { return v.Parameters }).(pulumi.StringOutput)
}

// A JSON representation of the job as it will be run by the system. All the task declarations, configurations and parameters are merged. Parameter values are all fully resolved.
func (o MediaWorkflowJobOutput) Runnable() pulumi.StringOutput {
	return o.ApplyT(func(v *MediaWorkflowJob) pulumi.StringOutput { return v.Runnable }).(pulumi.StringOutput)
}

// The current state of the MediaWorkflowJob task.
func (o MediaWorkflowJobOutput) State() pulumi.StringOutput {
	return o.ApplyT(func(v *MediaWorkflowJob) pulumi.StringOutput { return v.State }).(pulumi.StringOutput)
}

// Usage of system tag keys. These predefined keys are scoped to namespaces. Example: `{"orcl-cloud.free-tier-retained": "true"}`
func (o MediaWorkflowJobOutput) SystemTags() pulumi.StringMapOutput {
	return o.ApplyT(func(v *MediaWorkflowJob) pulumi.StringMapOutput { return v.SystemTags }).(pulumi.StringMapOutput)
}

// Status of each task.
func (o MediaWorkflowJobOutput) TaskLifecycleStates() MediaWorkflowJobTaskLifecycleStateArrayOutput {
	return o.ApplyT(func(v *MediaWorkflowJob) MediaWorkflowJobTaskLifecycleStateArrayOutput { return v.TaskLifecycleStates }).(MediaWorkflowJobTaskLifecycleStateArrayOutput)
}

// Creation time of the job. An RFC3339 formatted datetime string.
func (o MediaWorkflowJobOutput) TimeCreated() pulumi.StringOutput {
	return o.ApplyT(func(v *MediaWorkflowJob) pulumi.StringOutput { return v.TimeCreated }).(pulumi.StringOutput)
}

// Time when the job finished. An RFC3339 formatted datetime string.
func (o MediaWorkflowJobOutput) TimeEnded() pulumi.StringOutput {
	return o.ApplyT(func(v *MediaWorkflowJob) pulumi.StringOutput { return v.TimeEnded }).(pulumi.StringOutput)
}

// Time when the job started to execute. An RFC3339 formatted datetime string.
func (o MediaWorkflowJobOutput) TimeStarted() pulumi.StringOutput {
	return o.ApplyT(func(v *MediaWorkflowJob) pulumi.StringOutput { return v.TimeStarted }).(pulumi.StringOutput)
}

// Updated time of the job. An RFC3339 formatted datetime string.
func (o MediaWorkflowJobOutput) TimeUpdated() pulumi.StringOutput {
	return o.ApplyT(func(v *MediaWorkflowJob) pulumi.StringOutput { return v.TimeUpdated }).(pulumi.StringOutput)
}

// Discriminate identification of a workflow by name versus a workflow by ID.
//
// ** IMPORTANT **
// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
func (o MediaWorkflowJobOutput) WorkflowIdentifierType() pulumi.StringOutput {
	return o.ApplyT(func(v *MediaWorkflowJob) pulumi.StringOutput { return v.WorkflowIdentifierType }).(pulumi.StringOutput)
}

type MediaWorkflowJobArrayOutput struct{ *pulumi.OutputState }

func (MediaWorkflowJobArrayOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*[]*MediaWorkflowJob)(nil)).Elem()
}

func (o MediaWorkflowJobArrayOutput) ToMediaWorkflowJobArrayOutput() MediaWorkflowJobArrayOutput {
	return o
}

func (o MediaWorkflowJobArrayOutput) ToMediaWorkflowJobArrayOutputWithContext(ctx context.Context) MediaWorkflowJobArrayOutput {
	return o
}

func (o MediaWorkflowJobArrayOutput) Index(i pulumi.IntInput) MediaWorkflowJobOutput {
	return pulumi.All(o, i).ApplyT(func(vs []interface{}) *MediaWorkflowJob {
		return vs[0].([]*MediaWorkflowJob)[vs[1].(int)]
	}).(MediaWorkflowJobOutput)
}

type MediaWorkflowJobMapOutput struct{ *pulumi.OutputState }

func (MediaWorkflowJobMapOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*map[string]*MediaWorkflowJob)(nil)).Elem()
}

func (o MediaWorkflowJobMapOutput) ToMediaWorkflowJobMapOutput() MediaWorkflowJobMapOutput {
	return o
}

func (o MediaWorkflowJobMapOutput) ToMediaWorkflowJobMapOutputWithContext(ctx context.Context) MediaWorkflowJobMapOutput {
	return o
}

func (o MediaWorkflowJobMapOutput) MapIndex(k pulumi.StringInput) MediaWorkflowJobOutput {
	return pulumi.All(o, k).ApplyT(func(vs []interface{}) *MediaWorkflowJob {
		return vs[0].(map[string]*MediaWorkflowJob)[vs[1].(string)]
	}).(MediaWorkflowJobOutput)
}

func init() {
	pulumi.RegisterInputType(reflect.TypeOf((*MediaWorkflowJobInput)(nil)).Elem(), &MediaWorkflowJob{})
	pulumi.RegisterInputType(reflect.TypeOf((*MediaWorkflowJobArrayInput)(nil)).Elem(), MediaWorkflowJobArray{})
	pulumi.RegisterInputType(reflect.TypeOf((*MediaWorkflowJobMapInput)(nil)).Elem(), MediaWorkflowJobMap{})
	pulumi.RegisterOutputType(MediaWorkflowJobOutput{})
	pulumi.RegisterOutputType(MediaWorkflowJobArrayOutput{})
	pulumi.RegisterOutputType(MediaWorkflowJobMapOutput{})
}
