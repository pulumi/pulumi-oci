// Code generated by the Pulumi Terraform Bridge (tfgen) Tool DO NOT EDIT.
// *** WARNING: Do not edit by hand unless you're certain you know what you are doing! ***

package mediaservices

import (
	"context"
	"reflect"

	"errors"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This resource provides the Media Workflow resource in Oracle Cloud Infrastructure Media Services service.
//
// Creates a new MediaWorkflow.
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
//			_, err := MediaServices.NewMediaWorkflow(ctx, "testMediaWorkflow", &MediaServices.MediaWorkflowArgs{
//				CompartmentId: pulumi.Any(_var.Compartment_id),
//				DisplayName:   pulumi.Any(_var.Media_workflow_display_name),
//				DefinedTags: pulumi.AnyMap{
//					"foo-namespace.bar-key": pulumi.Any("value"),
//				},
//				FreeformTags: pulumi.AnyMap{
//					"bar-key": pulumi.Any("value"),
//				},
//				MediaWorkflowConfigurationIds: pulumi.Any(_var.Media_workflow_media_workflow_configuration_ids),
//				Parameters:                    pulumi.Any(_var.Media_workflow_parameters),
//				Tasks: mediaservices.MediaWorkflowTaskArray{
//					&mediaservices.MediaWorkflowTaskArgs{
//						Key:                                 pulumi.Any(_var.Media_workflow_tasks_key),
//						Parameters:                          pulumi.Any(_var.Media_workflow_tasks_parameters),
//						Type:                                pulumi.Any(_var.Media_workflow_tasks_type),
//						Version:                             pulumi.Any(_var.Media_workflow_tasks_version),
//						EnableParameterReference:            pulumi.Any(_var.Media_workflow_tasks_enable_parameter_reference),
//						EnableWhenReferencedParameterEquals: pulumi.Any(_var.Media_workflow_tasks_enable_when_referenced_parameter_equals),
//						Prerequisites:                       pulumi.Any(_var.Media_workflow_tasks_prerequisites),
//					},
//				},
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
// MediaWorkflows can be imported using the `id`, e.g.
//
// ```sh
//
//	$ pulumi import oci:MediaServices/mediaWorkflow:MediaWorkflow test_media_workflow "id"
//
// ```
type MediaWorkflow struct {
	pulumi.CustomResourceState

	// (Updatable) Compartment Identifier.
	CompartmentId pulumi.StringOutput `pulumi:"compartmentId"`
	// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
	DefinedTags pulumi.MapOutput `pulumi:"definedTags"`
	// (Updatable) Name for the MediaWorkflow. Does not have to be unique, and it's changeable. Avoid entering confidential information.
	DisplayName pulumi.StringOutput `pulumi:"displayName"`
	// (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
	FreeformTags pulumi.MapOutput `pulumi:"freeformTags"`
	// A message describing the current state in more detail. For example, can be used to provide actionable information for a resource in Failed state.
	LifecyleDetails pulumi.StringOutput `pulumi:"lifecyleDetails"`
	// (Updatable) Configurations to be applied to all the jobs for this workflow. Parameters in these configurations are overridden by parameters in the MediaWorkflowConfigurations of the MediaWorkflowJob and the parameters of the MediaWorkflowJob.
	MediaWorkflowConfigurationIds pulumi.StringArrayOutput `pulumi:"mediaWorkflowConfigurationIds"`
	// (Updatable) Data specifiying how this task is to be run. The data is a JSON object that must conform to the JSON Schema specified by the parameters of the MediaWorkflowTaskDeclaration this task references. The parameters may contain values or references to other parameters.
	Parameters pulumi.StringOutput `pulumi:"parameters"`
	// The current state of the MediaWorkflow.
	State pulumi.StringOutput `pulumi:"state"`
	// Usage of system tag keys. These predefined keys are scoped to namespaces. Example: `{"orcl-cloud.free-tier-retained": "true"}`
	SystemTags pulumi.MapOutput `pulumi:"systemTags"`
	// (Updatable) The processing to be done in this workflow. Each key of the MediaWorkflowTasks in this array must be unique within the array. The order of tasks given here will be preserved.
	Tasks MediaWorkflowTaskArrayOutput `pulumi:"tasks"`
	// The time when the MediaWorkflow was created. An RFC3339 formatted datetime string.
	TimeCreated pulumi.StringOutput `pulumi:"timeCreated"`
	// The time when the MediaWorkflow was updated. An RFC3339 formatted datetime string.
	TimeUpdated pulumi.StringOutput `pulumi:"timeUpdated"`
	// (Updatable) The version of the MediaWorkflowTaskDeclaration.
	Version pulumi.StringOutput `pulumi:"version"`
}

// NewMediaWorkflow registers a new resource with the given unique name, arguments, and options.
func NewMediaWorkflow(ctx *pulumi.Context,
	name string, args *MediaWorkflowArgs, opts ...pulumi.ResourceOption) (*MediaWorkflow, error) {
	if args == nil {
		return nil, errors.New("missing one or more required arguments")
	}

	if args.CompartmentId == nil {
		return nil, errors.New("invalid value for required argument 'CompartmentId'")
	}
	if args.DisplayName == nil {
		return nil, errors.New("invalid value for required argument 'DisplayName'")
	}
	var resource MediaWorkflow
	err := ctx.RegisterResource("oci:MediaServices/mediaWorkflow:MediaWorkflow", name, args, &resource, opts...)
	if err != nil {
		return nil, err
	}
	return &resource, nil
}

// GetMediaWorkflow gets an existing MediaWorkflow resource's state with the given name, ID, and optional
// state properties that are used to uniquely qualify the lookup (nil if not required).
func GetMediaWorkflow(ctx *pulumi.Context,
	name string, id pulumi.IDInput, state *MediaWorkflowState, opts ...pulumi.ResourceOption) (*MediaWorkflow, error) {
	var resource MediaWorkflow
	err := ctx.ReadResource("oci:MediaServices/mediaWorkflow:MediaWorkflow", name, id, state, &resource, opts...)
	if err != nil {
		return nil, err
	}
	return &resource, nil
}

// Input properties used for looking up and filtering MediaWorkflow resources.
type mediaWorkflowState struct {
	// (Updatable) Compartment Identifier.
	CompartmentId *string `pulumi:"compartmentId"`
	// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
	DefinedTags map[string]interface{} `pulumi:"definedTags"`
	// (Updatable) Name for the MediaWorkflow. Does not have to be unique, and it's changeable. Avoid entering confidential information.
	DisplayName *string `pulumi:"displayName"`
	// (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
	FreeformTags map[string]interface{} `pulumi:"freeformTags"`
	// A message describing the current state in more detail. For example, can be used to provide actionable information for a resource in Failed state.
	LifecyleDetails *string `pulumi:"lifecyleDetails"`
	// (Updatable) Configurations to be applied to all the jobs for this workflow. Parameters in these configurations are overridden by parameters in the MediaWorkflowConfigurations of the MediaWorkflowJob and the parameters of the MediaWorkflowJob.
	MediaWorkflowConfigurationIds []string `pulumi:"mediaWorkflowConfigurationIds"`
	// (Updatable) Data specifiying how this task is to be run. The data is a JSON object that must conform to the JSON Schema specified by the parameters of the MediaWorkflowTaskDeclaration this task references. The parameters may contain values or references to other parameters.
	Parameters *string `pulumi:"parameters"`
	// The current state of the MediaWorkflow.
	State *string `pulumi:"state"`
	// Usage of system tag keys. These predefined keys are scoped to namespaces. Example: `{"orcl-cloud.free-tier-retained": "true"}`
	SystemTags map[string]interface{} `pulumi:"systemTags"`
	// (Updatable) The processing to be done in this workflow. Each key of the MediaWorkflowTasks in this array must be unique within the array. The order of tasks given here will be preserved.
	Tasks []MediaWorkflowTask `pulumi:"tasks"`
	// The time when the MediaWorkflow was created. An RFC3339 formatted datetime string.
	TimeCreated *string `pulumi:"timeCreated"`
	// The time when the MediaWorkflow was updated. An RFC3339 formatted datetime string.
	TimeUpdated *string `pulumi:"timeUpdated"`
	// (Updatable) The version of the MediaWorkflowTaskDeclaration.
	Version *string `pulumi:"version"`
}

type MediaWorkflowState struct {
	// (Updatable) Compartment Identifier.
	CompartmentId pulumi.StringPtrInput
	// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
	DefinedTags pulumi.MapInput
	// (Updatable) Name for the MediaWorkflow. Does not have to be unique, and it's changeable. Avoid entering confidential information.
	DisplayName pulumi.StringPtrInput
	// (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
	FreeformTags pulumi.MapInput
	// A message describing the current state in more detail. For example, can be used to provide actionable information for a resource in Failed state.
	LifecyleDetails pulumi.StringPtrInput
	// (Updatable) Configurations to be applied to all the jobs for this workflow. Parameters in these configurations are overridden by parameters in the MediaWorkflowConfigurations of the MediaWorkflowJob and the parameters of the MediaWorkflowJob.
	MediaWorkflowConfigurationIds pulumi.StringArrayInput
	// (Updatable) Data specifiying how this task is to be run. The data is a JSON object that must conform to the JSON Schema specified by the parameters of the MediaWorkflowTaskDeclaration this task references. The parameters may contain values or references to other parameters.
	Parameters pulumi.StringPtrInput
	// The current state of the MediaWorkflow.
	State pulumi.StringPtrInput
	// Usage of system tag keys. These predefined keys are scoped to namespaces. Example: `{"orcl-cloud.free-tier-retained": "true"}`
	SystemTags pulumi.MapInput
	// (Updatable) The processing to be done in this workflow. Each key of the MediaWorkflowTasks in this array must be unique within the array. The order of tasks given here will be preserved.
	Tasks MediaWorkflowTaskArrayInput
	// The time when the MediaWorkflow was created. An RFC3339 formatted datetime string.
	TimeCreated pulumi.StringPtrInput
	// The time when the MediaWorkflow was updated. An RFC3339 formatted datetime string.
	TimeUpdated pulumi.StringPtrInput
	// (Updatable) The version of the MediaWorkflowTaskDeclaration.
	Version pulumi.StringPtrInput
}

func (MediaWorkflowState) ElementType() reflect.Type {
	return reflect.TypeOf((*mediaWorkflowState)(nil)).Elem()
}

type mediaWorkflowArgs struct {
	// (Updatable) Compartment Identifier.
	CompartmentId string `pulumi:"compartmentId"`
	// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
	DefinedTags map[string]interface{} `pulumi:"definedTags"`
	// (Updatable) Name for the MediaWorkflow. Does not have to be unique, and it's changeable. Avoid entering confidential information.
	DisplayName string `pulumi:"displayName"`
	// (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
	FreeformTags map[string]interface{} `pulumi:"freeformTags"`
	// (Updatable) Configurations to be applied to all the jobs for this workflow. Parameters in these configurations are overridden by parameters in the MediaWorkflowConfigurations of the MediaWorkflowJob and the parameters of the MediaWorkflowJob.
	MediaWorkflowConfigurationIds []string `pulumi:"mediaWorkflowConfigurationIds"`
	// (Updatable) Data specifiying how this task is to be run. The data is a JSON object that must conform to the JSON Schema specified by the parameters of the MediaWorkflowTaskDeclaration this task references. The parameters may contain values or references to other parameters.
	Parameters *string `pulumi:"parameters"`
	// (Updatable) The processing to be done in this workflow. Each key of the MediaWorkflowTasks in this array must be unique within the array. The order of tasks given here will be preserved.
	Tasks []MediaWorkflowTask `pulumi:"tasks"`
}

// The set of arguments for constructing a MediaWorkflow resource.
type MediaWorkflowArgs struct {
	// (Updatable) Compartment Identifier.
	CompartmentId pulumi.StringInput
	// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
	DefinedTags pulumi.MapInput
	// (Updatable) Name for the MediaWorkflow. Does not have to be unique, and it's changeable. Avoid entering confidential information.
	DisplayName pulumi.StringInput
	// (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
	FreeformTags pulumi.MapInput
	// (Updatable) Configurations to be applied to all the jobs for this workflow. Parameters in these configurations are overridden by parameters in the MediaWorkflowConfigurations of the MediaWorkflowJob and the parameters of the MediaWorkflowJob.
	MediaWorkflowConfigurationIds pulumi.StringArrayInput
	// (Updatable) Data specifiying how this task is to be run. The data is a JSON object that must conform to the JSON Schema specified by the parameters of the MediaWorkflowTaskDeclaration this task references. The parameters may contain values or references to other parameters.
	Parameters pulumi.StringPtrInput
	// (Updatable) The processing to be done in this workflow. Each key of the MediaWorkflowTasks in this array must be unique within the array. The order of tasks given here will be preserved.
	Tasks MediaWorkflowTaskArrayInput
}

func (MediaWorkflowArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*mediaWorkflowArgs)(nil)).Elem()
}

type MediaWorkflowInput interface {
	pulumi.Input

	ToMediaWorkflowOutput() MediaWorkflowOutput
	ToMediaWorkflowOutputWithContext(ctx context.Context) MediaWorkflowOutput
}

func (*MediaWorkflow) ElementType() reflect.Type {
	return reflect.TypeOf((**MediaWorkflow)(nil)).Elem()
}

func (i *MediaWorkflow) ToMediaWorkflowOutput() MediaWorkflowOutput {
	return i.ToMediaWorkflowOutputWithContext(context.Background())
}

func (i *MediaWorkflow) ToMediaWorkflowOutputWithContext(ctx context.Context) MediaWorkflowOutput {
	return pulumi.ToOutputWithContext(ctx, i).(MediaWorkflowOutput)
}

// MediaWorkflowArrayInput is an input type that accepts MediaWorkflowArray and MediaWorkflowArrayOutput values.
// You can construct a concrete instance of `MediaWorkflowArrayInput` via:
//
//	MediaWorkflowArray{ MediaWorkflowArgs{...} }
type MediaWorkflowArrayInput interface {
	pulumi.Input

	ToMediaWorkflowArrayOutput() MediaWorkflowArrayOutput
	ToMediaWorkflowArrayOutputWithContext(context.Context) MediaWorkflowArrayOutput
}

type MediaWorkflowArray []MediaWorkflowInput

func (MediaWorkflowArray) ElementType() reflect.Type {
	return reflect.TypeOf((*[]*MediaWorkflow)(nil)).Elem()
}

func (i MediaWorkflowArray) ToMediaWorkflowArrayOutput() MediaWorkflowArrayOutput {
	return i.ToMediaWorkflowArrayOutputWithContext(context.Background())
}

func (i MediaWorkflowArray) ToMediaWorkflowArrayOutputWithContext(ctx context.Context) MediaWorkflowArrayOutput {
	return pulumi.ToOutputWithContext(ctx, i).(MediaWorkflowArrayOutput)
}

// MediaWorkflowMapInput is an input type that accepts MediaWorkflowMap and MediaWorkflowMapOutput values.
// You can construct a concrete instance of `MediaWorkflowMapInput` via:
//
//	MediaWorkflowMap{ "key": MediaWorkflowArgs{...} }
type MediaWorkflowMapInput interface {
	pulumi.Input

	ToMediaWorkflowMapOutput() MediaWorkflowMapOutput
	ToMediaWorkflowMapOutputWithContext(context.Context) MediaWorkflowMapOutput
}

type MediaWorkflowMap map[string]MediaWorkflowInput

func (MediaWorkflowMap) ElementType() reflect.Type {
	return reflect.TypeOf((*map[string]*MediaWorkflow)(nil)).Elem()
}

func (i MediaWorkflowMap) ToMediaWorkflowMapOutput() MediaWorkflowMapOutput {
	return i.ToMediaWorkflowMapOutputWithContext(context.Background())
}

func (i MediaWorkflowMap) ToMediaWorkflowMapOutputWithContext(ctx context.Context) MediaWorkflowMapOutput {
	return pulumi.ToOutputWithContext(ctx, i).(MediaWorkflowMapOutput)
}

type MediaWorkflowOutput struct{ *pulumi.OutputState }

func (MediaWorkflowOutput) ElementType() reflect.Type {
	return reflect.TypeOf((**MediaWorkflow)(nil)).Elem()
}

func (o MediaWorkflowOutput) ToMediaWorkflowOutput() MediaWorkflowOutput {
	return o
}

func (o MediaWorkflowOutput) ToMediaWorkflowOutputWithContext(ctx context.Context) MediaWorkflowOutput {
	return o
}

// (Updatable) Compartment Identifier.
func (o MediaWorkflowOutput) CompartmentId() pulumi.StringOutput {
	return o.ApplyT(func(v *MediaWorkflow) pulumi.StringOutput { return v.CompartmentId }).(pulumi.StringOutput)
}

// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
func (o MediaWorkflowOutput) DefinedTags() pulumi.MapOutput {
	return o.ApplyT(func(v *MediaWorkflow) pulumi.MapOutput { return v.DefinedTags }).(pulumi.MapOutput)
}

// (Updatable) Name for the MediaWorkflow. Does not have to be unique, and it's changeable. Avoid entering confidential information.
func (o MediaWorkflowOutput) DisplayName() pulumi.StringOutput {
	return o.ApplyT(func(v *MediaWorkflow) pulumi.StringOutput { return v.DisplayName }).(pulumi.StringOutput)
}

// (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
func (o MediaWorkflowOutput) FreeformTags() pulumi.MapOutput {
	return o.ApplyT(func(v *MediaWorkflow) pulumi.MapOutput { return v.FreeformTags }).(pulumi.MapOutput)
}

// A message describing the current state in more detail. For example, can be used to provide actionable information for a resource in Failed state.
func (o MediaWorkflowOutput) LifecyleDetails() pulumi.StringOutput {
	return o.ApplyT(func(v *MediaWorkflow) pulumi.StringOutput { return v.LifecyleDetails }).(pulumi.StringOutput)
}

// (Updatable) Configurations to be applied to all the jobs for this workflow. Parameters in these configurations are overridden by parameters in the MediaWorkflowConfigurations of the MediaWorkflowJob and the parameters of the MediaWorkflowJob.
func (o MediaWorkflowOutput) MediaWorkflowConfigurationIds() pulumi.StringArrayOutput {
	return o.ApplyT(func(v *MediaWorkflow) pulumi.StringArrayOutput { return v.MediaWorkflowConfigurationIds }).(pulumi.StringArrayOutput)
}

// (Updatable) Data specifiying how this task is to be run. The data is a JSON object that must conform to the JSON Schema specified by the parameters of the MediaWorkflowTaskDeclaration this task references. The parameters may contain values or references to other parameters.
func (o MediaWorkflowOutput) Parameters() pulumi.StringOutput {
	return o.ApplyT(func(v *MediaWorkflow) pulumi.StringOutput { return v.Parameters }).(pulumi.StringOutput)
}

// The current state of the MediaWorkflow.
func (o MediaWorkflowOutput) State() pulumi.StringOutput {
	return o.ApplyT(func(v *MediaWorkflow) pulumi.StringOutput { return v.State }).(pulumi.StringOutput)
}

// Usage of system tag keys. These predefined keys are scoped to namespaces. Example: `{"orcl-cloud.free-tier-retained": "true"}`
func (o MediaWorkflowOutput) SystemTags() pulumi.MapOutput {
	return o.ApplyT(func(v *MediaWorkflow) pulumi.MapOutput { return v.SystemTags }).(pulumi.MapOutput)
}

// (Updatable) The processing to be done in this workflow. Each key of the MediaWorkflowTasks in this array must be unique within the array. The order of tasks given here will be preserved.
func (o MediaWorkflowOutput) Tasks() MediaWorkflowTaskArrayOutput {
	return o.ApplyT(func(v *MediaWorkflow) MediaWorkflowTaskArrayOutput { return v.Tasks }).(MediaWorkflowTaskArrayOutput)
}

// The time when the MediaWorkflow was created. An RFC3339 formatted datetime string.
func (o MediaWorkflowOutput) TimeCreated() pulumi.StringOutput {
	return o.ApplyT(func(v *MediaWorkflow) pulumi.StringOutput { return v.TimeCreated }).(pulumi.StringOutput)
}

// The time when the MediaWorkflow was updated. An RFC3339 formatted datetime string.
func (o MediaWorkflowOutput) TimeUpdated() pulumi.StringOutput {
	return o.ApplyT(func(v *MediaWorkflow) pulumi.StringOutput { return v.TimeUpdated }).(pulumi.StringOutput)
}

// (Updatable) The version of the MediaWorkflowTaskDeclaration.
func (o MediaWorkflowOutput) Version() pulumi.StringOutput {
	return o.ApplyT(func(v *MediaWorkflow) pulumi.StringOutput { return v.Version }).(pulumi.StringOutput)
}

type MediaWorkflowArrayOutput struct{ *pulumi.OutputState }

func (MediaWorkflowArrayOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*[]*MediaWorkflow)(nil)).Elem()
}

func (o MediaWorkflowArrayOutput) ToMediaWorkflowArrayOutput() MediaWorkflowArrayOutput {
	return o
}

func (o MediaWorkflowArrayOutput) ToMediaWorkflowArrayOutputWithContext(ctx context.Context) MediaWorkflowArrayOutput {
	return o
}

func (o MediaWorkflowArrayOutput) Index(i pulumi.IntInput) MediaWorkflowOutput {
	return pulumi.All(o, i).ApplyT(func(vs []interface{}) *MediaWorkflow {
		return vs[0].([]*MediaWorkflow)[vs[1].(int)]
	}).(MediaWorkflowOutput)
}

type MediaWorkflowMapOutput struct{ *pulumi.OutputState }

func (MediaWorkflowMapOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*map[string]*MediaWorkflow)(nil)).Elem()
}

func (o MediaWorkflowMapOutput) ToMediaWorkflowMapOutput() MediaWorkflowMapOutput {
	return o
}

func (o MediaWorkflowMapOutput) ToMediaWorkflowMapOutputWithContext(ctx context.Context) MediaWorkflowMapOutput {
	return o
}

func (o MediaWorkflowMapOutput) MapIndex(k pulumi.StringInput) MediaWorkflowOutput {
	return pulumi.All(o, k).ApplyT(func(vs []interface{}) *MediaWorkflow {
		return vs[0].(map[string]*MediaWorkflow)[vs[1].(string)]
	}).(MediaWorkflowOutput)
}

func init() {
	pulumi.RegisterInputType(reflect.TypeOf((*MediaWorkflowInput)(nil)).Elem(), &MediaWorkflow{})
	pulumi.RegisterInputType(reflect.TypeOf((*MediaWorkflowArrayInput)(nil)).Elem(), MediaWorkflowArray{})
	pulumi.RegisterInputType(reflect.TypeOf((*MediaWorkflowMapInput)(nil)).Elem(), MediaWorkflowMap{})
	pulumi.RegisterOutputType(MediaWorkflowOutput{})
	pulumi.RegisterOutputType(MediaWorkflowArrayOutput{})
	pulumi.RegisterOutputType(MediaWorkflowMapOutput{})
}