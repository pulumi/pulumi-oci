// Code generated by pulumi-language-go DO NOT EDIT.
// *** WARNING: Do not edit by hand unless you're certain you know what you are doing! ***

package dataintegration

import (
	"context"
	"reflect"

	"errors"
	"github.com/pulumi/pulumi-oci/sdk/v3/go/oci/internal"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This resource provides the Workspace Task resource in Oracle Cloud Infrastructure Data Integration service.
//
// Creates a new task ready for performing data integrations. There are specialized types of tasks that include data loader and integration tasks.
//
// ## Import
//
// WorkspaceTasks can be imported using the `id`, e.g.
//
// ```sh
// $ pulumi import oci:DataIntegration/workspaceTask:WorkspaceTask test_workspace_task "workspaces/{workspaceId}/tasks/{taskKey}"
// ```
type WorkspaceTask struct {
	pulumi.CustomResourceState

	// (Updatable) The REST invocation pattern to use. ASYNC_OCI_WORKREQUEST is being deprecated as well as cancelEndpoint/MethodType.
	ApiCallMode pulumi.StringOutput `pulumi:"apiCallMode"`
	// (Updatable) Authentication configuration for Generic REST invocation.
	AuthConfig WorkspaceTaskAuthConfigOutput `pulumi:"authConfig"`
	// (Updatable) The REST API configuration for cancelling the task.
	CancelRestCallConfig WorkspaceTaskCancelRestCallConfigOutput `pulumi:"cancelRestCallConfig"`
	// (Updatable) The type to create a config provider.
	ConfigProviderDelegate WorkspaceTaskConfigProviderDelegateOutput `pulumi:"configProviderDelegate"`
	// (Updatable) Detailed description for the object.
	Description pulumi.StringOutput `pulumi:"description"`
	// (Updatable) The REST API configuration for execution.
	ExecuteRestCallConfig WorkspaceTaskExecuteRestCallConfigOutput `pulumi:"executeRestCallConfig"`
	// (Updatable) Value can only contain upper case letters, underscore, and numbers. It should begin with upper case letter or underscore. The value can be modified.
	Identifier pulumi.StringOutput `pulumi:"identifier"`
	// (Updatable) An array of input ports.
	InputPorts WorkspaceTaskInputPortArrayOutput `pulumi:"inputPorts"`
	// (Updatable) Defines whether Data Loader task is used for single load or multiple
	IsSingleLoad pulumi.BoolOutput `pulumi:"isSingleLoad"`
	// (Updatable) Generated key that can be used in API calls to identify task. On scenarios where reference to the task is needed, a value can be passed in create.
	Key pulumi.StringOutput `pulumi:"key"`
	// A key map. If provided, key is replaced with generated key. This structure provides mapping between user provided key and generated key.
	KeyMap pulumi.StringMapOutput `pulumi:"keyMap"`
	// A summary type containing information about the object including its key, name and when/who created/updated it.
	Metadatas WorkspaceTaskMetadataArrayOutput `pulumi:"metadatas"`
	// (Updatable) The type of the task.
	ModelType pulumi.StringOutput `pulumi:"modelType"`
	// (Updatable) The object's model version.
	ModelVersion pulumi.StringOutput `pulumi:"modelVersion"`
	// (Updatable) Free form text without any restriction on permitted characters. Name can have letters, numbers, and special characters. The value is editable and is restricted to 1000 characters.
	Name pulumi.StringOutput `pulumi:"name"`
	// (Updatable) The status of an object that can be set to value 1 for shallow references across objects, other values reserved.
	ObjectStatus pulumi.IntOutput `pulumi:"objectStatus"`
	// This is used by the service for optimistic locking of the object, to prevent multiple users from simultaneously updating the object.
	ObjectVersion pulumi.IntOutput `pulumi:"objectVersion"`
	// (Updatable) Configuration values can be string, objects, or parameters.
	OpConfigValues WorkspaceTaskOpConfigValuesOutput `pulumi:"opConfigValues"`
	// (Updatable) Describes the shape of the execution result
	Operation pulumi.StringOutput `pulumi:"operation"`
	// (Updatable) An array of output ports.
	OutputPorts WorkspaceTaskOutputPortArrayOutput `pulumi:"outputPorts"`
	// (Updatable) Defines the number of entities being loaded in parallel at a time for a Data Loader task
	ParallelLoadLimit pulumi.IntOutput `pulumi:"parallelLoadLimit"`
	// (Updatable) An array of parameters.
	Parameters WorkspaceTaskParameterArrayOutput `pulumi:"parameters"`
	// (Updatable) A reference to the object's parent.
	ParentRef WorkspaceTaskParentRefOutput `pulumi:"parentRef"`
	// (Updatable) The REST API configuration for polling.
	PollRestCallConfig WorkspaceTaskPollRestCallConfigOutput `pulumi:"pollRestCallConfig"`
	// (Updatable) Information about the object and its parent.
	RegistryMetadata WorkspaceTaskRegistryMetadataOutput `pulumi:"registryMetadata"`
	// (Updatable) List of typed expressions.
	TypedExpressions WorkspaceTaskTypedExpressionArrayOutput `pulumi:"typedExpressions"`
	// The workspace ID.
	//
	// ** IMPORTANT **
	// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
	WorkspaceId pulumi.StringOutput `pulumi:"workspaceId"`
}

// NewWorkspaceTask registers a new resource with the given unique name, arguments, and options.
func NewWorkspaceTask(ctx *pulumi.Context,
	name string, args *WorkspaceTaskArgs, opts ...pulumi.ResourceOption) (*WorkspaceTask, error) {
	if args == nil {
		return nil, errors.New("missing one or more required arguments")
	}

	if args.Identifier == nil {
		return nil, errors.New("invalid value for required argument 'Identifier'")
	}
	if args.ModelType == nil {
		return nil, errors.New("invalid value for required argument 'ModelType'")
	}
	if args.RegistryMetadata == nil {
		return nil, errors.New("invalid value for required argument 'RegistryMetadata'")
	}
	if args.WorkspaceId == nil {
		return nil, errors.New("invalid value for required argument 'WorkspaceId'")
	}
	opts = internal.PkgResourceDefaultOpts(opts)
	var resource WorkspaceTask
	err := ctx.RegisterResource("oci:DataIntegration/workspaceTask:WorkspaceTask", name, args, &resource, opts...)
	if err != nil {
		return nil, err
	}
	return &resource, nil
}

// GetWorkspaceTask gets an existing WorkspaceTask resource's state with the given name, ID, and optional
// state properties that are used to uniquely qualify the lookup (nil if not required).
func GetWorkspaceTask(ctx *pulumi.Context,
	name string, id pulumi.IDInput, state *WorkspaceTaskState, opts ...pulumi.ResourceOption) (*WorkspaceTask, error) {
	var resource WorkspaceTask
	err := ctx.ReadResource("oci:DataIntegration/workspaceTask:WorkspaceTask", name, id, state, &resource, opts...)
	if err != nil {
		return nil, err
	}
	return &resource, nil
}

// Input properties used for looking up and filtering WorkspaceTask resources.
type workspaceTaskState struct {
	// (Updatable) The REST invocation pattern to use. ASYNC_OCI_WORKREQUEST is being deprecated as well as cancelEndpoint/MethodType.
	ApiCallMode *string `pulumi:"apiCallMode"`
	// (Updatable) Authentication configuration for Generic REST invocation.
	AuthConfig *WorkspaceTaskAuthConfig `pulumi:"authConfig"`
	// (Updatable) The REST API configuration for cancelling the task.
	CancelRestCallConfig *WorkspaceTaskCancelRestCallConfig `pulumi:"cancelRestCallConfig"`
	// (Updatable) The type to create a config provider.
	ConfigProviderDelegate *WorkspaceTaskConfigProviderDelegate `pulumi:"configProviderDelegate"`
	// (Updatable) Detailed description for the object.
	Description *string `pulumi:"description"`
	// (Updatable) The REST API configuration for execution.
	ExecuteRestCallConfig *WorkspaceTaskExecuteRestCallConfig `pulumi:"executeRestCallConfig"`
	// (Updatable) Value can only contain upper case letters, underscore, and numbers. It should begin with upper case letter or underscore. The value can be modified.
	Identifier *string `pulumi:"identifier"`
	// (Updatable) An array of input ports.
	InputPorts []WorkspaceTaskInputPort `pulumi:"inputPorts"`
	// (Updatable) Defines whether Data Loader task is used for single load or multiple
	IsSingleLoad *bool `pulumi:"isSingleLoad"`
	// (Updatable) Generated key that can be used in API calls to identify task. On scenarios where reference to the task is needed, a value can be passed in create.
	Key *string `pulumi:"key"`
	// A key map. If provided, key is replaced with generated key. This structure provides mapping between user provided key and generated key.
	KeyMap map[string]string `pulumi:"keyMap"`
	// A summary type containing information about the object including its key, name and when/who created/updated it.
	Metadatas []WorkspaceTaskMetadata `pulumi:"metadatas"`
	// (Updatable) The type of the task.
	ModelType *string `pulumi:"modelType"`
	// (Updatable) The object's model version.
	ModelVersion *string `pulumi:"modelVersion"`
	// (Updatable) Free form text without any restriction on permitted characters. Name can have letters, numbers, and special characters. The value is editable and is restricted to 1000 characters.
	Name *string `pulumi:"name"`
	// (Updatable) The status of an object that can be set to value 1 for shallow references across objects, other values reserved.
	ObjectStatus *int `pulumi:"objectStatus"`
	// This is used by the service for optimistic locking of the object, to prevent multiple users from simultaneously updating the object.
	ObjectVersion *int `pulumi:"objectVersion"`
	// (Updatable) Configuration values can be string, objects, or parameters.
	OpConfigValues *WorkspaceTaskOpConfigValues `pulumi:"opConfigValues"`
	// (Updatable) Describes the shape of the execution result
	Operation *string `pulumi:"operation"`
	// (Updatable) An array of output ports.
	OutputPorts []WorkspaceTaskOutputPort `pulumi:"outputPorts"`
	// (Updatable) Defines the number of entities being loaded in parallel at a time for a Data Loader task
	ParallelLoadLimit *int `pulumi:"parallelLoadLimit"`
	// (Updatable) An array of parameters.
	Parameters []WorkspaceTaskParameter `pulumi:"parameters"`
	// (Updatable) A reference to the object's parent.
	ParentRef *WorkspaceTaskParentRef `pulumi:"parentRef"`
	// (Updatable) The REST API configuration for polling.
	PollRestCallConfig *WorkspaceTaskPollRestCallConfig `pulumi:"pollRestCallConfig"`
	// (Updatable) Information about the object and its parent.
	RegistryMetadata *WorkspaceTaskRegistryMetadata `pulumi:"registryMetadata"`
	// (Updatable) List of typed expressions.
	TypedExpressions []WorkspaceTaskTypedExpression `pulumi:"typedExpressions"`
	// The workspace ID.
	//
	// ** IMPORTANT **
	// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
	WorkspaceId *string `pulumi:"workspaceId"`
}

type WorkspaceTaskState struct {
	// (Updatable) The REST invocation pattern to use. ASYNC_OCI_WORKREQUEST is being deprecated as well as cancelEndpoint/MethodType.
	ApiCallMode pulumi.StringPtrInput
	// (Updatable) Authentication configuration for Generic REST invocation.
	AuthConfig WorkspaceTaskAuthConfigPtrInput
	// (Updatable) The REST API configuration for cancelling the task.
	CancelRestCallConfig WorkspaceTaskCancelRestCallConfigPtrInput
	// (Updatable) The type to create a config provider.
	ConfigProviderDelegate WorkspaceTaskConfigProviderDelegatePtrInput
	// (Updatable) Detailed description for the object.
	Description pulumi.StringPtrInput
	// (Updatable) The REST API configuration for execution.
	ExecuteRestCallConfig WorkspaceTaskExecuteRestCallConfigPtrInput
	// (Updatable) Value can only contain upper case letters, underscore, and numbers. It should begin with upper case letter or underscore. The value can be modified.
	Identifier pulumi.StringPtrInput
	// (Updatable) An array of input ports.
	InputPorts WorkspaceTaskInputPortArrayInput
	// (Updatable) Defines whether Data Loader task is used for single load or multiple
	IsSingleLoad pulumi.BoolPtrInput
	// (Updatable) Generated key that can be used in API calls to identify task. On scenarios where reference to the task is needed, a value can be passed in create.
	Key pulumi.StringPtrInput
	// A key map. If provided, key is replaced with generated key. This structure provides mapping between user provided key and generated key.
	KeyMap pulumi.StringMapInput
	// A summary type containing information about the object including its key, name and when/who created/updated it.
	Metadatas WorkspaceTaskMetadataArrayInput
	// (Updatable) The type of the task.
	ModelType pulumi.StringPtrInput
	// (Updatable) The object's model version.
	ModelVersion pulumi.StringPtrInput
	// (Updatable) Free form text without any restriction on permitted characters. Name can have letters, numbers, and special characters. The value is editable and is restricted to 1000 characters.
	Name pulumi.StringPtrInput
	// (Updatable) The status of an object that can be set to value 1 for shallow references across objects, other values reserved.
	ObjectStatus pulumi.IntPtrInput
	// This is used by the service for optimistic locking of the object, to prevent multiple users from simultaneously updating the object.
	ObjectVersion pulumi.IntPtrInput
	// (Updatable) Configuration values can be string, objects, or parameters.
	OpConfigValues WorkspaceTaskOpConfigValuesPtrInput
	// (Updatable) Describes the shape of the execution result
	Operation pulumi.StringPtrInput
	// (Updatable) An array of output ports.
	OutputPorts WorkspaceTaskOutputPortArrayInput
	// (Updatable) Defines the number of entities being loaded in parallel at a time for a Data Loader task
	ParallelLoadLimit pulumi.IntPtrInput
	// (Updatable) An array of parameters.
	Parameters WorkspaceTaskParameterArrayInput
	// (Updatable) A reference to the object's parent.
	ParentRef WorkspaceTaskParentRefPtrInput
	// (Updatable) The REST API configuration for polling.
	PollRestCallConfig WorkspaceTaskPollRestCallConfigPtrInput
	// (Updatable) Information about the object and its parent.
	RegistryMetadata WorkspaceTaskRegistryMetadataPtrInput
	// (Updatable) List of typed expressions.
	TypedExpressions WorkspaceTaskTypedExpressionArrayInput
	// The workspace ID.
	//
	// ** IMPORTANT **
	// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
	WorkspaceId pulumi.StringPtrInput
}

func (WorkspaceTaskState) ElementType() reflect.Type {
	return reflect.TypeOf((*workspaceTaskState)(nil)).Elem()
}

type workspaceTaskArgs struct {
	// (Updatable) The REST invocation pattern to use. ASYNC_OCI_WORKREQUEST is being deprecated as well as cancelEndpoint/MethodType.
	ApiCallMode *string `pulumi:"apiCallMode"`
	// (Updatable) Authentication configuration for Generic REST invocation.
	AuthConfig *WorkspaceTaskAuthConfig `pulumi:"authConfig"`
	// (Updatable) The REST API configuration for cancelling the task.
	CancelRestCallConfig *WorkspaceTaskCancelRestCallConfig `pulumi:"cancelRestCallConfig"`
	// (Updatable) The type to create a config provider.
	ConfigProviderDelegate *WorkspaceTaskConfigProviderDelegate `pulumi:"configProviderDelegate"`
	// (Updatable) Detailed description for the object.
	Description *string `pulumi:"description"`
	// (Updatable) The REST API configuration for execution.
	ExecuteRestCallConfig *WorkspaceTaskExecuteRestCallConfig `pulumi:"executeRestCallConfig"`
	// (Updatable) Value can only contain upper case letters, underscore, and numbers. It should begin with upper case letter or underscore. The value can be modified.
	Identifier string `pulumi:"identifier"`
	// (Updatable) An array of input ports.
	InputPorts []WorkspaceTaskInputPort `pulumi:"inputPorts"`
	// (Updatable) Defines whether Data Loader task is used for single load or multiple
	IsSingleLoad *bool `pulumi:"isSingleLoad"`
	// (Updatable) Generated key that can be used in API calls to identify task. On scenarios where reference to the task is needed, a value can be passed in create.
	Key *string `pulumi:"key"`
	// (Updatable) The type of the task.
	ModelType string `pulumi:"modelType"`
	// (Updatable) The object's model version.
	ModelVersion *string `pulumi:"modelVersion"`
	// (Updatable) Free form text without any restriction on permitted characters. Name can have letters, numbers, and special characters. The value is editable and is restricted to 1000 characters.
	Name *string `pulumi:"name"`
	// (Updatable) The status of an object that can be set to value 1 for shallow references across objects, other values reserved.
	ObjectStatus *int `pulumi:"objectStatus"`
	// (Updatable) Configuration values can be string, objects, or parameters.
	OpConfigValues *WorkspaceTaskOpConfigValues `pulumi:"opConfigValues"`
	// (Updatable) Describes the shape of the execution result
	Operation *string `pulumi:"operation"`
	// (Updatable) An array of output ports.
	OutputPorts []WorkspaceTaskOutputPort `pulumi:"outputPorts"`
	// (Updatable) Defines the number of entities being loaded in parallel at a time for a Data Loader task
	ParallelLoadLimit *int `pulumi:"parallelLoadLimit"`
	// (Updatable) An array of parameters.
	Parameters []WorkspaceTaskParameter `pulumi:"parameters"`
	// (Updatable) A reference to the object's parent.
	ParentRef *WorkspaceTaskParentRef `pulumi:"parentRef"`
	// (Updatable) The REST API configuration for polling.
	PollRestCallConfig *WorkspaceTaskPollRestCallConfig `pulumi:"pollRestCallConfig"`
	// (Updatable) Information about the object and its parent.
	RegistryMetadata WorkspaceTaskRegistryMetadata `pulumi:"registryMetadata"`
	// (Updatable) List of typed expressions.
	TypedExpressions []WorkspaceTaskTypedExpression `pulumi:"typedExpressions"`
	// The workspace ID.
	//
	// ** IMPORTANT **
	// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
	WorkspaceId string `pulumi:"workspaceId"`
}

// The set of arguments for constructing a WorkspaceTask resource.
type WorkspaceTaskArgs struct {
	// (Updatable) The REST invocation pattern to use. ASYNC_OCI_WORKREQUEST is being deprecated as well as cancelEndpoint/MethodType.
	ApiCallMode pulumi.StringPtrInput
	// (Updatable) Authentication configuration for Generic REST invocation.
	AuthConfig WorkspaceTaskAuthConfigPtrInput
	// (Updatable) The REST API configuration for cancelling the task.
	CancelRestCallConfig WorkspaceTaskCancelRestCallConfigPtrInput
	// (Updatable) The type to create a config provider.
	ConfigProviderDelegate WorkspaceTaskConfigProviderDelegatePtrInput
	// (Updatable) Detailed description for the object.
	Description pulumi.StringPtrInput
	// (Updatable) The REST API configuration for execution.
	ExecuteRestCallConfig WorkspaceTaskExecuteRestCallConfigPtrInput
	// (Updatable) Value can only contain upper case letters, underscore, and numbers. It should begin with upper case letter or underscore. The value can be modified.
	Identifier pulumi.StringInput
	// (Updatable) An array of input ports.
	InputPorts WorkspaceTaskInputPortArrayInput
	// (Updatable) Defines whether Data Loader task is used for single load or multiple
	IsSingleLoad pulumi.BoolPtrInput
	// (Updatable) Generated key that can be used in API calls to identify task. On scenarios where reference to the task is needed, a value can be passed in create.
	Key pulumi.StringPtrInput
	// (Updatable) The type of the task.
	ModelType pulumi.StringInput
	// (Updatable) The object's model version.
	ModelVersion pulumi.StringPtrInput
	// (Updatable) Free form text without any restriction on permitted characters. Name can have letters, numbers, and special characters. The value is editable and is restricted to 1000 characters.
	Name pulumi.StringPtrInput
	// (Updatable) The status of an object that can be set to value 1 for shallow references across objects, other values reserved.
	ObjectStatus pulumi.IntPtrInput
	// (Updatable) Configuration values can be string, objects, or parameters.
	OpConfigValues WorkspaceTaskOpConfigValuesPtrInput
	// (Updatable) Describes the shape of the execution result
	Operation pulumi.StringPtrInput
	// (Updatable) An array of output ports.
	OutputPorts WorkspaceTaskOutputPortArrayInput
	// (Updatable) Defines the number of entities being loaded in parallel at a time for a Data Loader task
	ParallelLoadLimit pulumi.IntPtrInput
	// (Updatable) An array of parameters.
	Parameters WorkspaceTaskParameterArrayInput
	// (Updatable) A reference to the object's parent.
	ParentRef WorkspaceTaskParentRefPtrInput
	// (Updatable) The REST API configuration for polling.
	PollRestCallConfig WorkspaceTaskPollRestCallConfigPtrInput
	// (Updatable) Information about the object and its parent.
	RegistryMetadata WorkspaceTaskRegistryMetadataInput
	// (Updatable) List of typed expressions.
	TypedExpressions WorkspaceTaskTypedExpressionArrayInput
	// The workspace ID.
	//
	// ** IMPORTANT **
	// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
	WorkspaceId pulumi.StringInput
}

func (WorkspaceTaskArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*workspaceTaskArgs)(nil)).Elem()
}

type WorkspaceTaskInput interface {
	pulumi.Input

	ToWorkspaceTaskOutput() WorkspaceTaskOutput
	ToWorkspaceTaskOutputWithContext(ctx context.Context) WorkspaceTaskOutput
}

func (*WorkspaceTask) ElementType() reflect.Type {
	return reflect.TypeOf((**WorkspaceTask)(nil)).Elem()
}

func (i *WorkspaceTask) ToWorkspaceTaskOutput() WorkspaceTaskOutput {
	return i.ToWorkspaceTaskOutputWithContext(context.Background())
}

func (i *WorkspaceTask) ToWorkspaceTaskOutputWithContext(ctx context.Context) WorkspaceTaskOutput {
	return pulumi.ToOutputWithContext(ctx, i).(WorkspaceTaskOutput)
}

// WorkspaceTaskArrayInput is an input type that accepts WorkspaceTaskArray and WorkspaceTaskArrayOutput values.
// You can construct a concrete instance of `WorkspaceTaskArrayInput` via:
//
//	WorkspaceTaskArray{ WorkspaceTaskArgs{...} }
type WorkspaceTaskArrayInput interface {
	pulumi.Input

	ToWorkspaceTaskArrayOutput() WorkspaceTaskArrayOutput
	ToWorkspaceTaskArrayOutputWithContext(context.Context) WorkspaceTaskArrayOutput
}

type WorkspaceTaskArray []WorkspaceTaskInput

func (WorkspaceTaskArray) ElementType() reflect.Type {
	return reflect.TypeOf((*[]*WorkspaceTask)(nil)).Elem()
}

func (i WorkspaceTaskArray) ToWorkspaceTaskArrayOutput() WorkspaceTaskArrayOutput {
	return i.ToWorkspaceTaskArrayOutputWithContext(context.Background())
}

func (i WorkspaceTaskArray) ToWorkspaceTaskArrayOutputWithContext(ctx context.Context) WorkspaceTaskArrayOutput {
	return pulumi.ToOutputWithContext(ctx, i).(WorkspaceTaskArrayOutput)
}

// WorkspaceTaskMapInput is an input type that accepts WorkspaceTaskMap and WorkspaceTaskMapOutput values.
// You can construct a concrete instance of `WorkspaceTaskMapInput` via:
//
//	WorkspaceTaskMap{ "key": WorkspaceTaskArgs{...} }
type WorkspaceTaskMapInput interface {
	pulumi.Input

	ToWorkspaceTaskMapOutput() WorkspaceTaskMapOutput
	ToWorkspaceTaskMapOutputWithContext(context.Context) WorkspaceTaskMapOutput
}

type WorkspaceTaskMap map[string]WorkspaceTaskInput

func (WorkspaceTaskMap) ElementType() reflect.Type {
	return reflect.TypeOf((*map[string]*WorkspaceTask)(nil)).Elem()
}

func (i WorkspaceTaskMap) ToWorkspaceTaskMapOutput() WorkspaceTaskMapOutput {
	return i.ToWorkspaceTaskMapOutputWithContext(context.Background())
}

func (i WorkspaceTaskMap) ToWorkspaceTaskMapOutputWithContext(ctx context.Context) WorkspaceTaskMapOutput {
	return pulumi.ToOutputWithContext(ctx, i).(WorkspaceTaskMapOutput)
}

type WorkspaceTaskOutput struct{ *pulumi.OutputState }

func (WorkspaceTaskOutput) ElementType() reflect.Type {
	return reflect.TypeOf((**WorkspaceTask)(nil)).Elem()
}

func (o WorkspaceTaskOutput) ToWorkspaceTaskOutput() WorkspaceTaskOutput {
	return o
}

func (o WorkspaceTaskOutput) ToWorkspaceTaskOutputWithContext(ctx context.Context) WorkspaceTaskOutput {
	return o
}

// (Updatable) The REST invocation pattern to use. ASYNC_OCI_WORKREQUEST is being deprecated as well as cancelEndpoint/MethodType.
func (o WorkspaceTaskOutput) ApiCallMode() pulumi.StringOutput {
	return o.ApplyT(func(v *WorkspaceTask) pulumi.StringOutput { return v.ApiCallMode }).(pulumi.StringOutput)
}

// (Updatable) Authentication configuration for Generic REST invocation.
func (o WorkspaceTaskOutput) AuthConfig() WorkspaceTaskAuthConfigOutput {
	return o.ApplyT(func(v *WorkspaceTask) WorkspaceTaskAuthConfigOutput { return v.AuthConfig }).(WorkspaceTaskAuthConfigOutput)
}

// (Updatable) The REST API configuration for cancelling the task.
func (o WorkspaceTaskOutput) CancelRestCallConfig() WorkspaceTaskCancelRestCallConfigOutput {
	return o.ApplyT(func(v *WorkspaceTask) WorkspaceTaskCancelRestCallConfigOutput { return v.CancelRestCallConfig }).(WorkspaceTaskCancelRestCallConfigOutput)
}

// (Updatable) The type to create a config provider.
func (o WorkspaceTaskOutput) ConfigProviderDelegate() WorkspaceTaskConfigProviderDelegateOutput {
	return o.ApplyT(func(v *WorkspaceTask) WorkspaceTaskConfigProviderDelegateOutput { return v.ConfigProviderDelegate }).(WorkspaceTaskConfigProviderDelegateOutput)
}

// (Updatable) Detailed description for the object.
func (o WorkspaceTaskOutput) Description() pulumi.StringOutput {
	return o.ApplyT(func(v *WorkspaceTask) pulumi.StringOutput { return v.Description }).(pulumi.StringOutput)
}

// (Updatable) The REST API configuration for execution.
func (o WorkspaceTaskOutput) ExecuteRestCallConfig() WorkspaceTaskExecuteRestCallConfigOutput {
	return o.ApplyT(func(v *WorkspaceTask) WorkspaceTaskExecuteRestCallConfigOutput { return v.ExecuteRestCallConfig }).(WorkspaceTaskExecuteRestCallConfigOutput)
}

// (Updatable) Value can only contain upper case letters, underscore, and numbers. It should begin with upper case letter or underscore. The value can be modified.
func (o WorkspaceTaskOutput) Identifier() pulumi.StringOutput {
	return o.ApplyT(func(v *WorkspaceTask) pulumi.StringOutput { return v.Identifier }).(pulumi.StringOutput)
}

// (Updatable) An array of input ports.
func (o WorkspaceTaskOutput) InputPorts() WorkspaceTaskInputPortArrayOutput {
	return o.ApplyT(func(v *WorkspaceTask) WorkspaceTaskInputPortArrayOutput { return v.InputPorts }).(WorkspaceTaskInputPortArrayOutput)
}

// (Updatable) Defines whether Data Loader task is used for single load or multiple
func (o WorkspaceTaskOutput) IsSingleLoad() pulumi.BoolOutput {
	return o.ApplyT(func(v *WorkspaceTask) pulumi.BoolOutput { return v.IsSingleLoad }).(pulumi.BoolOutput)
}

// (Updatable) Generated key that can be used in API calls to identify task. On scenarios where reference to the task is needed, a value can be passed in create.
func (o WorkspaceTaskOutput) Key() pulumi.StringOutput {
	return o.ApplyT(func(v *WorkspaceTask) pulumi.StringOutput { return v.Key }).(pulumi.StringOutput)
}

// A key map. If provided, key is replaced with generated key. This structure provides mapping between user provided key and generated key.
func (o WorkspaceTaskOutput) KeyMap() pulumi.StringMapOutput {
	return o.ApplyT(func(v *WorkspaceTask) pulumi.StringMapOutput { return v.KeyMap }).(pulumi.StringMapOutput)
}

// A summary type containing information about the object including its key, name and when/who created/updated it.
func (o WorkspaceTaskOutput) Metadatas() WorkspaceTaskMetadataArrayOutput {
	return o.ApplyT(func(v *WorkspaceTask) WorkspaceTaskMetadataArrayOutput { return v.Metadatas }).(WorkspaceTaskMetadataArrayOutput)
}

// (Updatable) The type of the task.
func (o WorkspaceTaskOutput) ModelType() pulumi.StringOutput {
	return o.ApplyT(func(v *WorkspaceTask) pulumi.StringOutput { return v.ModelType }).(pulumi.StringOutput)
}

// (Updatable) The object's model version.
func (o WorkspaceTaskOutput) ModelVersion() pulumi.StringOutput {
	return o.ApplyT(func(v *WorkspaceTask) pulumi.StringOutput { return v.ModelVersion }).(pulumi.StringOutput)
}

// (Updatable) Free form text without any restriction on permitted characters. Name can have letters, numbers, and special characters. The value is editable and is restricted to 1000 characters.
func (o WorkspaceTaskOutput) Name() pulumi.StringOutput {
	return o.ApplyT(func(v *WorkspaceTask) pulumi.StringOutput { return v.Name }).(pulumi.StringOutput)
}

// (Updatable) The status of an object that can be set to value 1 for shallow references across objects, other values reserved.
func (o WorkspaceTaskOutput) ObjectStatus() pulumi.IntOutput {
	return o.ApplyT(func(v *WorkspaceTask) pulumi.IntOutput { return v.ObjectStatus }).(pulumi.IntOutput)
}

// This is used by the service for optimistic locking of the object, to prevent multiple users from simultaneously updating the object.
func (o WorkspaceTaskOutput) ObjectVersion() pulumi.IntOutput {
	return o.ApplyT(func(v *WorkspaceTask) pulumi.IntOutput { return v.ObjectVersion }).(pulumi.IntOutput)
}

// (Updatable) Configuration values can be string, objects, or parameters.
func (o WorkspaceTaskOutput) OpConfigValues() WorkspaceTaskOpConfigValuesOutput {
	return o.ApplyT(func(v *WorkspaceTask) WorkspaceTaskOpConfigValuesOutput { return v.OpConfigValues }).(WorkspaceTaskOpConfigValuesOutput)
}

// (Updatable) Describes the shape of the execution result
func (o WorkspaceTaskOutput) Operation() pulumi.StringOutput {
	return o.ApplyT(func(v *WorkspaceTask) pulumi.StringOutput { return v.Operation }).(pulumi.StringOutput)
}

// (Updatable) An array of output ports.
func (o WorkspaceTaskOutput) OutputPorts() WorkspaceTaskOutputPortArrayOutput {
	return o.ApplyT(func(v *WorkspaceTask) WorkspaceTaskOutputPortArrayOutput { return v.OutputPorts }).(WorkspaceTaskOutputPortArrayOutput)
}

// (Updatable) Defines the number of entities being loaded in parallel at a time for a Data Loader task
func (o WorkspaceTaskOutput) ParallelLoadLimit() pulumi.IntOutput {
	return o.ApplyT(func(v *WorkspaceTask) pulumi.IntOutput { return v.ParallelLoadLimit }).(pulumi.IntOutput)
}

// (Updatable) An array of parameters.
func (o WorkspaceTaskOutput) Parameters() WorkspaceTaskParameterArrayOutput {
	return o.ApplyT(func(v *WorkspaceTask) WorkspaceTaskParameterArrayOutput { return v.Parameters }).(WorkspaceTaskParameterArrayOutput)
}

// (Updatable) A reference to the object's parent.
func (o WorkspaceTaskOutput) ParentRef() WorkspaceTaskParentRefOutput {
	return o.ApplyT(func(v *WorkspaceTask) WorkspaceTaskParentRefOutput { return v.ParentRef }).(WorkspaceTaskParentRefOutput)
}

// (Updatable) The REST API configuration for polling.
func (o WorkspaceTaskOutput) PollRestCallConfig() WorkspaceTaskPollRestCallConfigOutput {
	return o.ApplyT(func(v *WorkspaceTask) WorkspaceTaskPollRestCallConfigOutput { return v.PollRestCallConfig }).(WorkspaceTaskPollRestCallConfigOutput)
}

// (Updatable) Information about the object and its parent.
func (o WorkspaceTaskOutput) RegistryMetadata() WorkspaceTaskRegistryMetadataOutput {
	return o.ApplyT(func(v *WorkspaceTask) WorkspaceTaskRegistryMetadataOutput { return v.RegistryMetadata }).(WorkspaceTaskRegistryMetadataOutput)
}

// (Updatable) List of typed expressions.
func (o WorkspaceTaskOutput) TypedExpressions() WorkspaceTaskTypedExpressionArrayOutput {
	return o.ApplyT(func(v *WorkspaceTask) WorkspaceTaskTypedExpressionArrayOutput { return v.TypedExpressions }).(WorkspaceTaskTypedExpressionArrayOutput)
}

// The workspace ID.
//
// ** IMPORTANT **
// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
func (o WorkspaceTaskOutput) WorkspaceId() pulumi.StringOutput {
	return o.ApplyT(func(v *WorkspaceTask) pulumi.StringOutput { return v.WorkspaceId }).(pulumi.StringOutput)
}

type WorkspaceTaskArrayOutput struct{ *pulumi.OutputState }

func (WorkspaceTaskArrayOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*[]*WorkspaceTask)(nil)).Elem()
}

func (o WorkspaceTaskArrayOutput) ToWorkspaceTaskArrayOutput() WorkspaceTaskArrayOutput {
	return o
}

func (o WorkspaceTaskArrayOutput) ToWorkspaceTaskArrayOutputWithContext(ctx context.Context) WorkspaceTaskArrayOutput {
	return o
}

func (o WorkspaceTaskArrayOutput) Index(i pulumi.IntInput) WorkspaceTaskOutput {
	return pulumi.All(o, i).ApplyT(func(vs []interface{}) *WorkspaceTask {
		return vs[0].([]*WorkspaceTask)[vs[1].(int)]
	}).(WorkspaceTaskOutput)
}

type WorkspaceTaskMapOutput struct{ *pulumi.OutputState }

func (WorkspaceTaskMapOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*map[string]*WorkspaceTask)(nil)).Elem()
}

func (o WorkspaceTaskMapOutput) ToWorkspaceTaskMapOutput() WorkspaceTaskMapOutput {
	return o
}

func (o WorkspaceTaskMapOutput) ToWorkspaceTaskMapOutputWithContext(ctx context.Context) WorkspaceTaskMapOutput {
	return o
}

func (o WorkspaceTaskMapOutput) MapIndex(k pulumi.StringInput) WorkspaceTaskOutput {
	return pulumi.All(o, k).ApplyT(func(vs []interface{}) *WorkspaceTask {
		return vs[0].(map[string]*WorkspaceTask)[vs[1].(string)]
	}).(WorkspaceTaskOutput)
}

func init() {
	pulumi.RegisterInputType(reflect.TypeOf((*WorkspaceTaskInput)(nil)).Elem(), &WorkspaceTask{})
	pulumi.RegisterInputType(reflect.TypeOf((*WorkspaceTaskArrayInput)(nil)).Elem(), WorkspaceTaskArray{})
	pulumi.RegisterInputType(reflect.TypeOf((*WorkspaceTaskMapInput)(nil)).Elem(), WorkspaceTaskMap{})
	pulumi.RegisterOutputType(WorkspaceTaskOutput{})
	pulumi.RegisterOutputType(WorkspaceTaskArrayOutput{})
	pulumi.RegisterOutputType(WorkspaceTaskMapOutput{})
}
