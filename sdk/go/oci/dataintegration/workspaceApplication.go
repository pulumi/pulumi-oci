// Code generated by the Pulumi Terraform Bridge (tfgen) Tool DO NOT EDIT.
// *** WARNING: Do not edit by hand unless you're certain you know what you are doing! ***

package dataintegration

import (
	"context"
	"reflect"

	"errors"
	"github.com/pulumi/pulumi-oci/sdk/go/oci/internal"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumix"
)

// This resource provides the Workspace Application resource in Oracle Cloud Infrastructure Data Integration service.
//
// Creates an application.
//
// ## Example Usage
//
// ```go
// package main
//
// import (
//
//	"github.com/pulumi/pulumi-oci/sdk/go/oci/DataIntegration"
//	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
//
// )
//
//	func main() {
//		pulumi.Run(func(ctx *pulumi.Context) error {
//			_, err := DataIntegration.NewWorkspaceApplication(ctx, "testWorkspaceApplication", &DataIntegration.WorkspaceApplicationArgs{
//				Identifier:  pulumi.Any(_var.Workspace_application_identifier),
//				WorkspaceId: pulumi.Any(oci_dataintegration_workspace.Test_workspace.Id),
//				ModelType:   pulumi.Any(_var.Workspace_application_model_type),
//				DefinedTags: pulumi.AnyMap{
//					"foo-namespace.bar-key": pulumi.Any("value"),
//				},
//				Description: pulumi.Any(_var.Workspace_application_description),
//				DisplayName: pulumi.Any(_var.Workspace_application_display_name),
//				FreeformTags: pulumi.AnyMap{
//					"bar-key": pulumi.Any("value"),
//				},
//				Key:          pulumi.Any(_var.Workspace_application_key),
//				ModelVersion: pulumi.Any(_var.Workspace_application_model_version),
//				ObjectStatus: pulumi.Any(_var.Workspace_application_object_status),
//				RegistryMetadata: &dataintegration.WorkspaceApplicationRegistryMetadataArgs{
//					AggregatorKey:   pulumi.Any(_var.Workspace_application_registry_metadata_aggregator_key),
//					IsFavorite:      pulumi.Any(_var.Workspace_application_registry_metadata_is_favorite),
//					Key:             pulumi.Any(_var.Workspace_application_registry_metadata_key),
//					Labels:          pulumi.Any(_var.Workspace_application_registry_metadata_labels),
//					RegistryVersion: pulumi.Any(_var.Workspace_application_registry_metadata_registry_version),
//				},
//				SourceApplicationInfo: &dataintegration.WorkspaceApplicationSourceApplicationInfoArgs{
//					ApplicationKey: pulumi.Any(_var.Workspace_application_source_application_info_application_key),
//					CopyType:       pulumi.Any(_var.Workspace_application_source_application_info_copy_type),
//					WorkspaceId:    pulumi.Any(oci_dataintegration_workspace.Test_workspace.Id),
//				},
//				State: pulumi.Any(_var.Workspace_application_state),
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
// WorkspaceApplications can be imported using the `id`, e.g.
//
// ```sh
//
//	$ pulumi import oci:DataIntegration/workspaceApplication:WorkspaceApplication test_workspace_application "workspaces/{workspaceId}/applications/{applicationKey}"
//
// ```
type WorkspaceApplication struct {
	pulumi.CustomResourceState

	// The source application version of the application.
	ApplicationVersion pulumi.IntOutput `pulumi:"applicationVersion"`
	// OCID of the compartment that this resource belongs to. Defaults to compartment of the Workspace.
	CompartmentId pulumi.StringOutput `pulumi:"compartmentId"`
	// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. See [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Operations.CostCenter": "42"}`
	DefinedTags pulumi.MapOutput `pulumi:"definedTags"`
	// A list of dependent objects in this patch.
	DependentObjectMetadatas WorkspaceApplicationDependentObjectMetadataArrayOutput `pulumi:"dependentObjectMetadatas"`
	// (Updatable) Detailed description for the object.
	Description pulumi.StringOutput `pulumi:"description"`
	// (Updatable) Free form text without any restriction on permitted characters. Name can have letters, numbers, and special characters. The value is editable and is restricted to 1000 characters.
	DisplayName pulumi.StringOutput `pulumi:"displayName"`
	// (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. See [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Department": "Finance"}`
	FreeformTags pulumi.MapOutput `pulumi:"freeformTags"`
	// (Updatable) Value can only contain upper case letters, underscore, and numbers. It should begin with upper case letter or underscore. The value can be modified.
	Identifier pulumi.StringOutput `pulumi:"identifier"`
	// The identifying key for the object.
	Key pulumi.StringOutput `pulumi:"key"`
	// A key map. If provided, key is replaced with generated key. This structure provides mapping between user provided key and generated key.
	KeyMap pulumi.MapOutput `pulumi:"keyMap"`
	// A summary type containing information about the object including its key, name and when/who created/updated it.
	Metadatas WorkspaceApplicationMetadataArrayOutput `pulumi:"metadatas"`
	// (Updatable) The type of the application.
	ModelType pulumi.StringOutput `pulumi:"modelType"`
	// (Updatable) The object's model version.
	ModelVersion pulumi.StringOutput `pulumi:"modelVersion"`
	// (Updatable) Free form text without any restriction on permitted characters. Name can have letters, numbers, and special characters. The value is editable and is restricted to 1000 characters.
	Name pulumi.StringOutput `pulumi:"name"`
	// (Updatable) The status of an object that can be set to value 1 for shallow references across objects, other values reserved.
	ObjectStatus pulumi.IntOutput `pulumi:"objectStatus"`
	// The object version.
	ObjectVersion pulumi.IntOutput `pulumi:"objectVersion"`
	// A reference to the object's parent.
	ParentReves WorkspaceApplicationParentRefArrayOutput `pulumi:"parentReves"`
	// A list of objects that are published or unpublished in this patch.
	PublishedObjectMetadatas WorkspaceApplicationPublishedObjectMetadataArrayOutput `pulumi:"publishedObjectMetadatas"`
	// Information about the object and its parent.
	RegistryMetadata WorkspaceApplicationRegistryMetadataOutput `pulumi:"registryMetadata"`
	// The information about the application.
	SourceApplicationInfo WorkspaceApplicationSourceApplicationInfoOutput `pulumi:"sourceApplicationInfo"`
	// (Updatable) The current state of the workspace.
	State pulumi.StringOutput `pulumi:"state"`
	// The date and time the application was created, in the timestamp format defined by RFC3339.
	TimeCreated pulumi.StringOutput `pulumi:"timeCreated"`
	// The date and time the application was patched, in the timestamp format defined by RFC3339.
	TimePatched pulumi.StringOutput `pulumi:"timePatched"`
	// The date and time the application was updated, in the timestamp format defined by RFC3339. example: 2019-08-25T21:10:29.41Z
	TimeUpdated pulumi.StringOutput `pulumi:"timeUpdated"`
	// The workspace ID.
	//
	// ** IMPORTANT **
	// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
	WorkspaceId pulumi.StringOutput `pulumi:"workspaceId"`
}

// NewWorkspaceApplication registers a new resource with the given unique name, arguments, and options.
func NewWorkspaceApplication(ctx *pulumi.Context,
	name string, args *WorkspaceApplicationArgs, opts ...pulumi.ResourceOption) (*WorkspaceApplication, error) {
	if args == nil {
		return nil, errors.New("missing one or more required arguments")
	}

	if args.Identifier == nil {
		return nil, errors.New("invalid value for required argument 'Identifier'")
	}
	if args.ModelType == nil {
		return nil, errors.New("invalid value for required argument 'ModelType'")
	}
	if args.WorkspaceId == nil {
		return nil, errors.New("invalid value for required argument 'WorkspaceId'")
	}
	opts = internal.PkgResourceDefaultOpts(opts)
	var resource WorkspaceApplication
	err := ctx.RegisterResource("oci:DataIntegration/workspaceApplication:WorkspaceApplication", name, args, &resource, opts...)
	if err != nil {
		return nil, err
	}
	return &resource, nil
}

// GetWorkspaceApplication gets an existing WorkspaceApplication resource's state with the given name, ID, and optional
// state properties that are used to uniquely qualify the lookup (nil if not required).
func GetWorkspaceApplication(ctx *pulumi.Context,
	name string, id pulumi.IDInput, state *WorkspaceApplicationState, opts ...pulumi.ResourceOption) (*WorkspaceApplication, error) {
	var resource WorkspaceApplication
	err := ctx.ReadResource("oci:DataIntegration/workspaceApplication:WorkspaceApplication", name, id, state, &resource, opts...)
	if err != nil {
		return nil, err
	}
	return &resource, nil
}

// Input properties used for looking up and filtering WorkspaceApplication resources.
type workspaceApplicationState struct {
	// The source application version of the application.
	ApplicationVersion *int `pulumi:"applicationVersion"`
	// OCID of the compartment that this resource belongs to. Defaults to compartment of the Workspace.
	CompartmentId *string `pulumi:"compartmentId"`
	// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. See [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Operations.CostCenter": "42"}`
	DefinedTags map[string]interface{} `pulumi:"definedTags"`
	// A list of dependent objects in this patch.
	DependentObjectMetadatas []WorkspaceApplicationDependentObjectMetadata `pulumi:"dependentObjectMetadatas"`
	// (Updatable) Detailed description for the object.
	Description *string `pulumi:"description"`
	// (Updatable) Free form text without any restriction on permitted characters. Name can have letters, numbers, and special characters. The value is editable and is restricted to 1000 characters.
	DisplayName *string `pulumi:"displayName"`
	// (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. See [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Department": "Finance"}`
	FreeformTags map[string]interface{} `pulumi:"freeformTags"`
	// (Updatable) Value can only contain upper case letters, underscore, and numbers. It should begin with upper case letter or underscore. The value can be modified.
	Identifier *string `pulumi:"identifier"`
	// The identifying key for the object.
	Key *string `pulumi:"key"`
	// A key map. If provided, key is replaced with generated key. This structure provides mapping between user provided key and generated key.
	KeyMap map[string]interface{} `pulumi:"keyMap"`
	// A summary type containing information about the object including its key, name and when/who created/updated it.
	Metadatas []WorkspaceApplicationMetadata `pulumi:"metadatas"`
	// (Updatable) The type of the application.
	ModelType *string `pulumi:"modelType"`
	// (Updatable) The object's model version.
	ModelVersion *string `pulumi:"modelVersion"`
	// (Updatable) Free form text without any restriction on permitted characters. Name can have letters, numbers, and special characters. The value is editable and is restricted to 1000 characters.
	Name *string `pulumi:"name"`
	// (Updatable) The status of an object that can be set to value 1 for shallow references across objects, other values reserved.
	ObjectStatus *int `pulumi:"objectStatus"`
	// The object version.
	ObjectVersion *int `pulumi:"objectVersion"`
	// A reference to the object's parent.
	ParentReves []WorkspaceApplicationParentRef `pulumi:"parentReves"`
	// A list of objects that are published or unpublished in this patch.
	PublishedObjectMetadatas []WorkspaceApplicationPublishedObjectMetadata `pulumi:"publishedObjectMetadatas"`
	// Information about the object and its parent.
	RegistryMetadata *WorkspaceApplicationRegistryMetadata `pulumi:"registryMetadata"`
	// The information about the application.
	SourceApplicationInfo *WorkspaceApplicationSourceApplicationInfo `pulumi:"sourceApplicationInfo"`
	// (Updatable) The current state of the workspace.
	State *string `pulumi:"state"`
	// The date and time the application was created, in the timestamp format defined by RFC3339.
	TimeCreated *string `pulumi:"timeCreated"`
	// The date and time the application was patched, in the timestamp format defined by RFC3339.
	TimePatched *string `pulumi:"timePatched"`
	// The date and time the application was updated, in the timestamp format defined by RFC3339. example: 2019-08-25T21:10:29.41Z
	TimeUpdated *string `pulumi:"timeUpdated"`
	// The workspace ID.
	//
	// ** IMPORTANT **
	// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
	WorkspaceId *string `pulumi:"workspaceId"`
}

type WorkspaceApplicationState struct {
	// The source application version of the application.
	ApplicationVersion pulumi.IntPtrInput
	// OCID of the compartment that this resource belongs to. Defaults to compartment of the Workspace.
	CompartmentId pulumi.StringPtrInput
	// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. See [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Operations.CostCenter": "42"}`
	DefinedTags pulumi.MapInput
	// A list of dependent objects in this patch.
	DependentObjectMetadatas WorkspaceApplicationDependentObjectMetadataArrayInput
	// (Updatable) Detailed description for the object.
	Description pulumi.StringPtrInput
	// (Updatable) Free form text without any restriction on permitted characters. Name can have letters, numbers, and special characters. The value is editable and is restricted to 1000 characters.
	DisplayName pulumi.StringPtrInput
	// (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. See [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Department": "Finance"}`
	FreeformTags pulumi.MapInput
	// (Updatable) Value can only contain upper case letters, underscore, and numbers. It should begin with upper case letter or underscore. The value can be modified.
	Identifier pulumi.StringPtrInput
	// The identifying key for the object.
	Key pulumi.StringPtrInput
	// A key map. If provided, key is replaced with generated key. This structure provides mapping between user provided key and generated key.
	KeyMap pulumi.MapInput
	// A summary type containing information about the object including its key, name and when/who created/updated it.
	Metadatas WorkspaceApplicationMetadataArrayInput
	// (Updatable) The type of the application.
	ModelType pulumi.StringPtrInput
	// (Updatable) The object's model version.
	ModelVersion pulumi.StringPtrInput
	// (Updatable) Free form text without any restriction on permitted characters. Name can have letters, numbers, and special characters. The value is editable and is restricted to 1000 characters.
	Name pulumi.StringPtrInput
	// (Updatable) The status of an object that can be set to value 1 for shallow references across objects, other values reserved.
	ObjectStatus pulumi.IntPtrInput
	// The object version.
	ObjectVersion pulumi.IntPtrInput
	// A reference to the object's parent.
	ParentReves WorkspaceApplicationParentRefArrayInput
	// A list of objects that are published or unpublished in this patch.
	PublishedObjectMetadatas WorkspaceApplicationPublishedObjectMetadataArrayInput
	// Information about the object and its parent.
	RegistryMetadata WorkspaceApplicationRegistryMetadataPtrInput
	// The information about the application.
	SourceApplicationInfo WorkspaceApplicationSourceApplicationInfoPtrInput
	// (Updatable) The current state of the workspace.
	State pulumi.StringPtrInput
	// The date and time the application was created, in the timestamp format defined by RFC3339.
	TimeCreated pulumi.StringPtrInput
	// The date and time the application was patched, in the timestamp format defined by RFC3339.
	TimePatched pulumi.StringPtrInput
	// The date and time the application was updated, in the timestamp format defined by RFC3339. example: 2019-08-25T21:10:29.41Z
	TimeUpdated pulumi.StringPtrInput
	// The workspace ID.
	//
	// ** IMPORTANT **
	// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
	WorkspaceId pulumi.StringPtrInput
}

func (WorkspaceApplicationState) ElementType() reflect.Type {
	return reflect.TypeOf((*workspaceApplicationState)(nil)).Elem()
}

type workspaceApplicationArgs struct {
	// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. See [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Operations.CostCenter": "42"}`
	DefinedTags map[string]interface{} `pulumi:"definedTags"`
	// (Updatable) Detailed description for the object.
	Description *string `pulumi:"description"`
	// (Updatable) Free form text without any restriction on permitted characters. Name can have letters, numbers, and special characters. The value is editable and is restricted to 1000 characters.
	DisplayName *string `pulumi:"displayName"`
	// (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. See [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Department": "Finance"}`
	FreeformTags map[string]interface{} `pulumi:"freeformTags"`
	// (Updatable) Value can only contain upper case letters, underscore, and numbers. It should begin with upper case letter or underscore. The value can be modified.
	Identifier string `pulumi:"identifier"`
	// The identifying key for the object.
	Key *string `pulumi:"key"`
	// (Updatable) The type of the application.
	ModelType string `pulumi:"modelType"`
	// (Updatable) The object's model version.
	ModelVersion *string `pulumi:"modelVersion"`
	// (Updatable) Free form text without any restriction on permitted characters. Name can have letters, numbers, and special characters. The value is editable and is restricted to 1000 characters.
	Name *string `pulumi:"name"`
	// (Updatable) The status of an object that can be set to value 1 for shallow references across objects, other values reserved.
	ObjectStatus *int `pulumi:"objectStatus"`
	// Information about the object and its parent.
	RegistryMetadata *WorkspaceApplicationRegistryMetadata `pulumi:"registryMetadata"`
	// The information about the application.
	SourceApplicationInfo *WorkspaceApplicationSourceApplicationInfo `pulumi:"sourceApplicationInfo"`
	// (Updatable) The current state of the workspace.
	State *string `pulumi:"state"`
	// The workspace ID.
	//
	// ** IMPORTANT **
	// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
	WorkspaceId string `pulumi:"workspaceId"`
}

// The set of arguments for constructing a WorkspaceApplication resource.
type WorkspaceApplicationArgs struct {
	// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. See [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Operations.CostCenter": "42"}`
	DefinedTags pulumi.MapInput
	// (Updatable) Detailed description for the object.
	Description pulumi.StringPtrInput
	// (Updatable) Free form text without any restriction on permitted characters. Name can have letters, numbers, and special characters. The value is editable and is restricted to 1000 characters.
	DisplayName pulumi.StringPtrInput
	// (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. See [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Department": "Finance"}`
	FreeformTags pulumi.MapInput
	// (Updatable) Value can only contain upper case letters, underscore, and numbers. It should begin with upper case letter or underscore. The value can be modified.
	Identifier pulumi.StringInput
	// The identifying key for the object.
	Key pulumi.StringPtrInput
	// (Updatable) The type of the application.
	ModelType pulumi.StringInput
	// (Updatable) The object's model version.
	ModelVersion pulumi.StringPtrInput
	// (Updatable) Free form text without any restriction on permitted characters. Name can have letters, numbers, and special characters. The value is editable and is restricted to 1000 characters.
	Name pulumi.StringPtrInput
	// (Updatable) The status of an object that can be set to value 1 for shallow references across objects, other values reserved.
	ObjectStatus pulumi.IntPtrInput
	// Information about the object and its parent.
	RegistryMetadata WorkspaceApplicationRegistryMetadataPtrInput
	// The information about the application.
	SourceApplicationInfo WorkspaceApplicationSourceApplicationInfoPtrInput
	// (Updatable) The current state of the workspace.
	State pulumi.StringPtrInput
	// The workspace ID.
	//
	// ** IMPORTANT **
	// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
	WorkspaceId pulumi.StringInput
}

func (WorkspaceApplicationArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*workspaceApplicationArgs)(nil)).Elem()
}

type WorkspaceApplicationInput interface {
	pulumi.Input

	ToWorkspaceApplicationOutput() WorkspaceApplicationOutput
	ToWorkspaceApplicationOutputWithContext(ctx context.Context) WorkspaceApplicationOutput
}

func (*WorkspaceApplication) ElementType() reflect.Type {
	return reflect.TypeOf((**WorkspaceApplication)(nil)).Elem()
}

func (i *WorkspaceApplication) ToWorkspaceApplicationOutput() WorkspaceApplicationOutput {
	return i.ToWorkspaceApplicationOutputWithContext(context.Background())
}

func (i *WorkspaceApplication) ToWorkspaceApplicationOutputWithContext(ctx context.Context) WorkspaceApplicationOutput {
	return pulumi.ToOutputWithContext(ctx, i).(WorkspaceApplicationOutput)
}

func (i *WorkspaceApplication) ToOutput(ctx context.Context) pulumix.Output[*WorkspaceApplication] {
	return pulumix.Output[*WorkspaceApplication]{
		OutputState: i.ToWorkspaceApplicationOutputWithContext(ctx).OutputState,
	}
}

// WorkspaceApplicationArrayInput is an input type that accepts WorkspaceApplicationArray and WorkspaceApplicationArrayOutput values.
// You can construct a concrete instance of `WorkspaceApplicationArrayInput` via:
//
//	WorkspaceApplicationArray{ WorkspaceApplicationArgs{...} }
type WorkspaceApplicationArrayInput interface {
	pulumi.Input

	ToWorkspaceApplicationArrayOutput() WorkspaceApplicationArrayOutput
	ToWorkspaceApplicationArrayOutputWithContext(context.Context) WorkspaceApplicationArrayOutput
}

type WorkspaceApplicationArray []WorkspaceApplicationInput

func (WorkspaceApplicationArray) ElementType() reflect.Type {
	return reflect.TypeOf((*[]*WorkspaceApplication)(nil)).Elem()
}

func (i WorkspaceApplicationArray) ToWorkspaceApplicationArrayOutput() WorkspaceApplicationArrayOutput {
	return i.ToWorkspaceApplicationArrayOutputWithContext(context.Background())
}

func (i WorkspaceApplicationArray) ToWorkspaceApplicationArrayOutputWithContext(ctx context.Context) WorkspaceApplicationArrayOutput {
	return pulumi.ToOutputWithContext(ctx, i).(WorkspaceApplicationArrayOutput)
}

func (i WorkspaceApplicationArray) ToOutput(ctx context.Context) pulumix.Output[[]*WorkspaceApplication] {
	return pulumix.Output[[]*WorkspaceApplication]{
		OutputState: i.ToWorkspaceApplicationArrayOutputWithContext(ctx).OutputState,
	}
}

// WorkspaceApplicationMapInput is an input type that accepts WorkspaceApplicationMap and WorkspaceApplicationMapOutput values.
// You can construct a concrete instance of `WorkspaceApplicationMapInput` via:
//
//	WorkspaceApplicationMap{ "key": WorkspaceApplicationArgs{...} }
type WorkspaceApplicationMapInput interface {
	pulumi.Input

	ToWorkspaceApplicationMapOutput() WorkspaceApplicationMapOutput
	ToWorkspaceApplicationMapOutputWithContext(context.Context) WorkspaceApplicationMapOutput
}

type WorkspaceApplicationMap map[string]WorkspaceApplicationInput

func (WorkspaceApplicationMap) ElementType() reflect.Type {
	return reflect.TypeOf((*map[string]*WorkspaceApplication)(nil)).Elem()
}

func (i WorkspaceApplicationMap) ToWorkspaceApplicationMapOutput() WorkspaceApplicationMapOutput {
	return i.ToWorkspaceApplicationMapOutputWithContext(context.Background())
}

func (i WorkspaceApplicationMap) ToWorkspaceApplicationMapOutputWithContext(ctx context.Context) WorkspaceApplicationMapOutput {
	return pulumi.ToOutputWithContext(ctx, i).(WorkspaceApplicationMapOutput)
}

func (i WorkspaceApplicationMap) ToOutput(ctx context.Context) pulumix.Output[map[string]*WorkspaceApplication] {
	return pulumix.Output[map[string]*WorkspaceApplication]{
		OutputState: i.ToWorkspaceApplicationMapOutputWithContext(ctx).OutputState,
	}
}

type WorkspaceApplicationOutput struct{ *pulumi.OutputState }

func (WorkspaceApplicationOutput) ElementType() reflect.Type {
	return reflect.TypeOf((**WorkspaceApplication)(nil)).Elem()
}

func (o WorkspaceApplicationOutput) ToWorkspaceApplicationOutput() WorkspaceApplicationOutput {
	return o
}

func (o WorkspaceApplicationOutput) ToWorkspaceApplicationOutputWithContext(ctx context.Context) WorkspaceApplicationOutput {
	return o
}

func (o WorkspaceApplicationOutput) ToOutput(ctx context.Context) pulumix.Output[*WorkspaceApplication] {
	return pulumix.Output[*WorkspaceApplication]{
		OutputState: o.OutputState,
	}
}

// The source application version of the application.
func (o WorkspaceApplicationOutput) ApplicationVersion() pulumi.IntOutput {
	return o.ApplyT(func(v *WorkspaceApplication) pulumi.IntOutput { return v.ApplicationVersion }).(pulumi.IntOutput)
}

// OCID of the compartment that this resource belongs to. Defaults to compartment of the Workspace.
func (o WorkspaceApplicationOutput) CompartmentId() pulumi.StringOutput {
	return o.ApplyT(func(v *WorkspaceApplication) pulumi.StringOutput { return v.CompartmentId }).(pulumi.StringOutput)
}

// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. See [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Operations.CostCenter": "42"}`
func (o WorkspaceApplicationOutput) DefinedTags() pulumi.MapOutput {
	return o.ApplyT(func(v *WorkspaceApplication) pulumi.MapOutput { return v.DefinedTags }).(pulumi.MapOutput)
}

// A list of dependent objects in this patch.
func (o WorkspaceApplicationOutput) DependentObjectMetadatas() WorkspaceApplicationDependentObjectMetadataArrayOutput {
	return o.ApplyT(func(v *WorkspaceApplication) WorkspaceApplicationDependentObjectMetadataArrayOutput {
		return v.DependentObjectMetadatas
	}).(WorkspaceApplicationDependentObjectMetadataArrayOutput)
}

// (Updatable) Detailed description for the object.
func (o WorkspaceApplicationOutput) Description() pulumi.StringOutput {
	return o.ApplyT(func(v *WorkspaceApplication) pulumi.StringOutput { return v.Description }).(pulumi.StringOutput)
}

// (Updatable) Free form text without any restriction on permitted characters. Name can have letters, numbers, and special characters. The value is editable and is restricted to 1000 characters.
func (o WorkspaceApplicationOutput) DisplayName() pulumi.StringOutput {
	return o.ApplyT(func(v *WorkspaceApplication) pulumi.StringOutput { return v.DisplayName }).(pulumi.StringOutput)
}

// (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. See [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Department": "Finance"}`
func (o WorkspaceApplicationOutput) FreeformTags() pulumi.MapOutput {
	return o.ApplyT(func(v *WorkspaceApplication) pulumi.MapOutput { return v.FreeformTags }).(pulumi.MapOutput)
}

// (Updatable) Value can only contain upper case letters, underscore, and numbers. It should begin with upper case letter or underscore. The value can be modified.
func (o WorkspaceApplicationOutput) Identifier() pulumi.StringOutput {
	return o.ApplyT(func(v *WorkspaceApplication) pulumi.StringOutput { return v.Identifier }).(pulumi.StringOutput)
}

// The identifying key for the object.
func (o WorkspaceApplicationOutput) Key() pulumi.StringOutput {
	return o.ApplyT(func(v *WorkspaceApplication) pulumi.StringOutput { return v.Key }).(pulumi.StringOutput)
}

// A key map. If provided, key is replaced with generated key. This structure provides mapping between user provided key and generated key.
func (o WorkspaceApplicationOutput) KeyMap() pulumi.MapOutput {
	return o.ApplyT(func(v *WorkspaceApplication) pulumi.MapOutput { return v.KeyMap }).(pulumi.MapOutput)
}

// A summary type containing information about the object including its key, name and when/who created/updated it.
func (o WorkspaceApplicationOutput) Metadatas() WorkspaceApplicationMetadataArrayOutput {
	return o.ApplyT(func(v *WorkspaceApplication) WorkspaceApplicationMetadataArrayOutput { return v.Metadatas }).(WorkspaceApplicationMetadataArrayOutput)
}

// (Updatable) The type of the application.
func (o WorkspaceApplicationOutput) ModelType() pulumi.StringOutput {
	return o.ApplyT(func(v *WorkspaceApplication) pulumi.StringOutput { return v.ModelType }).(pulumi.StringOutput)
}

// (Updatable) The object's model version.
func (o WorkspaceApplicationOutput) ModelVersion() pulumi.StringOutput {
	return o.ApplyT(func(v *WorkspaceApplication) pulumi.StringOutput { return v.ModelVersion }).(pulumi.StringOutput)
}

// (Updatable) Free form text without any restriction on permitted characters. Name can have letters, numbers, and special characters. The value is editable and is restricted to 1000 characters.
func (o WorkspaceApplicationOutput) Name() pulumi.StringOutput {
	return o.ApplyT(func(v *WorkspaceApplication) pulumi.StringOutput { return v.Name }).(pulumi.StringOutput)
}

// (Updatable) The status of an object that can be set to value 1 for shallow references across objects, other values reserved.
func (o WorkspaceApplicationOutput) ObjectStatus() pulumi.IntOutput {
	return o.ApplyT(func(v *WorkspaceApplication) pulumi.IntOutput { return v.ObjectStatus }).(pulumi.IntOutput)
}

// The object version.
func (o WorkspaceApplicationOutput) ObjectVersion() pulumi.IntOutput {
	return o.ApplyT(func(v *WorkspaceApplication) pulumi.IntOutput { return v.ObjectVersion }).(pulumi.IntOutput)
}

// A reference to the object's parent.
func (o WorkspaceApplicationOutput) ParentReves() WorkspaceApplicationParentRefArrayOutput {
	return o.ApplyT(func(v *WorkspaceApplication) WorkspaceApplicationParentRefArrayOutput { return v.ParentReves }).(WorkspaceApplicationParentRefArrayOutput)
}

// A list of objects that are published or unpublished in this patch.
func (o WorkspaceApplicationOutput) PublishedObjectMetadatas() WorkspaceApplicationPublishedObjectMetadataArrayOutput {
	return o.ApplyT(func(v *WorkspaceApplication) WorkspaceApplicationPublishedObjectMetadataArrayOutput {
		return v.PublishedObjectMetadatas
	}).(WorkspaceApplicationPublishedObjectMetadataArrayOutput)
}

// Information about the object and its parent.
func (o WorkspaceApplicationOutput) RegistryMetadata() WorkspaceApplicationRegistryMetadataOutput {
	return o.ApplyT(func(v *WorkspaceApplication) WorkspaceApplicationRegistryMetadataOutput { return v.RegistryMetadata }).(WorkspaceApplicationRegistryMetadataOutput)
}

// The information about the application.
func (o WorkspaceApplicationOutput) SourceApplicationInfo() WorkspaceApplicationSourceApplicationInfoOutput {
	return o.ApplyT(func(v *WorkspaceApplication) WorkspaceApplicationSourceApplicationInfoOutput {
		return v.SourceApplicationInfo
	}).(WorkspaceApplicationSourceApplicationInfoOutput)
}

// (Updatable) The current state of the workspace.
func (o WorkspaceApplicationOutput) State() pulumi.StringOutput {
	return o.ApplyT(func(v *WorkspaceApplication) pulumi.StringOutput { return v.State }).(pulumi.StringOutput)
}

// The date and time the application was created, in the timestamp format defined by RFC3339.
func (o WorkspaceApplicationOutput) TimeCreated() pulumi.StringOutput {
	return o.ApplyT(func(v *WorkspaceApplication) pulumi.StringOutput { return v.TimeCreated }).(pulumi.StringOutput)
}

// The date and time the application was patched, in the timestamp format defined by RFC3339.
func (o WorkspaceApplicationOutput) TimePatched() pulumi.StringOutput {
	return o.ApplyT(func(v *WorkspaceApplication) pulumi.StringOutput { return v.TimePatched }).(pulumi.StringOutput)
}

// The date and time the application was updated, in the timestamp format defined by RFC3339. example: 2019-08-25T21:10:29.41Z
func (o WorkspaceApplicationOutput) TimeUpdated() pulumi.StringOutput {
	return o.ApplyT(func(v *WorkspaceApplication) pulumi.StringOutput { return v.TimeUpdated }).(pulumi.StringOutput)
}

// The workspace ID.
//
// ** IMPORTANT **
// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
func (o WorkspaceApplicationOutput) WorkspaceId() pulumi.StringOutput {
	return o.ApplyT(func(v *WorkspaceApplication) pulumi.StringOutput { return v.WorkspaceId }).(pulumi.StringOutput)
}

type WorkspaceApplicationArrayOutput struct{ *pulumi.OutputState }

func (WorkspaceApplicationArrayOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*[]*WorkspaceApplication)(nil)).Elem()
}

func (o WorkspaceApplicationArrayOutput) ToWorkspaceApplicationArrayOutput() WorkspaceApplicationArrayOutput {
	return o
}

func (o WorkspaceApplicationArrayOutput) ToWorkspaceApplicationArrayOutputWithContext(ctx context.Context) WorkspaceApplicationArrayOutput {
	return o
}

func (o WorkspaceApplicationArrayOutput) ToOutput(ctx context.Context) pulumix.Output[[]*WorkspaceApplication] {
	return pulumix.Output[[]*WorkspaceApplication]{
		OutputState: o.OutputState,
	}
}

func (o WorkspaceApplicationArrayOutput) Index(i pulumi.IntInput) WorkspaceApplicationOutput {
	return pulumi.All(o, i).ApplyT(func(vs []interface{}) *WorkspaceApplication {
		return vs[0].([]*WorkspaceApplication)[vs[1].(int)]
	}).(WorkspaceApplicationOutput)
}

type WorkspaceApplicationMapOutput struct{ *pulumi.OutputState }

func (WorkspaceApplicationMapOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*map[string]*WorkspaceApplication)(nil)).Elem()
}

func (o WorkspaceApplicationMapOutput) ToWorkspaceApplicationMapOutput() WorkspaceApplicationMapOutput {
	return o
}

func (o WorkspaceApplicationMapOutput) ToWorkspaceApplicationMapOutputWithContext(ctx context.Context) WorkspaceApplicationMapOutput {
	return o
}

func (o WorkspaceApplicationMapOutput) ToOutput(ctx context.Context) pulumix.Output[map[string]*WorkspaceApplication] {
	return pulumix.Output[map[string]*WorkspaceApplication]{
		OutputState: o.OutputState,
	}
}

func (o WorkspaceApplicationMapOutput) MapIndex(k pulumi.StringInput) WorkspaceApplicationOutput {
	return pulumi.All(o, k).ApplyT(func(vs []interface{}) *WorkspaceApplication {
		return vs[0].(map[string]*WorkspaceApplication)[vs[1].(string)]
	}).(WorkspaceApplicationOutput)
}

func init() {
	pulumi.RegisterInputType(reflect.TypeOf((*WorkspaceApplicationInput)(nil)).Elem(), &WorkspaceApplication{})
	pulumi.RegisterInputType(reflect.TypeOf((*WorkspaceApplicationArrayInput)(nil)).Elem(), WorkspaceApplicationArray{})
	pulumi.RegisterInputType(reflect.TypeOf((*WorkspaceApplicationMapInput)(nil)).Elem(), WorkspaceApplicationMap{})
	pulumi.RegisterOutputType(WorkspaceApplicationOutput{})
	pulumi.RegisterOutputType(WorkspaceApplicationArrayOutput{})
	pulumi.RegisterOutputType(WorkspaceApplicationMapOutput{})
}