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

// This resource provides the Model Version Set resource in Oracle Cloud Infrastructure Data Science service.
//
// Creates a new modelVersionSet.
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
//			_, err := datascience.NewModelVersionSet(ctx, "test_model_version_set", &datascience.ModelVersionSetArgs{
//				CompartmentId: pulumi.Any(compartmentId),
//				Name:          pulumi.Any(modelVersionSetName),
//				ProjectId:     pulumi.Any(testProject.Id),
//				DefinedTags: pulumi.StringMap{
//					"Operations.CostCenter": pulumi.String("42"),
//				},
//				Description: pulumi.Any(modelVersionSetDescription),
//				FreeformTags: pulumi.StringMap{
//					"Department": pulumi.String("Finance"),
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
// ModelVersionSets can be imported using the `id`, e.g.
//
// ```sh
// $ pulumi import oci:DataScience/modelVersionSet:ModelVersionSet test_model_version_set "id"
// ```
type ModelVersionSet struct {
	pulumi.CustomResourceState

	// The category of the model version set.
	Category pulumi.StringOutput `pulumi:"category"`
	// (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment to create the model version set in.
	CompartmentId pulumi.StringOutput `pulumi:"compartmentId"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the user who created the model version set.
	CreatedBy pulumi.StringOutput `pulumi:"createdBy"`
	// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. See [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Operations.CostCenter": "42"}`
	DefinedTags pulumi.StringMapOutput `pulumi:"definedTags"`
	// (Updatable) A short description of the model version set.
	Description pulumi.StringOutput `pulumi:"description"`
	// (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. See [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Department": "Finance"}`
	FreeformTags pulumi.StringMapOutput `pulumi:"freeformTags"`
	// A user-friendly name for the resource. It must be unique and can't be modified. Avoid entering confidential information. Example: `My model version set`
	Name pulumi.StringOutput `pulumi:"name"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the project to associate with the model version set.
	//
	// ** IMPORTANT **
	// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
	ProjectId pulumi.StringOutput `pulumi:"projectId"`
	// The state of the model version set.
	State pulumi.StringOutput `pulumi:"state"`
	// Usage of system tag keys. These predefined keys are scoped to namespaces. Example: `{"orcl-cloud.free-tier-retained": "true"}`
	SystemTags pulumi.StringMapOutput `pulumi:"systemTags"`
	// The date and time that the resource was created in the timestamp format defined by [RFC3339](https://tools.ietf.org/html/rfc3339). Example: 2019-08-25T21:10:29.41Z
	TimeCreated pulumi.StringOutput `pulumi:"timeCreated"`
	// The date and time that the resource was created in the timestamp format defined by [RFC3339](https://tools.ietf.org/html/rfc3339). Example: 2019-08-25T21:10:29.41Z
	TimeUpdated pulumi.StringOutput `pulumi:"timeUpdated"`
}

// NewModelVersionSet registers a new resource with the given unique name, arguments, and options.
func NewModelVersionSet(ctx *pulumi.Context,
	name string, args *ModelVersionSetArgs, opts ...pulumi.ResourceOption) (*ModelVersionSet, error) {
	if args == nil {
		return nil, errors.New("missing one or more required arguments")
	}

	if args.CompartmentId == nil {
		return nil, errors.New("invalid value for required argument 'CompartmentId'")
	}
	if args.ProjectId == nil {
		return nil, errors.New("invalid value for required argument 'ProjectId'")
	}
	opts = internal.PkgResourceDefaultOpts(opts)
	var resource ModelVersionSet
	err := ctx.RegisterResource("oci:DataScience/modelVersionSet:ModelVersionSet", name, args, &resource, opts...)
	if err != nil {
		return nil, err
	}
	return &resource, nil
}

// GetModelVersionSet gets an existing ModelVersionSet resource's state with the given name, ID, and optional
// state properties that are used to uniquely qualify the lookup (nil if not required).
func GetModelVersionSet(ctx *pulumi.Context,
	name string, id pulumi.IDInput, state *ModelVersionSetState, opts ...pulumi.ResourceOption) (*ModelVersionSet, error) {
	var resource ModelVersionSet
	err := ctx.ReadResource("oci:DataScience/modelVersionSet:ModelVersionSet", name, id, state, &resource, opts...)
	if err != nil {
		return nil, err
	}
	return &resource, nil
}

// Input properties used for looking up and filtering ModelVersionSet resources.
type modelVersionSetState struct {
	// The category of the model version set.
	Category *string `pulumi:"category"`
	// (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment to create the model version set in.
	CompartmentId *string `pulumi:"compartmentId"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the user who created the model version set.
	CreatedBy *string `pulumi:"createdBy"`
	// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. See [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Operations.CostCenter": "42"}`
	DefinedTags map[string]string `pulumi:"definedTags"`
	// (Updatable) A short description of the model version set.
	Description *string `pulumi:"description"`
	// (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. See [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Department": "Finance"}`
	FreeformTags map[string]string `pulumi:"freeformTags"`
	// A user-friendly name for the resource. It must be unique and can't be modified. Avoid entering confidential information. Example: `My model version set`
	Name *string `pulumi:"name"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the project to associate with the model version set.
	//
	// ** IMPORTANT **
	// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
	ProjectId *string `pulumi:"projectId"`
	// The state of the model version set.
	State *string `pulumi:"state"`
	// Usage of system tag keys. These predefined keys are scoped to namespaces. Example: `{"orcl-cloud.free-tier-retained": "true"}`
	SystemTags map[string]string `pulumi:"systemTags"`
	// The date and time that the resource was created in the timestamp format defined by [RFC3339](https://tools.ietf.org/html/rfc3339). Example: 2019-08-25T21:10:29.41Z
	TimeCreated *string `pulumi:"timeCreated"`
	// The date and time that the resource was created in the timestamp format defined by [RFC3339](https://tools.ietf.org/html/rfc3339). Example: 2019-08-25T21:10:29.41Z
	TimeUpdated *string `pulumi:"timeUpdated"`
}

type ModelVersionSetState struct {
	// The category of the model version set.
	Category pulumi.StringPtrInput
	// (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment to create the model version set in.
	CompartmentId pulumi.StringPtrInput
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the user who created the model version set.
	CreatedBy pulumi.StringPtrInput
	// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. See [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Operations.CostCenter": "42"}`
	DefinedTags pulumi.StringMapInput
	// (Updatable) A short description of the model version set.
	Description pulumi.StringPtrInput
	// (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. See [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Department": "Finance"}`
	FreeformTags pulumi.StringMapInput
	// A user-friendly name for the resource. It must be unique and can't be modified. Avoid entering confidential information. Example: `My model version set`
	Name pulumi.StringPtrInput
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the project to associate with the model version set.
	//
	// ** IMPORTANT **
	// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
	ProjectId pulumi.StringPtrInput
	// The state of the model version set.
	State pulumi.StringPtrInput
	// Usage of system tag keys. These predefined keys are scoped to namespaces. Example: `{"orcl-cloud.free-tier-retained": "true"}`
	SystemTags pulumi.StringMapInput
	// The date and time that the resource was created in the timestamp format defined by [RFC3339](https://tools.ietf.org/html/rfc3339). Example: 2019-08-25T21:10:29.41Z
	TimeCreated pulumi.StringPtrInput
	// The date and time that the resource was created in the timestamp format defined by [RFC3339](https://tools.ietf.org/html/rfc3339). Example: 2019-08-25T21:10:29.41Z
	TimeUpdated pulumi.StringPtrInput
}

func (ModelVersionSetState) ElementType() reflect.Type {
	return reflect.TypeOf((*modelVersionSetState)(nil)).Elem()
}

type modelVersionSetArgs struct {
	// (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment to create the model version set in.
	CompartmentId string `pulumi:"compartmentId"`
	// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. See [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Operations.CostCenter": "42"}`
	DefinedTags map[string]string `pulumi:"definedTags"`
	// (Updatable) A short description of the model version set.
	Description *string `pulumi:"description"`
	// (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. See [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Department": "Finance"}`
	FreeformTags map[string]string `pulumi:"freeformTags"`
	// A user-friendly name for the resource. It must be unique and can't be modified. Avoid entering confidential information. Example: `My model version set`
	Name *string `pulumi:"name"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the project to associate with the model version set.
	//
	// ** IMPORTANT **
	// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
	ProjectId string `pulumi:"projectId"`
}

// The set of arguments for constructing a ModelVersionSet resource.
type ModelVersionSetArgs struct {
	// (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment to create the model version set in.
	CompartmentId pulumi.StringInput
	// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. See [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Operations.CostCenter": "42"}`
	DefinedTags pulumi.StringMapInput
	// (Updatable) A short description of the model version set.
	Description pulumi.StringPtrInput
	// (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. See [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Department": "Finance"}`
	FreeformTags pulumi.StringMapInput
	// A user-friendly name for the resource. It must be unique and can't be modified. Avoid entering confidential information. Example: `My model version set`
	Name pulumi.StringPtrInput
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the project to associate with the model version set.
	//
	// ** IMPORTANT **
	// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
	ProjectId pulumi.StringInput
}

func (ModelVersionSetArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*modelVersionSetArgs)(nil)).Elem()
}

type ModelVersionSetInput interface {
	pulumi.Input

	ToModelVersionSetOutput() ModelVersionSetOutput
	ToModelVersionSetOutputWithContext(ctx context.Context) ModelVersionSetOutput
}

func (*ModelVersionSet) ElementType() reflect.Type {
	return reflect.TypeOf((**ModelVersionSet)(nil)).Elem()
}

func (i *ModelVersionSet) ToModelVersionSetOutput() ModelVersionSetOutput {
	return i.ToModelVersionSetOutputWithContext(context.Background())
}

func (i *ModelVersionSet) ToModelVersionSetOutputWithContext(ctx context.Context) ModelVersionSetOutput {
	return pulumi.ToOutputWithContext(ctx, i).(ModelVersionSetOutput)
}

// ModelVersionSetArrayInput is an input type that accepts ModelVersionSetArray and ModelVersionSetArrayOutput values.
// You can construct a concrete instance of `ModelVersionSetArrayInput` via:
//
//	ModelVersionSetArray{ ModelVersionSetArgs{...} }
type ModelVersionSetArrayInput interface {
	pulumi.Input

	ToModelVersionSetArrayOutput() ModelVersionSetArrayOutput
	ToModelVersionSetArrayOutputWithContext(context.Context) ModelVersionSetArrayOutput
}

type ModelVersionSetArray []ModelVersionSetInput

func (ModelVersionSetArray) ElementType() reflect.Type {
	return reflect.TypeOf((*[]*ModelVersionSet)(nil)).Elem()
}

func (i ModelVersionSetArray) ToModelVersionSetArrayOutput() ModelVersionSetArrayOutput {
	return i.ToModelVersionSetArrayOutputWithContext(context.Background())
}

func (i ModelVersionSetArray) ToModelVersionSetArrayOutputWithContext(ctx context.Context) ModelVersionSetArrayOutput {
	return pulumi.ToOutputWithContext(ctx, i).(ModelVersionSetArrayOutput)
}

// ModelVersionSetMapInput is an input type that accepts ModelVersionSetMap and ModelVersionSetMapOutput values.
// You can construct a concrete instance of `ModelVersionSetMapInput` via:
//
//	ModelVersionSetMap{ "key": ModelVersionSetArgs{...} }
type ModelVersionSetMapInput interface {
	pulumi.Input

	ToModelVersionSetMapOutput() ModelVersionSetMapOutput
	ToModelVersionSetMapOutputWithContext(context.Context) ModelVersionSetMapOutput
}

type ModelVersionSetMap map[string]ModelVersionSetInput

func (ModelVersionSetMap) ElementType() reflect.Type {
	return reflect.TypeOf((*map[string]*ModelVersionSet)(nil)).Elem()
}

func (i ModelVersionSetMap) ToModelVersionSetMapOutput() ModelVersionSetMapOutput {
	return i.ToModelVersionSetMapOutputWithContext(context.Background())
}

func (i ModelVersionSetMap) ToModelVersionSetMapOutputWithContext(ctx context.Context) ModelVersionSetMapOutput {
	return pulumi.ToOutputWithContext(ctx, i).(ModelVersionSetMapOutput)
}

type ModelVersionSetOutput struct{ *pulumi.OutputState }

func (ModelVersionSetOutput) ElementType() reflect.Type {
	return reflect.TypeOf((**ModelVersionSet)(nil)).Elem()
}

func (o ModelVersionSetOutput) ToModelVersionSetOutput() ModelVersionSetOutput {
	return o
}

func (o ModelVersionSetOutput) ToModelVersionSetOutputWithContext(ctx context.Context) ModelVersionSetOutput {
	return o
}

// The category of the model version set.
func (o ModelVersionSetOutput) Category() pulumi.StringOutput {
	return o.ApplyT(func(v *ModelVersionSet) pulumi.StringOutput { return v.Category }).(pulumi.StringOutput)
}

// (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment to create the model version set in.
func (o ModelVersionSetOutput) CompartmentId() pulumi.StringOutput {
	return o.ApplyT(func(v *ModelVersionSet) pulumi.StringOutput { return v.CompartmentId }).(pulumi.StringOutput)
}

// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the user who created the model version set.
func (o ModelVersionSetOutput) CreatedBy() pulumi.StringOutput {
	return o.ApplyT(func(v *ModelVersionSet) pulumi.StringOutput { return v.CreatedBy }).(pulumi.StringOutput)
}

// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. See [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Operations.CostCenter": "42"}`
func (o ModelVersionSetOutput) DefinedTags() pulumi.StringMapOutput {
	return o.ApplyT(func(v *ModelVersionSet) pulumi.StringMapOutput { return v.DefinedTags }).(pulumi.StringMapOutput)
}

// (Updatable) A short description of the model version set.
func (o ModelVersionSetOutput) Description() pulumi.StringOutput {
	return o.ApplyT(func(v *ModelVersionSet) pulumi.StringOutput { return v.Description }).(pulumi.StringOutput)
}

// (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. See [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Department": "Finance"}`
func (o ModelVersionSetOutput) FreeformTags() pulumi.StringMapOutput {
	return o.ApplyT(func(v *ModelVersionSet) pulumi.StringMapOutput { return v.FreeformTags }).(pulumi.StringMapOutput)
}

// A user-friendly name for the resource. It must be unique and can't be modified. Avoid entering confidential information. Example: `My model version set`
func (o ModelVersionSetOutput) Name() pulumi.StringOutput {
	return o.ApplyT(func(v *ModelVersionSet) pulumi.StringOutput { return v.Name }).(pulumi.StringOutput)
}

// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the project to associate with the model version set.
//
// ** IMPORTANT **
// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
func (o ModelVersionSetOutput) ProjectId() pulumi.StringOutput {
	return o.ApplyT(func(v *ModelVersionSet) pulumi.StringOutput { return v.ProjectId }).(pulumi.StringOutput)
}

// The state of the model version set.
func (o ModelVersionSetOutput) State() pulumi.StringOutput {
	return o.ApplyT(func(v *ModelVersionSet) pulumi.StringOutput { return v.State }).(pulumi.StringOutput)
}

// Usage of system tag keys. These predefined keys are scoped to namespaces. Example: `{"orcl-cloud.free-tier-retained": "true"}`
func (o ModelVersionSetOutput) SystemTags() pulumi.StringMapOutput {
	return o.ApplyT(func(v *ModelVersionSet) pulumi.StringMapOutput { return v.SystemTags }).(pulumi.StringMapOutput)
}

// The date and time that the resource was created in the timestamp format defined by [RFC3339](https://tools.ietf.org/html/rfc3339). Example: 2019-08-25T21:10:29.41Z
func (o ModelVersionSetOutput) TimeCreated() pulumi.StringOutput {
	return o.ApplyT(func(v *ModelVersionSet) pulumi.StringOutput { return v.TimeCreated }).(pulumi.StringOutput)
}

// The date and time that the resource was created in the timestamp format defined by [RFC3339](https://tools.ietf.org/html/rfc3339). Example: 2019-08-25T21:10:29.41Z
func (o ModelVersionSetOutput) TimeUpdated() pulumi.StringOutput {
	return o.ApplyT(func(v *ModelVersionSet) pulumi.StringOutput { return v.TimeUpdated }).(pulumi.StringOutput)
}

type ModelVersionSetArrayOutput struct{ *pulumi.OutputState }

func (ModelVersionSetArrayOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*[]*ModelVersionSet)(nil)).Elem()
}

func (o ModelVersionSetArrayOutput) ToModelVersionSetArrayOutput() ModelVersionSetArrayOutput {
	return o
}

func (o ModelVersionSetArrayOutput) ToModelVersionSetArrayOutputWithContext(ctx context.Context) ModelVersionSetArrayOutput {
	return o
}

func (o ModelVersionSetArrayOutput) Index(i pulumi.IntInput) ModelVersionSetOutput {
	return pulumi.All(o, i).ApplyT(func(vs []interface{}) *ModelVersionSet {
		return vs[0].([]*ModelVersionSet)[vs[1].(int)]
	}).(ModelVersionSetOutput)
}

type ModelVersionSetMapOutput struct{ *pulumi.OutputState }

func (ModelVersionSetMapOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*map[string]*ModelVersionSet)(nil)).Elem()
}

func (o ModelVersionSetMapOutput) ToModelVersionSetMapOutput() ModelVersionSetMapOutput {
	return o
}

func (o ModelVersionSetMapOutput) ToModelVersionSetMapOutputWithContext(ctx context.Context) ModelVersionSetMapOutput {
	return o
}

func (o ModelVersionSetMapOutput) MapIndex(k pulumi.StringInput) ModelVersionSetOutput {
	return pulumi.All(o, k).ApplyT(func(vs []interface{}) *ModelVersionSet {
		return vs[0].(map[string]*ModelVersionSet)[vs[1].(string)]
	}).(ModelVersionSetOutput)
}

func init() {
	pulumi.RegisterInputType(reflect.TypeOf((*ModelVersionSetInput)(nil)).Elem(), &ModelVersionSet{})
	pulumi.RegisterInputType(reflect.TypeOf((*ModelVersionSetArrayInput)(nil)).Elem(), ModelVersionSetArray{})
	pulumi.RegisterInputType(reflect.TypeOf((*ModelVersionSetMapInput)(nil)).Elem(), ModelVersionSetMap{})
	pulumi.RegisterOutputType(ModelVersionSetOutput{})
	pulumi.RegisterOutputType(ModelVersionSetArrayOutput{})
	pulumi.RegisterOutputType(ModelVersionSetMapOutput{})
}
