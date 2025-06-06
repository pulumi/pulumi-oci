// Code generated by pulumi-language-go DO NOT EDIT.
// *** WARNING: Do not edit by hand unless you're certain you know what you are doing! ***

package cloudguard

import (
	"context"
	"reflect"

	"errors"
	"github.com/pulumi/pulumi-oci/sdk/v3/go/oci/internal"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This resource provides the Detector Recipe resource in Oracle Cloud Infrastructure Cloud Guard service.
//
// Creates a new DetectorRecipe resource.
//
// ## Import
//
// DetectorRecipes can be imported using the `id`, e.g.
//
// ```sh
// $ pulumi import oci:CloudGuard/detectorRecipe:DetectorRecipe test_detector_recipe "id"
// ```
type DetectorRecipe struct {
	pulumi.CustomResourceState

	// (Updatable) Compartment OCID
	CompartmentId pulumi.StringOutput `pulumi:"compartmentId"`
	// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
	DefinedTags pulumi.StringMapOutput `pulumi:"definedTags"`
	// (Updatable) Detector recipe description.
	//
	// Avoid entering confidential information.
	Description pulumi.StringOutput `pulumi:"description"`
	// Detector for the rule
	Detector pulumi.StringOutput `pulumi:"detector"`
	// Recipe type ( STANDARD, ENTERPRISE )
	DetectorRecipeType pulumi.StringOutput `pulumi:"detectorRecipeType"`
	// (Updatable) Detector rules to override from source detector recipe
	DetectorRules DetectorRecipeDetectorRuleArrayOutput `pulumi:"detectorRules"`
	// (Updatable) Detector recipe display name.
	//
	// Avoid entering confidential information.
	DisplayName pulumi.StringOutput `pulumi:"displayName"`
	// List of effective detector rules for the detector type for recipe after applying defaults
	EffectiveDetectorRules DetectorRecipeEffectiveDetectorRuleArrayOutput `pulumi:"effectiveDetectorRules"`
	// (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
	//
	// Avoid entering confidential information.
	FreeformTags pulumi.StringMapOutput `pulumi:"freeformTags"`
	// Owner of detector recipe
	Owner pulumi.StringOutput `pulumi:"owner"`
	// The ID of the source detector recipe
	//
	// ** IMPORTANT **
	// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
	SourceDetectorRecipeId pulumi.StringOutput `pulumi:"sourceDetectorRecipeId"`
	// The current lifecycle state of the resource
	State pulumi.StringOutput `pulumi:"state"`
	// System tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). System tags can be viewed by users, but can only be created by the system.  Example: `{"orcl-cloud.free-tier-retained": "true"}`
	SystemTags pulumi.StringMapOutput `pulumi:"systemTags"`
	// List of target IDs to which the recipe is attached
	TargetIds pulumi.StringArrayOutput `pulumi:"targetIds"`
	// The date and time the detector recipe was created Format defined by RFC3339.
	TimeCreated pulumi.StringOutput `pulumi:"timeCreated"`
	// The date and time the detector recipe was last updated Format defined by RFC3339.
	TimeUpdated pulumi.StringOutput `pulumi:"timeUpdated"`
}

// NewDetectorRecipe registers a new resource with the given unique name, arguments, and options.
func NewDetectorRecipe(ctx *pulumi.Context,
	name string, args *DetectorRecipeArgs, opts ...pulumi.ResourceOption) (*DetectorRecipe, error) {
	if args == nil {
		return nil, errors.New("missing one or more required arguments")
	}

	if args.CompartmentId == nil {
		return nil, errors.New("invalid value for required argument 'CompartmentId'")
	}
	if args.DisplayName == nil {
		return nil, errors.New("invalid value for required argument 'DisplayName'")
	}
	opts = internal.PkgResourceDefaultOpts(opts)
	var resource DetectorRecipe
	err := ctx.RegisterResource("oci:CloudGuard/detectorRecipe:DetectorRecipe", name, args, &resource, opts...)
	if err != nil {
		return nil, err
	}
	return &resource, nil
}

// GetDetectorRecipe gets an existing DetectorRecipe resource's state with the given name, ID, and optional
// state properties that are used to uniquely qualify the lookup (nil if not required).
func GetDetectorRecipe(ctx *pulumi.Context,
	name string, id pulumi.IDInput, state *DetectorRecipeState, opts ...pulumi.ResourceOption) (*DetectorRecipe, error) {
	var resource DetectorRecipe
	err := ctx.ReadResource("oci:CloudGuard/detectorRecipe:DetectorRecipe", name, id, state, &resource, opts...)
	if err != nil {
		return nil, err
	}
	return &resource, nil
}

// Input properties used for looking up and filtering DetectorRecipe resources.
type detectorRecipeState struct {
	// (Updatable) Compartment OCID
	CompartmentId *string `pulumi:"compartmentId"`
	// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
	DefinedTags map[string]string `pulumi:"definedTags"`
	// (Updatable) Detector recipe description.
	//
	// Avoid entering confidential information.
	Description *string `pulumi:"description"`
	// Detector for the rule
	Detector *string `pulumi:"detector"`
	// Recipe type ( STANDARD, ENTERPRISE )
	DetectorRecipeType *string `pulumi:"detectorRecipeType"`
	// (Updatable) Detector rules to override from source detector recipe
	DetectorRules []DetectorRecipeDetectorRule `pulumi:"detectorRules"`
	// (Updatable) Detector recipe display name.
	//
	// Avoid entering confidential information.
	DisplayName *string `pulumi:"displayName"`
	// List of effective detector rules for the detector type for recipe after applying defaults
	EffectiveDetectorRules []DetectorRecipeEffectiveDetectorRule `pulumi:"effectiveDetectorRules"`
	// (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
	//
	// Avoid entering confidential information.
	FreeformTags map[string]string `pulumi:"freeformTags"`
	// Owner of detector recipe
	Owner *string `pulumi:"owner"`
	// The ID of the source detector recipe
	//
	// ** IMPORTANT **
	// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
	SourceDetectorRecipeId *string `pulumi:"sourceDetectorRecipeId"`
	// The current lifecycle state of the resource
	State *string `pulumi:"state"`
	// System tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). System tags can be viewed by users, but can only be created by the system.  Example: `{"orcl-cloud.free-tier-retained": "true"}`
	SystemTags map[string]string `pulumi:"systemTags"`
	// List of target IDs to which the recipe is attached
	TargetIds []string `pulumi:"targetIds"`
	// The date and time the detector recipe was created Format defined by RFC3339.
	TimeCreated *string `pulumi:"timeCreated"`
	// The date and time the detector recipe was last updated Format defined by RFC3339.
	TimeUpdated *string `pulumi:"timeUpdated"`
}

type DetectorRecipeState struct {
	// (Updatable) Compartment OCID
	CompartmentId pulumi.StringPtrInput
	// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
	DefinedTags pulumi.StringMapInput
	// (Updatable) Detector recipe description.
	//
	// Avoid entering confidential information.
	Description pulumi.StringPtrInput
	// Detector for the rule
	Detector pulumi.StringPtrInput
	// Recipe type ( STANDARD, ENTERPRISE )
	DetectorRecipeType pulumi.StringPtrInput
	// (Updatable) Detector rules to override from source detector recipe
	DetectorRules DetectorRecipeDetectorRuleArrayInput
	// (Updatable) Detector recipe display name.
	//
	// Avoid entering confidential information.
	DisplayName pulumi.StringPtrInput
	// List of effective detector rules for the detector type for recipe after applying defaults
	EffectiveDetectorRules DetectorRecipeEffectiveDetectorRuleArrayInput
	// (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
	//
	// Avoid entering confidential information.
	FreeformTags pulumi.StringMapInput
	// Owner of detector recipe
	Owner pulumi.StringPtrInput
	// The ID of the source detector recipe
	//
	// ** IMPORTANT **
	// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
	SourceDetectorRecipeId pulumi.StringPtrInput
	// The current lifecycle state of the resource
	State pulumi.StringPtrInput
	// System tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). System tags can be viewed by users, but can only be created by the system.  Example: `{"orcl-cloud.free-tier-retained": "true"}`
	SystemTags pulumi.StringMapInput
	// List of target IDs to which the recipe is attached
	TargetIds pulumi.StringArrayInput
	// The date and time the detector recipe was created Format defined by RFC3339.
	TimeCreated pulumi.StringPtrInput
	// The date and time the detector recipe was last updated Format defined by RFC3339.
	TimeUpdated pulumi.StringPtrInput
}

func (DetectorRecipeState) ElementType() reflect.Type {
	return reflect.TypeOf((*detectorRecipeState)(nil)).Elem()
}

type detectorRecipeArgs struct {
	// (Updatable) Compartment OCID
	CompartmentId string `pulumi:"compartmentId"`
	// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
	DefinedTags map[string]string `pulumi:"definedTags"`
	// (Updatable) Detector recipe description.
	//
	// Avoid entering confidential information.
	Description *string `pulumi:"description"`
	// Detector for the rule
	Detector *string `pulumi:"detector"`
	// (Updatable) Detector rules to override from source detector recipe
	DetectorRules []DetectorRecipeDetectorRule `pulumi:"detectorRules"`
	// (Updatable) Detector recipe display name.
	//
	// Avoid entering confidential information.
	DisplayName string `pulumi:"displayName"`
	// (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
	//
	// Avoid entering confidential information.
	FreeformTags map[string]string `pulumi:"freeformTags"`
	// The ID of the source detector recipe
	//
	// ** IMPORTANT **
	// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
	SourceDetectorRecipeId *string `pulumi:"sourceDetectorRecipeId"`
}

// The set of arguments for constructing a DetectorRecipe resource.
type DetectorRecipeArgs struct {
	// (Updatable) Compartment OCID
	CompartmentId pulumi.StringInput
	// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
	DefinedTags pulumi.StringMapInput
	// (Updatable) Detector recipe description.
	//
	// Avoid entering confidential information.
	Description pulumi.StringPtrInput
	// Detector for the rule
	Detector pulumi.StringPtrInput
	// (Updatable) Detector rules to override from source detector recipe
	DetectorRules DetectorRecipeDetectorRuleArrayInput
	// (Updatable) Detector recipe display name.
	//
	// Avoid entering confidential information.
	DisplayName pulumi.StringInput
	// (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
	//
	// Avoid entering confidential information.
	FreeformTags pulumi.StringMapInput
	// The ID of the source detector recipe
	//
	// ** IMPORTANT **
	// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
	SourceDetectorRecipeId pulumi.StringPtrInput
}

func (DetectorRecipeArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*detectorRecipeArgs)(nil)).Elem()
}

type DetectorRecipeInput interface {
	pulumi.Input

	ToDetectorRecipeOutput() DetectorRecipeOutput
	ToDetectorRecipeOutputWithContext(ctx context.Context) DetectorRecipeOutput
}

func (*DetectorRecipe) ElementType() reflect.Type {
	return reflect.TypeOf((**DetectorRecipe)(nil)).Elem()
}

func (i *DetectorRecipe) ToDetectorRecipeOutput() DetectorRecipeOutput {
	return i.ToDetectorRecipeOutputWithContext(context.Background())
}

func (i *DetectorRecipe) ToDetectorRecipeOutputWithContext(ctx context.Context) DetectorRecipeOutput {
	return pulumi.ToOutputWithContext(ctx, i).(DetectorRecipeOutput)
}

// DetectorRecipeArrayInput is an input type that accepts DetectorRecipeArray and DetectorRecipeArrayOutput values.
// You can construct a concrete instance of `DetectorRecipeArrayInput` via:
//
//	DetectorRecipeArray{ DetectorRecipeArgs{...} }
type DetectorRecipeArrayInput interface {
	pulumi.Input

	ToDetectorRecipeArrayOutput() DetectorRecipeArrayOutput
	ToDetectorRecipeArrayOutputWithContext(context.Context) DetectorRecipeArrayOutput
}

type DetectorRecipeArray []DetectorRecipeInput

func (DetectorRecipeArray) ElementType() reflect.Type {
	return reflect.TypeOf((*[]*DetectorRecipe)(nil)).Elem()
}

func (i DetectorRecipeArray) ToDetectorRecipeArrayOutput() DetectorRecipeArrayOutput {
	return i.ToDetectorRecipeArrayOutputWithContext(context.Background())
}

func (i DetectorRecipeArray) ToDetectorRecipeArrayOutputWithContext(ctx context.Context) DetectorRecipeArrayOutput {
	return pulumi.ToOutputWithContext(ctx, i).(DetectorRecipeArrayOutput)
}

// DetectorRecipeMapInput is an input type that accepts DetectorRecipeMap and DetectorRecipeMapOutput values.
// You can construct a concrete instance of `DetectorRecipeMapInput` via:
//
//	DetectorRecipeMap{ "key": DetectorRecipeArgs{...} }
type DetectorRecipeMapInput interface {
	pulumi.Input

	ToDetectorRecipeMapOutput() DetectorRecipeMapOutput
	ToDetectorRecipeMapOutputWithContext(context.Context) DetectorRecipeMapOutput
}

type DetectorRecipeMap map[string]DetectorRecipeInput

func (DetectorRecipeMap) ElementType() reflect.Type {
	return reflect.TypeOf((*map[string]*DetectorRecipe)(nil)).Elem()
}

func (i DetectorRecipeMap) ToDetectorRecipeMapOutput() DetectorRecipeMapOutput {
	return i.ToDetectorRecipeMapOutputWithContext(context.Background())
}

func (i DetectorRecipeMap) ToDetectorRecipeMapOutputWithContext(ctx context.Context) DetectorRecipeMapOutput {
	return pulumi.ToOutputWithContext(ctx, i).(DetectorRecipeMapOutput)
}

type DetectorRecipeOutput struct{ *pulumi.OutputState }

func (DetectorRecipeOutput) ElementType() reflect.Type {
	return reflect.TypeOf((**DetectorRecipe)(nil)).Elem()
}

func (o DetectorRecipeOutput) ToDetectorRecipeOutput() DetectorRecipeOutput {
	return o
}

func (o DetectorRecipeOutput) ToDetectorRecipeOutputWithContext(ctx context.Context) DetectorRecipeOutput {
	return o
}

// (Updatable) Compartment OCID
func (o DetectorRecipeOutput) CompartmentId() pulumi.StringOutput {
	return o.ApplyT(func(v *DetectorRecipe) pulumi.StringOutput { return v.CompartmentId }).(pulumi.StringOutput)
}

// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
func (o DetectorRecipeOutput) DefinedTags() pulumi.StringMapOutput {
	return o.ApplyT(func(v *DetectorRecipe) pulumi.StringMapOutput { return v.DefinedTags }).(pulumi.StringMapOutput)
}

// (Updatable) Detector recipe description.
//
// Avoid entering confidential information.
func (o DetectorRecipeOutput) Description() pulumi.StringOutput {
	return o.ApplyT(func(v *DetectorRecipe) pulumi.StringOutput { return v.Description }).(pulumi.StringOutput)
}

// Detector for the rule
func (o DetectorRecipeOutput) Detector() pulumi.StringOutput {
	return o.ApplyT(func(v *DetectorRecipe) pulumi.StringOutput { return v.Detector }).(pulumi.StringOutput)
}

// Recipe type ( STANDARD, ENTERPRISE )
func (o DetectorRecipeOutput) DetectorRecipeType() pulumi.StringOutput {
	return o.ApplyT(func(v *DetectorRecipe) pulumi.StringOutput { return v.DetectorRecipeType }).(pulumi.StringOutput)
}

// (Updatable) Detector rules to override from source detector recipe
func (o DetectorRecipeOutput) DetectorRules() DetectorRecipeDetectorRuleArrayOutput {
	return o.ApplyT(func(v *DetectorRecipe) DetectorRecipeDetectorRuleArrayOutput { return v.DetectorRules }).(DetectorRecipeDetectorRuleArrayOutput)
}

// (Updatable) Detector recipe display name.
//
// Avoid entering confidential information.
func (o DetectorRecipeOutput) DisplayName() pulumi.StringOutput {
	return o.ApplyT(func(v *DetectorRecipe) pulumi.StringOutput { return v.DisplayName }).(pulumi.StringOutput)
}

// List of effective detector rules for the detector type for recipe after applying defaults
func (o DetectorRecipeOutput) EffectiveDetectorRules() DetectorRecipeEffectiveDetectorRuleArrayOutput {
	return o.ApplyT(func(v *DetectorRecipe) DetectorRecipeEffectiveDetectorRuleArrayOutput {
		return v.EffectiveDetectorRules
	}).(DetectorRecipeEffectiveDetectorRuleArrayOutput)
}

// (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
//
// Avoid entering confidential information.
func (o DetectorRecipeOutput) FreeformTags() pulumi.StringMapOutput {
	return o.ApplyT(func(v *DetectorRecipe) pulumi.StringMapOutput { return v.FreeformTags }).(pulumi.StringMapOutput)
}

// Owner of detector recipe
func (o DetectorRecipeOutput) Owner() pulumi.StringOutput {
	return o.ApplyT(func(v *DetectorRecipe) pulumi.StringOutput { return v.Owner }).(pulumi.StringOutput)
}

// The ID of the source detector recipe
//
// ** IMPORTANT **
// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
func (o DetectorRecipeOutput) SourceDetectorRecipeId() pulumi.StringOutput {
	return o.ApplyT(func(v *DetectorRecipe) pulumi.StringOutput { return v.SourceDetectorRecipeId }).(pulumi.StringOutput)
}

// The current lifecycle state of the resource
func (o DetectorRecipeOutput) State() pulumi.StringOutput {
	return o.ApplyT(func(v *DetectorRecipe) pulumi.StringOutput { return v.State }).(pulumi.StringOutput)
}

// System tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). System tags can be viewed by users, but can only be created by the system.  Example: `{"orcl-cloud.free-tier-retained": "true"}`
func (o DetectorRecipeOutput) SystemTags() pulumi.StringMapOutput {
	return o.ApplyT(func(v *DetectorRecipe) pulumi.StringMapOutput { return v.SystemTags }).(pulumi.StringMapOutput)
}

// List of target IDs to which the recipe is attached
func (o DetectorRecipeOutput) TargetIds() pulumi.StringArrayOutput {
	return o.ApplyT(func(v *DetectorRecipe) pulumi.StringArrayOutput { return v.TargetIds }).(pulumi.StringArrayOutput)
}

// The date and time the detector recipe was created Format defined by RFC3339.
func (o DetectorRecipeOutput) TimeCreated() pulumi.StringOutput {
	return o.ApplyT(func(v *DetectorRecipe) pulumi.StringOutput { return v.TimeCreated }).(pulumi.StringOutput)
}

// The date and time the detector recipe was last updated Format defined by RFC3339.
func (o DetectorRecipeOutput) TimeUpdated() pulumi.StringOutput {
	return o.ApplyT(func(v *DetectorRecipe) pulumi.StringOutput { return v.TimeUpdated }).(pulumi.StringOutput)
}

type DetectorRecipeArrayOutput struct{ *pulumi.OutputState }

func (DetectorRecipeArrayOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*[]*DetectorRecipe)(nil)).Elem()
}

func (o DetectorRecipeArrayOutput) ToDetectorRecipeArrayOutput() DetectorRecipeArrayOutput {
	return o
}

func (o DetectorRecipeArrayOutput) ToDetectorRecipeArrayOutputWithContext(ctx context.Context) DetectorRecipeArrayOutput {
	return o
}

func (o DetectorRecipeArrayOutput) Index(i pulumi.IntInput) DetectorRecipeOutput {
	return pulumi.All(o, i).ApplyT(func(vs []interface{}) *DetectorRecipe {
		return vs[0].([]*DetectorRecipe)[vs[1].(int)]
	}).(DetectorRecipeOutput)
}

type DetectorRecipeMapOutput struct{ *pulumi.OutputState }

func (DetectorRecipeMapOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*map[string]*DetectorRecipe)(nil)).Elem()
}

func (o DetectorRecipeMapOutput) ToDetectorRecipeMapOutput() DetectorRecipeMapOutput {
	return o
}

func (o DetectorRecipeMapOutput) ToDetectorRecipeMapOutputWithContext(ctx context.Context) DetectorRecipeMapOutput {
	return o
}

func (o DetectorRecipeMapOutput) MapIndex(k pulumi.StringInput) DetectorRecipeOutput {
	return pulumi.All(o, k).ApplyT(func(vs []interface{}) *DetectorRecipe {
		return vs[0].(map[string]*DetectorRecipe)[vs[1].(string)]
	}).(DetectorRecipeOutput)
}

func init() {
	pulumi.RegisterInputType(reflect.TypeOf((*DetectorRecipeInput)(nil)).Elem(), &DetectorRecipe{})
	pulumi.RegisterInputType(reflect.TypeOf((*DetectorRecipeArrayInput)(nil)).Elem(), DetectorRecipeArray{})
	pulumi.RegisterInputType(reflect.TypeOf((*DetectorRecipeMapInput)(nil)).Elem(), DetectorRecipeMap{})
	pulumi.RegisterOutputType(DetectorRecipeOutput{})
	pulumi.RegisterOutputType(DetectorRecipeArrayOutput{})
	pulumi.RegisterOutputType(DetectorRecipeMapOutput{})
}
