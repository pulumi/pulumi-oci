// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package cloudguard

import (
	"context"
	"reflect"

	"github.com/pkg/errors"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This resource provides the Detector Recipe resource in Oracle Cloud Infrastructure Cloud Guard service.
//
// Creates a DetectorRecipe
//
// ## Import
//
// DetectorRecipes can be imported using the `id`, e.g.
//
// ```sh
//  $ pulumi import oci:CloudGuard/detectorRecipe:DetectorRecipe test_detector_recipe "id"
// ```
type DetectorRecipe struct {
	pulumi.CustomResourceState

	// (Updatable) Compartment Identifier
	CompartmentId pulumi.StringOutput `pulumi:"compartmentId"`
	// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
	DefinedTags pulumi.MapOutput `pulumi:"definedTags"`
	// (Updatable) DetectorRecipe Description
	Description pulumi.StringOutput `pulumi:"description"`
	// detector for the rule
	Detector pulumi.StringOutput `pulumi:"detector"`
	// (Updatable) Detector Rules to override from source detector recipe
	DetectorRules DetectorRecipeDetectorRuleArrayOutput `pulumi:"detectorRules"`
	// (Updatable) DetectorRecipe Display Name
	DisplayName pulumi.StringOutput `pulumi:"displayName"`
	// List of effective detector rules for the detector type for recipe after applying defaults
	EffectiveDetectorRules DetectorRecipeEffectiveDetectorRuleArrayOutput `pulumi:"effectiveDetectorRules"`
	// (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
	FreeformTags pulumi.MapOutput `pulumi:"freeformTags"`
	// Owner of detector recipe
	Owner pulumi.StringOutput `pulumi:"owner"`
	// The id of the source detector recipe.
	SourceDetectorRecipeId pulumi.StringOutput `pulumi:"sourceDetectorRecipeId"`
	// The current state of the resource.
	State pulumi.StringOutput `pulumi:"state"`
	// System tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). System tags can be viewed by users, but can only be created by the system.  Example: `{"orcl-cloud.free-tier-retained": "true"}`
	SystemTags pulumi.MapOutput `pulumi:"systemTags"`
	// The date and time the detector recipe was created. Format defined by RFC3339.
	TimeCreated pulumi.StringOutput `pulumi:"timeCreated"`
	// The date and time the detector recipe was updated. Format defined by RFC3339.
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
	if args.SourceDetectorRecipeId == nil {
		return nil, errors.New("invalid value for required argument 'SourceDetectorRecipeId'")
	}
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
	// (Updatable) Compartment Identifier
	CompartmentId *string `pulumi:"compartmentId"`
	// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
	DefinedTags map[string]interface{} `pulumi:"definedTags"`
	// (Updatable) DetectorRecipe Description
	Description *string `pulumi:"description"`
	// detector for the rule
	Detector *string `pulumi:"detector"`
	// (Updatable) Detector Rules to override from source detector recipe
	DetectorRules []DetectorRecipeDetectorRule `pulumi:"detectorRules"`
	// (Updatable) DetectorRecipe Display Name
	DisplayName *string `pulumi:"displayName"`
	// List of effective detector rules for the detector type for recipe after applying defaults
	EffectiveDetectorRules []DetectorRecipeEffectiveDetectorRule `pulumi:"effectiveDetectorRules"`
	// (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
	FreeformTags map[string]interface{} `pulumi:"freeformTags"`
	// Owner of detector recipe
	Owner *string `pulumi:"owner"`
	// The id of the source detector recipe.
	SourceDetectorRecipeId *string `pulumi:"sourceDetectorRecipeId"`
	// The current state of the resource.
	State *string `pulumi:"state"`
	// System tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). System tags can be viewed by users, but can only be created by the system.  Example: `{"orcl-cloud.free-tier-retained": "true"}`
	SystemTags map[string]interface{} `pulumi:"systemTags"`
	// The date and time the detector recipe was created. Format defined by RFC3339.
	TimeCreated *string `pulumi:"timeCreated"`
	// The date and time the detector recipe was updated. Format defined by RFC3339.
	TimeUpdated *string `pulumi:"timeUpdated"`
}

type DetectorRecipeState struct {
	// (Updatable) Compartment Identifier
	CompartmentId pulumi.StringPtrInput
	// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
	DefinedTags pulumi.MapInput
	// (Updatable) DetectorRecipe Description
	Description pulumi.StringPtrInput
	// detector for the rule
	Detector pulumi.StringPtrInput
	// (Updatable) Detector Rules to override from source detector recipe
	DetectorRules DetectorRecipeDetectorRuleArrayInput
	// (Updatable) DetectorRecipe Display Name
	DisplayName pulumi.StringPtrInput
	// List of effective detector rules for the detector type for recipe after applying defaults
	EffectiveDetectorRules DetectorRecipeEffectiveDetectorRuleArrayInput
	// (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
	FreeformTags pulumi.MapInput
	// Owner of detector recipe
	Owner pulumi.StringPtrInput
	// The id of the source detector recipe.
	SourceDetectorRecipeId pulumi.StringPtrInput
	// The current state of the resource.
	State pulumi.StringPtrInput
	// System tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). System tags can be viewed by users, but can only be created by the system.  Example: `{"orcl-cloud.free-tier-retained": "true"}`
	SystemTags pulumi.MapInput
	// The date and time the detector recipe was created. Format defined by RFC3339.
	TimeCreated pulumi.StringPtrInput
	// The date and time the detector recipe was updated. Format defined by RFC3339.
	TimeUpdated pulumi.StringPtrInput
}

func (DetectorRecipeState) ElementType() reflect.Type {
	return reflect.TypeOf((*detectorRecipeState)(nil)).Elem()
}

type detectorRecipeArgs struct {
	// (Updatable) Compartment Identifier
	CompartmentId string `pulumi:"compartmentId"`
	// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
	DefinedTags map[string]interface{} `pulumi:"definedTags"`
	// (Updatable) DetectorRecipe Description
	Description *string `pulumi:"description"`
	// (Updatable) Detector Rules to override from source detector recipe
	DetectorRules []DetectorRecipeDetectorRule `pulumi:"detectorRules"`
	// (Updatable) DetectorRecipe Display Name
	DisplayName string `pulumi:"displayName"`
	// (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
	FreeformTags map[string]interface{} `pulumi:"freeformTags"`
	// The id of the source detector recipe.
	SourceDetectorRecipeId string `pulumi:"sourceDetectorRecipeId"`
}

// The set of arguments for constructing a DetectorRecipe resource.
type DetectorRecipeArgs struct {
	// (Updatable) Compartment Identifier
	CompartmentId pulumi.StringInput
	// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
	DefinedTags pulumi.MapInput
	// (Updatable) DetectorRecipe Description
	Description pulumi.StringPtrInput
	// (Updatable) Detector Rules to override from source detector recipe
	DetectorRules DetectorRecipeDetectorRuleArrayInput
	// (Updatable) DetectorRecipe Display Name
	DisplayName pulumi.StringInput
	// (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
	FreeformTags pulumi.MapInput
	// The id of the source detector recipe.
	SourceDetectorRecipeId pulumi.StringInput
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
//          DetectorRecipeArray{ DetectorRecipeArgs{...} }
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
//          DetectorRecipeMap{ "key": DetectorRecipeArgs{...} }
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
