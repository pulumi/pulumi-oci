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

// This resource provides the Security Zone resource in Oracle Cloud Infrastructure Cloud Guard service.
//
// Creates a security zone (SecurityZone resource) for a compartment. Pass parameters
// through a CreateSecurityZoneDetails resource.
//
// ## Example Usage
//
// ```go
// package main
//
// import (
//
//	"github.com/pulumi/pulumi-oci/sdk/v3/go/oci/cloudguard"
//	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
//
// )
//
//	func main() {
//		pulumi.Run(func(ctx *pulumi.Context) error {
//			_, err := cloudguard.NewSecurityZone(ctx, "test_security_zone", &cloudguard.SecurityZoneArgs{
//				CompartmentId:        pulumi.Any(compartmentId),
//				DisplayName:          pulumi.Any(securityZoneDisplayName),
//				SecurityZoneRecipeId: pulumi.Any(testSecurityZoneRecipe.Id),
//				DefinedTags: pulumi.StringMap{
//					"foo-namespace.bar-key": pulumi.String("value"),
//				},
//				Description: pulumi.Any(securityZoneDescription),
//				FreeformTags: pulumi.StringMap{
//					"bar-key": pulumi.String("value"),
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
// SecurityZones can be imported using the `id`, e.g.
//
// ```sh
// $ pulumi import oci:CloudGuard/securityZone:SecurityZone test_security_zone "id"
// ```
type SecurityZone struct {
	pulumi.CustomResourceState

	// (Updatable) The OCID of the compartment for the security zone
	CompartmentId pulumi.StringOutput `pulumi:"compartmentId"`
	// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
	DefinedTags pulumi.StringMapOutput `pulumi:"definedTags"`
	// (Updatable) The security zone's description
	Description pulumi.StringOutput `pulumi:"description"`
	// (Updatable) The security zone's display name
	DisplayName pulumi.StringOutput `pulumi:"displayName"`
	// (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
	//
	// Avoid entering confidential information.
	FreeformTags pulumi.StringMapOutput `pulumi:"freeformTags"`
	// List of inherited compartments
	InheritedByCompartments pulumi.StringArrayOutput `pulumi:"inheritedByCompartments"`
	// A message describing the current state in more detail. For example, this can be used to provide actionable information for a zone in the `Failed` state.
	LifecycleDetails pulumi.StringOutput `pulumi:"lifecycleDetails"`
	// (Updatable) The OCID of the security zone recipe (`SecurityRecipe` resource) for the security zone
	//
	// ** IMPORTANT **
	// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
	SecurityZoneRecipeId pulumi.StringOutput `pulumi:"securityZoneRecipeId"`
	// The OCID of the target associated with the security zone
	SecurityZoneTargetId pulumi.StringOutput `pulumi:"securityZoneTargetId"`
	// The current lifecycle state of the security zone
	State pulumi.StringOutput `pulumi:"state"`
	// The time the security zone was created. An RFC3339 formatted datetime string.
	TimeCreated pulumi.StringOutput `pulumi:"timeCreated"`
	// The time the security zone was last updated. An RFC3339 formatted datetime string.
	TimeUpdated pulumi.StringOutput `pulumi:"timeUpdated"`
}

// NewSecurityZone registers a new resource with the given unique name, arguments, and options.
func NewSecurityZone(ctx *pulumi.Context,
	name string, args *SecurityZoneArgs, opts ...pulumi.ResourceOption) (*SecurityZone, error) {
	if args == nil {
		return nil, errors.New("missing one or more required arguments")
	}

	if args.CompartmentId == nil {
		return nil, errors.New("invalid value for required argument 'CompartmentId'")
	}
	if args.DisplayName == nil {
		return nil, errors.New("invalid value for required argument 'DisplayName'")
	}
	if args.SecurityZoneRecipeId == nil {
		return nil, errors.New("invalid value for required argument 'SecurityZoneRecipeId'")
	}
	opts = internal.PkgResourceDefaultOpts(opts)
	var resource SecurityZone
	err := ctx.RegisterResource("oci:CloudGuard/securityZone:SecurityZone", name, args, &resource, opts...)
	if err != nil {
		return nil, err
	}
	return &resource, nil
}

// GetSecurityZone gets an existing SecurityZone resource's state with the given name, ID, and optional
// state properties that are used to uniquely qualify the lookup (nil if not required).
func GetSecurityZone(ctx *pulumi.Context,
	name string, id pulumi.IDInput, state *SecurityZoneState, opts ...pulumi.ResourceOption) (*SecurityZone, error) {
	var resource SecurityZone
	err := ctx.ReadResource("oci:CloudGuard/securityZone:SecurityZone", name, id, state, &resource, opts...)
	if err != nil {
		return nil, err
	}
	return &resource, nil
}

// Input properties used for looking up and filtering SecurityZone resources.
type securityZoneState struct {
	// (Updatable) The OCID of the compartment for the security zone
	CompartmentId *string `pulumi:"compartmentId"`
	// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
	DefinedTags map[string]string `pulumi:"definedTags"`
	// (Updatable) The security zone's description
	Description *string `pulumi:"description"`
	// (Updatable) The security zone's display name
	DisplayName *string `pulumi:"displayName"`
	// (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
	//
	// Avoid entering confidential information.
	FreeformTags map[string]string `pulumi:"freeformTags"`
	// List of inherited compartments
	InheritedByCompartments []string `pulumi:"inheritedByCompartments"`
	// A message describing the current state in more detail. For example, this can be used to provide actionable information for a zone in the `Failed` state.
	LifecycleDetails *string `pulumi:"lifecycleDetails"`
	// (Updatable) The OCID of the security zone recipe (`SecurityRecipe` resource) for the security zone
	//
	// ** IMPORTANT **
	// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
	SecurityZoneRecipeId *string `pulumi:"securityZoneRecipeId"`
	// The OCID of the target associated with the security zone
	SecurityZoneTargetId *string `pulumi:"securityZoneTargetId"`
	// The current lifecycle state of the security zone
	State *string `pulumi:"state"`
	// The time the security zone was created. An RFC3339 formatted datetime string.
	TimeCreated *string `pulumi:"timeCreated"`
	// The time the security zone was last updated. An RFC3339 formatted datetime string.
	TimeUpdated *string `pulumi:"timeUpdated"`
}

type SecurityZoneState struct {
	// (Updatable) The OCID of the compartment for the security zone
	CompartmentId pulumi.StringPtrInput
	// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
	DefinedTags pulumi.StringMapInput
	// (Updatable) The security zone's description
	Description pulumi.StringPtrInput
	// (Updatable) The security zone's display name
	DisplayName pulumi.StringPtrInput
	// (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
	//
	// Avoid entering confidential information.
	FreeformTags pulumi.StringMapInput
	// List of inherited compartments
	InheritedByCompartments pulumi.StringArrayInput
	// A message describing the current state in more detail. For example, this can be used to provide actionable information for a zone in the `Failed` state.
	LifecycleDetails pulumi.StringPtrInput
	// (Updatable) The OCID of the security zone recipe (`SecurityRecipe` resource) for the security zone
	//
	// ** IMPORTANT **
	// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
	SecurityZoneRecipeId pulumi.StringPtrInput
	// The OCID of the target associated with the security zone
	SecurityZoneTargetId pulumi.StringPtrInput
	// The current lifecycle state of the security zone
	State pulumi.StringPtrInput
	// The time the security zone was created. An RFC3339 formatted datetime string.
	TimeCreated pulumi.StringPtrInput
	// The time the security zone was last updated. An RFC3339 formatted datetime string.
	TimeUpdated pulumi.StringPtrInput
}

func (SecurityZoneState) ElementType() reflect.Type {
	return reflect.TypeOf((*securityZoneState)(nil)).Elem()
}

type securityZoneArgs struct {
	// (Updatable) The OCID of the compartment for the security zone
	CompartmentId string `pulumi:"compartmentId"`
	// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
	DefinedTags map[string]string `pulumi:"definedTags"`
	// (Updatable) The security zone's description
	Description *string `pulumi:"description"`
	// (Updatable) The security zone's display name
	DisplayName string `pulumi:"displayName"`
	// (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
	//
	// Avoid entering confidential information.
	FreeformTags map[string]string `pulumi:"freeformTags"`
	// (Updatable) The OCID of the security zone recipe (`SecurityRecipe` resource) for the security zone
	//
	// ** IMPORTANT **
	// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
	SecurityZoneRecipeId string `pulumi:"securityZoneRecipeId"`
}

// The set of arguments for constructing a SecurityZone resource.
type SecurityZoneArgs struct {
	// (Updatable) The OCID of the compartment for the security zone
	CompartmentId pulumi.StringInput
	// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
	DefinedTags pulumi.StringMapInput
	// (Updatable) The security zone's description
	Description pulumi.StringPtrInput
	// (Updatable) The security zone's display name
	DisplayName pulumi.StringInput
	// (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
	//
	// Avoid entering confidential information.
	FreeformTags pulumi.StringMapInput
	// (Updatable) The OCID of the security zone recipe (`SecurityRecipe` resource) for the security zone
	//
	// ** IMPORTANT **
	// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
	SecurityZoneRecipeId pulumi.StringInput
}

func (SecurityZoneArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*securityZoneArgs)(nil)).Elem()
}

type SecurityZoneInput interface {
	pulumi.Input

	ToSecurityZoneOutput() SecurityZoneOutput
	ToSecurityZoneOutputWithContext(ctx context.Context) SecurityZoneOutput
}

func (*SecurityZone) ElementType() reflect.Type {
	return reflect.TypeOf((**SecurityZone)(nil)).Elem()
}

func (i *SecurityZone) ToSecurityZoneOutput() SecurityZoneOutput {
	return i.ToSecurityZoneOutputWithContext(context.Background())
}

func (i *SecurityZone) ToSecurityZoneOutputWithContext(ctx context.Context) SecurityZoneOutput {
	return pulumi.ToOutputWithContext(ctx, i).(SecurityZoneOutput)
}

// SecurityZoneArrayInput is an input type that accepts SecurityZoneArray and SecurityZoneArrayOutput values.
// You can construct a concrete instance of `SecurityZoneArrayInput` via:
//
//	SecurityZoneArray{ SecurityZoneArgs{...} }
type SecurityZoneArrayInput interface {
	pulumi.Input

	ToSecurityZoneArrayOutput() SecurityZoneArrayOutput
	ToSecurityZoneArrayOutputWithContext(context.Context) SecurityZoneArrayOutput
}

type SecurityZoneArray []SecurityZoneInput

func (SecurityZoneArray) ElementType() reflect.Type {
	return reflect.TypeOf((*[]*SecurityZone)(nil)).Elem()
}

func (i SecurityZoneArray) ToSecurityZoneArrayOutput() SecurityZoneArrayOutput {
	return i.ToSecurityZoneArrayOutputWithContext(context.Background())
}

func (i SecurityZoneArray) ToSecurityZoneArrayOutputWithContext(ctx context.Context) SecurityZoneArrayOutput {
	return pulumi.ToOutputWithContext(ctx, i).(SecurityZoneArrayOutput)
}

// SecurityZoneMapInput is an input type that accepts SecurityZoneMap and SecurityZoneMapOutput values.
// You can construct a concrete instance of `SecurityZoneMapInput` via:
//
//	SecurityZoneMap{ "key": SecurityZoneArgs{...} }
type SecurityZoneMapInput interface {
	pulumi.Input

	ToSecurityZoneMapOutput() SecurityZoneMapOutput
	ToSecurityZoneMapOutputWithContext(context.Context) SecurityZoneMapOutput
}

type SecurityZoneMap map[string]SecurityZoneInput

func (SecurityZoneMap) ElementType() reflect.Type {
	return reflect.TypeOf((*map[string]*SecurityZone)(nil)).Elem()
}

func (i SecurityZoneMap) ToSecurityZoneMapOutput() SecurityZoneMapOutput {
	return i.ToSecurityZoneMapOutputWithContext(context.Background())
}

func (i SecurityZoneMap) ToSecurityZoneMapOutputWithContext(ctx context.Context) SecurityZoneMapOutput {
	return pulumi.ToOutputWithContext(ctx, i).(SecurityZoneMapOutput)
}

type SecurityZoneOutput struct{ *pulumi.OutputState }

func (SecurityZoneOutput) ElementType() reflect.Type {
	return reflect.TypeOf((**SecurityZone)(nil)).Elem()
}

func (o SecurityZoneOutput) ToSecurityZoneOutput() SecurityZoneOutput {
	return o
}

func (o SecurityZoneOutput) ToSecurityZoneOutputWithContext(ctx context.Context) SecurityZoneOutput {
	return o
}

// (Updatable) The OCID of the compartment for the security zone
func (o SecurityZoneOutput) CompartmentId() pulumi.StringOutput {
	return o.ApplyT(func(v *SecurityZone) pulumi.StringOutput { return v.CompartmentId }).(pulumi.StringOutput)
}

// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
func (o SecurityZoneOutput) DefinedTags() pulumi.StringMapOutput {
	return o.ApplyT(func(v *SecurityZone) pulumi.StringMapOutput { return v.DefinedTags }).(pulumi.StringMapOutput)
}

// (Updatable) The security zone's description
func (o SecurityZoneOutput) Description() pulumi.StringOutput {
	return o.ApplyT(func(v *SecurityZone) pulumi.StringOutput { return v.Description }).(pulumi.StringOutput)
}

// (Updatable) The security zone's display name
func (o SecurityZoneOutput) DisplayName() pulumi.StringOutput {
	return o.ApplyT(func(v *SecurityZone) pulumi.StringOutput { return v.DisplayName }).(pulumi.StringOutput)
}

// (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
//
// Avoid entering confidential information.
func (o SecurityZoneOutput) FreeformTags() pulumi.StringMapOutput {
	return o.ApplyT(func(v *SecurityZone) pulumi.StringMapOutput { return v.FreeformTags }).(pulumi.StringMapOutput)
}

// List of inherited compartments
func (o SecurityZoneOutput) InheritedByCompartments() pulumi.StringArrayOutput {
	return o.ApplyT(func(v *SecurityZone) pulumi.StringArrayOutput { return v.InheritedByCompartments }).(pulumi.StringArrayOutput)
}

// A message describing the current state in more detail. For example, this can be used to provide actionable information for a zone in the `Failed` state.
func (o SecurityZoneOutput) LifecycleDetails() pulumi.StringOutput {
	return o.ApplyT(func(v *SecurityZone) pulumi.StringOutput { return v.LifecycleDetails }).(pulumi.StringOutput)
}

// (Updatable) The OCID of the security zone recipe (`SecurityRecipe` resource) for the security zone
//
// ** IMPORTANT **
// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
func (o SecurityZoneOutput) SecurityZoneRecipeId() pulumi.StringOutput {
	return o.ApplyT(func(v *SecurityZone) pulumi.StringOutput { return v.SecurityZoneRecipeId }).(pulumi.StringOutput)
}

// The OCID of the target associated with the security zone
func (o SecurityZoneOutput) SecurityZoneTargetId() pulumi.StringOutput {
	return o.ApplyT(func(v *SecurityZone) pulumi.StringOutput { return v.SecurityZoneTargetId }).(pulumi.StringOutput)
}

// The current lifecycle state of the security zone
func (o SecurityZoneOutput) State() pulumi.StringOutput {
	return o.ApplyT(func(v *SecurityZone) pulumi.StringOutput { return v.State }).(pulumi.StringOutput)
}

// The time the security zone was created. An RFC3339 formatted datetime string.
func (o SecurityZoneOutput) TimeCreated() pulumi.StringOutput {
	return o.ApplyT(func(v *SecurityZone) pulumi.StringOutput { return v.TimeCreated }).(pulumi.StringOutput)
}

// The time the security zone was last updated. An RFC3339 formatted datetime string.
func (o SecurityZoneOutput) TimeUpdated() pulumi.StringOutput {
	return o.ApplyT(func(v *SecurityZone) pulumi.StringOutput { return v.TimeUpdated }).(pulumi.StringOutput)
}

type SecurityZoneArrayOutput struct{ *pulumi.OutputState }

func (SecurityZoneArrayOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*[]*SecurityZone)(nil)).Elem()
}

func (o SecurityZoneArrayOutput) ToSecurityZoneArrayOutput() SecurityZoneArrayOutput {
	return o
}

func (o SecurityZoneArrayOutput) ToSecurityZoneArrayOutputWithContext(ctx context.Context) SecurityZoneArrayOutput {
	return o
}

func (o SecurityZoneArrayOutput) Index(i pulumi.IntInput) SecurityZoneOutput {
	return pulumi.All(o, i).ApplyT(func(vs []interface{}) *SecurityZone {
		return vs[0].([]*SecurityZone)[vs[1].(int)]
	}).(SecurityZoneOutput)
}

type SecurityZoneMapOutput struct{ *pulumi.OutputState }

func (SecurityZoneMapOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*map[string]*SecurityZone)(nil)).Elem()
}

func (o SecurityZoneMapOutput) ToSecurityZoneMapOutput() SecurityZoneMapOutput {
	return o
}

func (o SecurityZoneMapOutput) ToSecurityZoneMapOutputWithContext(ctx context.Context) SecurityZoneMapOutput {
	return o
}

func (o SecurityZoneMapOutput) MapIndex(k pulumi.StringInput) SecurityZoneOutput {
	return pulumi.All(o, k).ApplyT(func(vs []interface{}) *SecurityZone {
		return vs[0].(map[string]*SecurityZone)[vs[1].(string)]
	}).(SecurityZoneOutput)
}

func init() {
	pulumi.RegisterInputType(reflect.TypeOf((*SecurityZoneInput)(nil)).Elem(), &SecurityZone{})
	pulumi.RegisterInputType(reflect.TypeOf((*SecurityZoneArrayInput)(nil)).Elem(), SecurityZoneArray{})
	pulumi.RegisterInputType(reflect.TypeOf((*SecurityZoneMapInput)(nil)).Elem(), SecurityZoneMap{})
	pulumi.RegisterOutputType(SecurityZoneOutput{})
	pulumi.RegisterOutputType(SecurityZoneArrayOutput{})
	pulumi.RegisterOutputType(SecurityZoneMapOutput{})
}
