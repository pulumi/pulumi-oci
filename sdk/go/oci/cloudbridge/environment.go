// Code generated by pulumi-language-go DO NOT EDIT.
// *** WARNING: Do not edit by hand unless you're certain you know what you are doing! ***

package cloudbridge

import (
	"context"
	"reflect"

	"errors"
	"github.com/pulumi/pulumi-oci/sdk/v3/go/oci/internal"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This resource provides the Environment resource in Oracle Cloud Infrastructure Cloud Bridge service.
//
// Creates a source environment.
//
// ## Example Usage
//
// ```go
// package main
//
// import (
//
//	"github.com/pulumi/pulumi-oci/sdk/v3/go/oci/cloudbridge"
//	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
//
// )
//
//	func main() {
//		pulumi.Run(func(ctx *pulumi.Context) error {
//			_, err := cloudbridge.NewEnvironment(ctx, "test_environment", &cloudbridge.EnvironmentArgs{
//				CompartmentId: pulumi.Any(compartmentId),
//				DefinedTags: pulumi.StringMap{
//					"Operations.CostCenter": pulumi.String("42"),
//				},
//				DisplayName: pulumi.Any(environmentDisplayName),
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
// Environments can be imported using the `id`, e.g.
//
// ```sh
// $ pulumi import oci:CloudBridge/environment:Environment test_environment "id"
// ```
type Environment struct {
	pulumi.CustomResourceState

	// (Updatable) Compartment identifier.
	CompartmentId pulumi.StringOutput `pulumi:"compartmentId"`
	// (Updatable) The defined tags associated with this resource, if any. Each key is predefined and scoped to namespaces. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Operations.CostCenter": "42"}`
	DefinedTags pulumi.StringMapOutput `pulumi:"definedTags"`
	// (Updatable) Environment identifier.
	DisplayName pulumi.StringOutput `pulumi:"displayName"`
	// (Updatable) The freeform tags associated with this resource, if any. Each tag is a simple key-value pair with no predefined name, type, or namespace/scope. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Department": "Finance"}`
	//
	// ** IMPORTANT **
	// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
	FreeformTags pulumi.StringMapOutput `pulumi:"freeformTags"`
	// A message describing the current state in more detail. For example, it can be used to provide actionable information for a resource in Failed state.
	LifecycleDetails pulumi.StringOutput `pulumi:"lifecycleDetails"`
	// The current state of the source environment.
	State pulumi.StringOutput `pulumi:"state"`
	// The system tags associated with this resource, if any. The system tags are set by Oracle cloud infrastructure services. Each key is predefined and scoped to namespaces. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{orcl-cloud: {free-tier-retain: true}}`
	SystemTags pulumi.StringMapOutput `pulumi:"systemTags"`
	// The time when the source environment was created. An RFC3339 formatted datetime string.
	TimeCreated pulumi.StringOutput `pulumi:"timeCreated"`
	// The time when the source environment was updated. An RFC3339 formatted datetime string.
	TimeUpdated pulumi.StringOutput `pulumi:"timeUpdated"`
}

// NewEnvironment registers a new resource with the given unique name, arguments, and options.
func NewEnvironment(ctx *pulumi.Context,
	name string, args *EnvironmentArgs, opts ...pulumi.ResourceOption) (*Environment, error) {
	if args == nil {
		return nil, errors.New("missing one or more required arguments")
	}

	if args.CompartmentId == nil {
		return nil, errors.New("invalid value for required argument 'CompartmentId'")
	}
	opts = internal.PkgResourceDefaultOpts(opts)
	var resource Environment
	err := ctx.RegisterResource("oci:CloudBridge/environment:Environment", name, args, &resource, opts...)
	if err != nil {
		return nil, err
	}
	return &resource, nil
}

// GetEnvironment gets an existing Environment resource's state with the given name, ID, and optional
// state properties that are used to uniquely qualify the lookup (nil if not required).
func GetEnvironment(ctx *pulumi.Context,
	name string, id pulumi.IDInput, state *EnvironmentState, opts ...pulumi.ResourceOption) (*Environment, error) {
	var resource Environment
	err := ctx.ReadResource("oci:CloudBridge/environment:Environment", name, id, state, &resource, opts...)
	if err != nil {
		return nil, err
	}
	return &resource, nil
}

// Input properties used for looking up and filtering Environment resources.
type environmentState struct {
	// (Updatable) Compartment identifier.
	CompartmentId *string `pulumi:"compartmentId"`
	// (Updatable) The defined tags associated with this resource, if any. Each key is predefined and scoped to namespaces. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Operations.CostCenter": "42"}`
	DefinedTags map[string]string `pulumi:"definedTags"`
	// (Updatable) Environment identifier.
	DisplayName *string `pulumi:"displayName"`
	// (Updatable) The freeform tags associated with this resource, if any. Each tag is a simple key-value pair with no predefined name, type, or namespace/scope. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Department": "Finance"}`
	//
	// ** IMPORTANT **
	// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
	FreeformTags map[string]string `pulumi:"freeformTags"`
	// A message describing the current state in more detail. For example, it can be used to provide actionable information for a resource in Failed state.
	LifecycleDetails *string `pulumi:"lifecycleDetails"`
	// The current state of the source environment.
	State *string `pulumi:"state"`
	// The system tags associated with this resource, if any. The system tags are set by Oracle cloud infrastructure services. Each key is predefined and scoped to namespaces. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{orcl-cloud: {free-tier-retain: true}}`
	SystemTags map[string]string `pulumi:"systemTags"`
	// The time when the source environment was created. An RFC3339 formatted datetime string.
	TimeCreated *string `pulumi:"timeCreated"`
	// The time when the source environment was updated. An RFC3339 formatted datetime string.
	TimeUpdated *string `pulumi:"timeUpdated"`
}

type EnvironmentState struct {
	// (Updatable) Compartment identifier.
	CompartmentId pulumi.StringPtrInput
	// (Updatable) The defined tags associated with this resource, if any. Each key is predefined and scoped to namespaces. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Operations.CostCenter": "42"}`
	DefinedTags pulumi.StringMapInput
	// (Updatable) Environment identifier.
	DisplayName pulumi.StringPtrInput
	// (Updatable) The freeform tags associated with this resource, if any. Each tag is a simple key-value pair with no predefined name, type, or namespace/scope. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Department": "Finance"}`
	//
	// ** IMPORTANT **
	// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
	FreeformTags pulumi.StringMapInput
	// A message describing the current state in more detail. For example, it can be used to provide actionable information for a resource in Failed state.
	LifecycleDetails pulumi.StringPtrInput
	// The current state of the source environment.
	State pulumi.StringPtrInput
	// The system tags associated with this resource, if any. The system tags are set by Oracle cloud infrastructure services. Each key is predefined and scoped to namespaces. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{orcl-cloud: {free-tier-retain: true}}`
	SystemTags pulumi.StringMapInput
	// The time when the source environment was created. An RFC3339 formatted datetime string.
	TimeCreated pulumi.StringPtrInput
	// The time when the source environment was updated. An RFC3339 formatted datetime string.
	TimeUpdated pulumi.StringPtrInput
}

func (EnvironmentState) ElementType() reflect.Type {
	return reflect.TypeOf((*environmentState)(nil)).Elem()
}

type environmentArgs struct {
	// (Updatable) Compartment identifier.
	CompartmentId string `pulumi:"compartmentId"`
	// (Updatable) The defined tags associated with this resource, if any. Each key is predefined and scoped to namespaces. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Operations.CostCenter": "42"}`
	DefinedTags map[string]string `pulumi:"definedTags"`
	// (Updatable) Environment identifier.
	DisplayName *string `pulumi:"displayName"`
	// (Updatable) The freeform tags associated with this resource, if any. Each tag is a simple key-value pair with no predefined name, type, or namespace/scope. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Department": "Finance"}`
	//
	// ** IMPORTANT **
	// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
	FreeformTags map[string]string `pulumi:"freeformTags"`
}

// The set of arguments for constructing a Environment resource.
type EnvironmentArgs struct {
	// (Updatable) Compartment identifier.
	CompartmentId pulumi.StringInput
	// (Updatable) The defined tags associated with this resource, if any. Each key is predefined and scoped to namespaces. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Operations.CostCenter": "42"}`
	DefinedTags pulumi.StringMapInput
	// (Updatable) Environment identifier.
	DisplayName pulumi.StringPtrInput
	// (Updatable) The freeform tags associated with this resource, if any. Each tag is a simple key-value pair with no predefined name, type, or namespace/scope. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Department": "Finance"}`
	//
	// ** IMPORTANT **
	// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
	FreeformTags pulumi.StringMapInput
}

func (EnvironmentArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*environmentArgs)(nil)).Elem()
}

type EnvironmentInput interface {
	pulumi.Input

	ToEnvironmentOutput() EnvironmentOutput
	ToEnvironmentOutputWithContext(ctx context.Context) EnvironmentOutput
}

func (*Environment) ElementType() reflect.Type {
	return reflect.TypeOf((**Environment)(nil)).Elem()
}

func (i *Environment) ToEnvironmentOutput() EnvironmentOutput {
	return i.ToEnvironmentOutputWithContext(context.Background())
}

func (i *Environment) ToEnvironmentOutputWithContext(ctx context.Context) EnvironmentOutput {
	return pulumi.ToOutputWithContext(ctx, i).(EnvironmentOutput)
}

// EnvironmentArrayInput is an input type that accepts EnvironmentArray and EnvironmentArrayOutput values.
// You can construct a concrete instance of `EnvironmentArrayInput` via:
//
//	EnvironmentArray{ EnvironmentArgs{...} }
type EnvironmentArrayInput interface {
	pulumi.Input

	ToEnvironmentArrayOutput() EnvironmentArrayOutput
	ToEnvironmentArrayOutputWithContext(context.Context) EnvironmentArrayOutput
}

type EnvironmentArray []EnvironmentInput

func (EnvironmentArray) ElementType() reflect.Type {
	return reflect.TypeOf((*[]*Environment)(nil)).Elem()
}

func (i EnvironmentArray) ToEnvironmentArrayOutput() EnvironmentArrayOutput {
	return i.ToEnvironmentArrayOutputWithContext(context.Background())
}

func (i EnvironmentArray) ToEnvironmentArrayOutputWithContext(ctx context.Context) EnvironmentArrayOutput {
	return pulumi.ToOutputWithContext(ctx, i).(EnvironmentArrayOutput)
}

// EnvironmentMapInput is an input type that accepts EnvironmentMap and EnvironmentMapOutput values.
// You can construct a concrete instance of `EnvironmentMapInput` via:
//
//	EnvironmentMap{ "key": EnvironmentArgs{...} }
type EnvironmentMapInput interface {
	pulumi.Input

	ToEnvironmentMapOutput() EnvironmentMapOutput
	ToEnvironmentMapOutputWithContext(context.Context) EnvironmentMapOutput
}

type EnvironmentMap map[string]EnvironmentInput

func (EnvironmentMap) ElementType() reflect.Type {
	return reflect.TypeOf((*map[string]*Environment)(nil)).Elem()
}

func (i EnvironmentMap) ToEnvironmentMapOutput() EnvironmentMapOutput {
	return i.ToEnvironmentMapOutputWithContext(context.Background())
}

func (i EnvironmentMap) ToEnvironmentMapOutputWithContext(ctx context.Context) EnvironmentMapOutput {
	return pulumi.ToOutputWithContext(ctx, i).(EnvironmentMapOutput)
}

type EnvironmentOutput struct{ *pulumi.OutputState }

func (EnvironmentOutput) ElementType() reflect.Type {
	return reflect.TypeOf((**Environment)(nil)).Elem()
}

func (o EnvironmentOutput) ToEnvironmentOutput() EnvironmentOutput {
	return o
}

func (o EnvironmentOutput) ToEnvironmentOutputWithContext(ctx context.Context) EnvironmentOutput {
	return o
}

// (Updatable) Compartment identifier.
func (o EnvironmentOutput) CompartmentId() pulumi.StringOutput {
	return o.ApplyT(func(v *Environment) pulumi.StringOutput { return v.CompartmentId }).(pulumi.StringOutput)
}

// (Updatable) The defined tags associated with this resource, if any. Each key is predefined and scoped to namespaces. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Operations.CostCenter": "42"}`
func (o EnvironmentOutput) DefinedTags() pulumi.StringMapOutput {
	return o.ApplyT(func(v *Environment) pulumi.StringMapOutput { return v.DefinedTags }).(pulumi.StringMapOutput)
}

// (Updatable) Environment identifier.
func (o EnvironmentOutput) DisplayName() pulumi.StringOutput {
	return o.ApplyT(func(v *Environment) pulumi.StringOutput { return v.DisplayName }).(pulumi.StringOutput)
}

// (Updatable) The freeform tags associated with this resource, if any. Each tag is a simple key-value pair with no predefined name, type, or namespace/scope. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Department": "Finance"}`
//
// ** IMPORTANT **
// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
func (o EnvironmentOutput) FreeformTags() pulumi.StringMapOutput {
	return o.ApplyT(func(v *Environment) pulumi.StringMapOutput { return v.FreeformTags }).(pulumi.StringMapOutput)
}

// A message describing the current state in more detail. For example, it can be used to provide actionable information for a resource in Failed state.
func (o EnvironmentOutput) LifecycleDetails() pulumi.StringOutput {
	return o.ApplyT(func(v *Environment) pulumi.StringOutput { return v.LifecycleDetails }).(pulumi.StringOutput)
}

// The current state of the source environment.
func (o EnvironmentOutput) State() pulumi.StringOutput {
	return o.ApplyT(func(v *Environment) pulumi.StringOutput { return v.State }).(pulumi.StringOutput)
}

// The system tags associated with this resource, if any. The system tags are set by Oracle cloud infrastructure services. Each key is predefined and scoped to namespaces. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{orcl-cloud: {free-tier-retain: true}}`
func (o EnvironmentOutput) SystemTags() pulumi.StringMapOutput {
	return o.ApplyT(func(v *Environment) pulumi.StringMapOutput { return v.SystemTags }).(pulumi.StringMapOutput)
}

// The time when the source environment was created. An RFC3339 formatted datetime string.
func (o EnvironmentOutput) TimeCreated() pulumi.StringOutput {
	return o.ApplyT(func(v *Environment) pulumi.StringOutput { return v.TimeCreated }).(pulumi.StringOutput)
}

// The time when the source environment was updated. An RFC3339 formatted datetime string.
func (o EnvironmentOutput) TimeUpdated() pulumi.StringOutput {
	return o.ApplyT(func(v *Environment) pulumi.StringOutput { return v.TimeUpdated }).(pulumi.StringOutput)
}

type EnvironmentArrayOutput struct{ *pulumi.OutputState }

func (EnvironmentArrayOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*[]*Environment)(nil)).Elem()
}

func (o EnvironmentArrayOutput) ToEnvironmentArrayOutput() EnvironmentArrayOutput {
	return o
}

func (o EnvironmentArrayOutput) ToEnvironmentArrayOutputWithContext(ctx context.Context) EnvironmentArrayOutput {
	return o
}

func (o EnvironmentArrayOutput) Index(i pulumi.IntInput) EnvironmentOutput {
	return pulumi.All(o, i).ApplyT(func(vs []interface{}) *Environment {
		return vs[0].([]*Environment)[vs[1].(int)]
	}).(EnvironmentOutput)
}

type EnvironmentMapOutput struct{ *pulumi.OutputState }

func (EnvironmentMapOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*map[string]*Environment)(nil)).Elem()
}

func (o EnvironmentMapOutput) ToEnvironmentMapOutput() EnvironmentMapOutput {
	return o
}

func (o EnvironmentMapOutput) ToEnvironmentMapOutputWithContext(ctx context.Context) EnvironmentMapOutput {
	return o
}

func (o EnvironmentMapOutput) MapIndex(k pulumi.StringInput) EnvironmentOutput {
	return pulumi.All(o, k).ApplyT(func(vs []interface{}) *Environment {
		return vs[0].(map[string]*Environment)[vs[1].(string)]
	}).(EnvironmentOutput)
}

func init() {
	pulumi.RegisterInputType(reflect.TypeOf((*EnvironmentInput)(nil)).Elem(), &Environment{})
	pulumi.RegisterInputType(reflect.TypeOf((*EnvironmentArrayInput)(nil)).Elem(), EnvironmentArray{})
	pulumi.RegisterInputType(reflect.TypeOf((*EnvironmentMapInput)(nil)).Elem(), EnvironmentMap{})
	pulumi.RegisterOutputType(EnvironmentOutput{})
	pulumi.RegisterOutputType(EnvironmentArrayOutput{})
	pulumi.RegisterOutputType(EnvironmentMapOutput{})
}
