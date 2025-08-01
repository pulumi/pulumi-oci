// Code generated by pulumi-language-go DO NOT EDIT.
// *** WARNING: Do not edit by hand unless you're certain you know what you are doing! ***

package capacitymanagement

import (
	"context"
	"reflect"

	"errors"
	"github.com/pulumi/pulumi-oci/sdk/v3/go/oci/internal"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This resource provides the Occm Demand Signal resource in Oracle Cloud Infrastructure Capacity Management service.
//
// This is a post API to create occm demand signal.
//
// ## Example Usage
//
// ```go
// package main
//
// import (
//
//	"github.com/pulumi/pulumi-oci/sdk/v3/go/oci/capacitymanagement"
//	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
//
// )
//
//	func main() {
//		pulumi.Run(func(ctx *pulumi.Context) error {
//			_, err := capacitymanagement.NewOccmDemandSignal(ctx, "test_occm_demand_signal", &capacitymanagement.OccmDemandSignalArgs{
//				CompartmentId: pulumi.Any(compartmentId),
//				DisplayName:   pulumi.Any(occmDemandSignalDisplayName),
//				DefinedTags: pulumi.StringMap{
//					"foo-namespace.bar-key": pulumi.String("value"),
//				},
//				Description: pulumi.Any(occmDemandSignalDescription),
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
// OccmDemandSignals can be imported using the `id`, e.g.
//
// ```sh
// $ pulumi import oci:CapacityManagement/occmDemandSignal:OccmDemandSignal test_occm_demand_signal "id"
// ```
type OccmDemandSignal struct {
	pulumi.CustomResourceState

	// The OCID of the tenancy where we would like to create a demand signal.
	CompartmentId pulumi.StringOutput `pulumi:"compartmentId"`
	// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
	DefinedTags pulumi.StringMapOutput `pulumi:"definedTags"`
	// (Updatable) A short description of the demand signal.
	Description pulumi.StringOutput `pulumi:"description"`
	// (Updatable) The user-friendly name of the demand signal. Does not have to be unique. Avoid entering anything confidential.
	DisplayName pulumi.StringOutput `pulumi:"displayName"`
	// (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
	//
	// ** IMPORTANT **
	// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
	FreeformTags pulumi.StringMapOutput `pulumi:"freeformTags"`
	// The different states associated with a demand signal.
	LifecycleDetails pulumi.StringOutput `pulumi:"lifecycleDetails"`
	// The current lifecycle state of the resource.
	State pulumi.StringOutput `pulumi:"state"`
	// System tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"orcl-cloud.free-tier-retained": "true"}`
	SystemTags pulumi.StringMapOutput `pulumi:"systemTags"`
	// The time when the demand signal was created.
	TimeCreated pulumi.StringOutput `pulumi:"timeCreated"`
	// The time when the demand signal was last updated.
	TimeUpdated pulumi.StringOutput `pulumi:"timeUpdated"`
}

// NewOccmDemandSignal registers a new resource with the given unique name, arguments, and options.
func NewOccmDemandSignal(ctx *pulumi.Context,
	name string, args *OccmDemandSignalArgs, opts ...pulumi.ResourceOption) (*OccmDemandSignal, error) {
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
	var resource OccmDemandSignal
	err := ctx.RegisterResource("oci:CapacityManagement/occmDemandSignal:OccmDemandSignal", name, args, &resource, opts...)
	if err != nil {
		return nil, err
	}
	return &resource, nil
}

// GetOccmDemandSignal gets an existing OccmDemandSignal resource's state with the given name, ID, and optional
// state properties that are used to uniquely qualify the lookup (nil if not required).
func GetOccmDemandSignal(ctx *pulumi.Context,
	name string, id pulumi.IDInput, state *OccmDemandSignalState, opts ...pulumi.ResourceOption) (*OccmDemandSignal, error) {
	var resource OccmDemandSignal
	err := ctx.ReadResource("oci:CapacityManagement/occmDemandSignal:OccmDemandSignal", name, id, state, &resource, opts...)
	if err != nil {
		return nil, err
	}
	return &resource, nil
}

// Input properties used for looking up and filtering OccmDemandSignal resources.
type occmDemandSignalState struct {
	// The OCID of the tenancy where we would like to create a demand signal.
	CompartmentId *string `pulumi:"compartmentId"`
	// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
	DefinedTags map[string]string `pulumi:"definedTags"`
	// (Updatable) A short description of the demand signal.
	Description *string `pulumi:"description"`
	// (Updatable) The user-friendly name of the demand signal. Does not have to be unique. Avoid entering anything confidential.
	DisplayName *string `pulumi:"displayName"`
	// (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
	//
	// ** IMPORTANT **
	// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
	FreeformTags map[string]string `pulumi:"freeformTags"`
	// The different states associated with a demand signal.
	LifecycleDetails *string `pulumi:"lifecycleDetails"`
	// The current lifecycle state of the resource.
	State *string `pulumi:"state"`
	// System tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"orcl-cloud.free-tier-retained": "true"}`
	SystemTags map[string]string `pulumi:"systemTags"`
	// The time when the demand signal was created.
	TimeCreated *string `pulumi:"timeCreated"`
	// The time when the demand signal was last updated.
	TimeUpdated *string `pulumi:"timeUpdated"`
}

type OccmDemandSignalState struct {
	// The OCID of the tenancy where we would like to create a demand signal.
	CompartmentId pulumi.StringPtrInput
	// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
	DefinedTags pulumi.StringMapInput
	// (Updatable) A short description of the demand signal.
	Description pulumi.StringPtrInput
	// (Updatable) The user-friendly name of the demand signal. Does not have to be unique. Avoid entering anything confidential.
	DisplayName pulumi.StringPtrInput
	// (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
	//
	// ** IMPORTANT **
	// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
	FreeformTags pulumi.StringMapInput
	// The different states associated with a demand signal.
	LifecycleDetails pulumi.StringPtrInput
	// The current lifecycle state of the resource.
	State pulumi.StringPtrInput
	// System tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"orcl-cloud.free-tier-retained": "true"}`
	SystemTags pulumi.StringMapInput
	// The time when the demand signal was created.
	TimeCreated pulumi.StringPtrInput
	// The time when the demand signal was last updated.
	TimeUpdated pulumi.StringPtrInput
}

func (OccmDemandSignalState) ElementType() reflect.Type {
	return reflect.TypeOf((*occmDemandSignalState)(nil)).Elem()
}

type occmDemandSignalArgs struct {
	// The OCID of the tenancy where we would like to create a demand signal.
	CompartmentId string `pulumi:"compartmentId"`
	// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
	DefinedTags map[string]string `pulumi:"definedTags"`
	// (Updatable) A short description of the demand signal.
	Description *string `pulumi:"description"`
	// (Updatable) The user-friendly name of the demand signal. Does not have to be unique. Avoid entering anything confidential.
	DisplayName string `pulumi:"displayName"`
	// (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
	//
	// ** IMPORTANT **
	// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
	FreeformTags map[string]string `pulumi:"freeformTags"`
	// The different states associated with a demand signal.
	LifecycleDetails *string `pulumi:"lifecycleDetails"`
}

// The set of arguments for constructing a OccmDemandSignal resource.
type OccmDemandSignalArgs struct {
	// The OCID of the tenancy where we would like to create a demand signal.
	CompartmentId pulumi.StringInput
	// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
	DefinedTags pulumi.StringMapInput
	// (Updatable) A short description of the demand signal.
	Description pulumi.StringPtrInput
	// (Updatable) The user-friendly name of the demand signal. Does not have to be unique. Avoid entering anything confidential.
	DisplayName pulumi.StringInput
	// (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
	//
	// ** IMPORTANT **
	// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
	FreeformTags pulumi.StringMapInput
	// The different states associated with a demand signal.
	LifecycleDetails pulumi.StringPtrInput
}

func (OccmDemandSignalArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*occmDemandSignalArgs)(nil)).Elem()
}

type OccmDemandSignalInput interface {
	pulumi.Input

	ToOccmDemandSignalOutput() OccmDemandSignalOutput
	ToOccmDemandSignalOutputWithContext(ctx context.Context) OccmDemandSignalOutput
}

func (*OccmDemandSignal) ElementType() reflect.Type {
	return reflect.TypeOf((**OccmDemandSignal)(nil)).Elem()
}

func (i *OccmDemandSignal) ToOccmDemandSignalOutput() OccmDemandSignalOutput {
	return i.ToOccmDemandSignalOutputWithContext(context.Background())
}

func (i *OccmDemandSignal) ToOccmDemandSignalOutputWithContext(ctx context.Context) OccmDemandSignalOutput {
	return pulumi.ToOutputWithContext(ctx, i).(OccmDemandSignalOutput)
}

// OccmDemandSignalArrayInput is an input type that accepts OccmDemandSignalArray and OccmDemandSignalArrayOutput values.
// You can construct a concrete instance of `OccmDemandSignalArrayInput` via:
//
//	OccmDemandSignalArray{ OccmDemandSignalArgs{...} }
type OccmDemandSignalArrayInput interface {
	pulumi.Input

	ToOccmDemandSignalArrayOutput() OccmDemandSignalArrayOutput
	ToOccmDemandSignalArrayOutputWithContext(context.Context) OccmDemandSignalArrayOutput
}

type OccmDemandSignalArray []OccmDemandSignalInput

func (OccmDemandSignalArray) ElementType() reflect.Type {
	return reflect.TypeOf((*[]*OccmDemandSignal)(nil)).Elem()
}

func (i OccmDemandSignalArray) ToOccmDemandSignalArrayOutput() OccmDemandSignalArrayOutput {
	return i.ToOccmDemandSignalArrayOutputWithContext(context.Background())
}

func (i OccmDemandSignalArray) ToOccmDemandSignalArrayOutputWithContext(ctx context.Context) OccmDemandSignalArrayOutput {
	return pulumi.ToOutputWithContext(ctx, i).(OccmDemandSignalArrayOutput)
}

// OccmDemandSignalMapInput is an input type that accepts OccmDemandSignalMap and OccmDemandSignalMapOutput values.
// You can construct a concrete instance of `OccmDemandSignalMapInput` via:
//
//	OccmDemandSignalMap{ "key": OccmDemandSignalArgs{...} }
type OccmDemandSignalMapInput interface {
	pulumi.Input

	ToOccmDemandSignalMapOutput() OccmDemandSignalMapOutput
	ToOccmDemandSignalMapOutputWithContext(context.Context) OccmDemandSignalMapOutput
}

type OccmDemandSignalMap map[string]OccmDemandSignalInput

func (OccmDemandSignalMap) ElementType() reflect.Type {
	return reflect.TypeOf((*map[string]*OccmDemandSignal)(nil)).Elem()
}

func (i OccmDemandSignalMap) ToOccmDemandSignalMapOutput() OccmDemandSignalMapOutput {
	return i.ToOccmDemandSignalMapOutputWithContext(context.Background())
}

func (i OccmDemandSignalMap) ToOccmDemandSignalMapOutputWithContext(ctx context.Context) OccmDemandSignalMapOutput {
	return pulumi.ToOutputWithContext(ctx, i).(OccmDemandSignalMapOutput)
}

type OccmDemandSignalOutput struct{ *pulumi.OutputState }

func (OccmDemandSignalOutput) ElementType() reflect.Type {
	return reflect.TypeOf((**OccmDemandSignal)(nil)).Elem()
}

func (o OccmDemandSignalOutput) ToOccmDemandSignalOutput() OccmDemandSignalOutput {
	return o
}

func (o OccmDemandSignalOutput) ToOccmDemandSignalOutputWithContext(ctx context.Context) OccmDemandSignalOutput {
	return o
}

// The OCID of the tenancy where we would like to create a demand signal.
func (o OccmDemandSignalOutput) CompartmentId() pulumi.StringOutput {
	return o.ApplyT(func(v *OccmDemandSignal) pulumi.StringOutput { return v.CompartmentId }).(pulumi.StringOutput)
}

// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
func (o OccmDemandSignalOutput) DefinedTags() pulumi.StringMapOutput {
	return o.ApplyT(func(v *OccmDemandSignal) pulumi.StringMapOutput { return v.DefinedTags }).(pulumi.StringMapOutput)
}

// (Updatable) A short description of the demand signal.
func (o OccmDemandSignalOutput) Description() pulumi.StringOutput {
	return o.ApplyT(func(v *OccmDemandSignal) pulumi.StringOutput { return v.Description }).(pulumi.StringOutput)
}

// (Updatable) The user-friendly name of the demand signal. Does not have to be unique. Avoid entering anything confidential.
func (o OccmDemandSignalOutput) DisplayName() pulumi.StringOutput {
	return o.ApplyT(func(v *OccmDemandSignal) pulumi.StringOutput { return v.DisplayName }).(pulumi.StringOutput)
}

// (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
//
// ** IMPORTANT **
// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
func (o OccmDemandSignalOutput) FreeformTags() pulumi.StringMapOutput {
	return o.ApplyT(func(v *OccmDemandSignal) pulumi.StringMapOutput { return v.FreeformTags }).(pulumi.StringMapOutput)
}

// The different states associated with a demand signal.
func (o OccmDemandSignalOutput) LifecycleDetails() pulumi.StringOutput {
	return o.ApplyT(func(v *OccmDemandSignal) pulumi.StringOutput { return v.LifecycleDetails }).(pulumi.StringOutput)
}

// The current lifecycle state of the resource.
func (o OccmDemandSignalOutput) State() pulumi.StringOutput {
	return o.ApplyT(func(v *OccmDemandSignal) pulumi.StringOutput { return v.State }).(pulumi.StringOutput)
}

// System tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"orcl-cloud.free-tier-retained": "true"}`
func (o OccmDemandSignalOutput) SystemTags() pulumi.StringMapOutput {
	return o.ApplyT(func(v *OccmDemandSignal) pulumi.StringMapOutput { return v.SystemTags }).(pulumi.StringMapOutput)
}

// The time when the demand signal was created.
func (o OccmDemandSignalOutput) TimeCreated() pulumi.StringOutput {
	return o.ApplyT(func(v *OccmDemandSignal) pulumi.StringOutput { return v.TimeCreated }).(pulumi.StringOutput)
}

// The time when the demand signal was last updated.
func (o OccmDemandSignalOutput) TimeUpdated() pulumi.StringOutput {
	return o.ApplyT(func(v *OccmDemandSignal) pulumi.StringOutput { return v.TimeUpdated }).(pulumi.StringOutput)
}

type OccmDemandSignalArrayOutput struct{ *pulumi.OutputState }

func (OccmDemandSignalArrayOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*[]*OccmDemandSignal)(nil)).Elem()
}

func (o OccmDemandSignalArrayOutput) ToOccmDemandSignalArrayOutput() OccmDemandSignalArrayOutput {
	return o
}

func (o OccmDemandSignalArrayOutput) ToOccmDemandSignalArrayOutputWithContext(ctx context.Context) OccmDemandSignalArrayOutput {
	return o
}

func (o OccmDemandSignalArrayOutput) Index(i pulumi.IntInput) OccmDemandSignalOutput {
	return pulumi.All(o, i).ApplyT(func(vs []interface{}) *OccmDemandSignal {
		return vs[0].([]*OccmDemandSignal)[vs[1].(int)]
	}).(OccmDemandSignalOutput)
}

type OccmDemandSignalMapOutput struct{ *pulumi.OutputState }

func (OccmDemandSignalMapOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*map[string]*OccmDemandSignal)(nil)).Elem()
}

func (o OccmDemandSignalMapOutput) ToOccmDemandSignalMapOutput() OccmDemandSignalMapOutput {
	return o
}

func (o OccmDemandSignalMapOutput) ToOccmDemandSignalMapOutputWithContext(ctx context.Context) OccmDemandSignalMapOutput {
	return o
}

func (o OccmDemandSignalMapOutput) MapIndex(k pulumi.StringInput) OccmDemandSignalOutput {
	return pulumi.All(o, k).ApplyT(func(vs []interface{}) *OccmDemandSignal {
		return vs[0].(map[string]*OccmDemandSignal)[vs[1].(string)]
	}).(OccmDemandSignalOutput)
}

func init() {
	pulumi.RegisterInputType(reflect.TypeOf((*OccmDemandSignalInput)(nil)).Elem(), &OccmDemandSignal{})
	pulumi.RegisterInputType(reflect.TypeOf((*OccmDemandSignalArrayInput)(nil)).Elem(), OccmDemandSignalArray{})
	pulumi.RegisterInputType(reflect.TypeOf((*OccmDemandSignalMapInput)(nil)).Elem(), OccmDemandSignalMap{})
	pulumi.RegisterOutputType(OccmDemandSignalOutput{})
	pulumi.RegisterOutputType(OccmDemandSignalArrayOutput{})
	pulumi.RegisterOutputType(OccmDemandSignalMapOutput{})
}
