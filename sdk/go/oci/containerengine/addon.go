// Code generated by pulumi-language-go DO NOT EDIT.
// *** WARNING: Do not edit by hand unless you're certain you know what you are doing! ***

package containerengine

import (
	"context"
	"reflect"

	"errors"
	"github.com/pulumi/pulumi-oci/sdk/v3/go/oci/internal"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This resource provides the Addon resource in Oracle Cloud Infrastructure Container Engine service.
//
// Install the specified addon for a cluster.
//
// ## Import
//
// Addons can be imported using the `id`, e.g.
//
// ```sh
// $ pulumi import oci:ContainerEngine/addon:Addon test_addon "clusters/{clusterId}/addons/{addonName}"
// ```
type Addon struct {
	pulumi.CustomResourceState

	// The error info of the addon.
	AddonErrors AddonAddonErrorArrayOutput `pulumi:"addonErrors"`
	// The name of the addon.
	AddonName pulumi.StringOutput `pulumi:"addonName"`
	// The OCID of the cluster.
	ClusterId pulumi.StringOutput `pulumi:"clusterId"`
	// (Updatable) Addon configuration details
	Configurations AddonConfigurationArrayOutput `pulumi:"configurations"`
	// current installed version of the addon
	CurrentInstalledVersion pulumi.StringOutput `pulumi:"currentInstalledVersion"`
	// Whether or not to override an existing addon installation. Defaults to false. If set to true, any existing addon installation would be overridden as per new installation details.
	OverrideExisting pulumi.BoolPtrOutput `pulumi:"overrideExisting"`
	// Whether to remove addon resource in deletion.
	RemoveAddonResourcesOnDelete pulumi.BoolOutput `pulumi:"removeAddonResourcesOnDelete"`
	// The state of the addon.
	State pulumi.StringOutput `pulumi:"state"`
	// The time the cluster was created.
	TimeCreated pulumi.StringOutput `pulumi:"timeCreated"`
	// (Updatable) The version of addon to be installed.
	//
	// ** IMPORTANT **
	// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
	Version pulumi.StringPtrOutput `pulumi:"version"`
}

// NewAddon registers a new resource with the given unique name, arguments, and options.
func NewAddon(ctx *pulumi.Context,
	name string, args *AddonArgs, opts ...pulumi.ResourceOption) (*Addon, error) {
	if args == nil {
		return nil, errors.New("missing one or more required arguments")
	}

	if args.AddonName == nil {
		return nil, errors.New("invalid value for required argument 'AddonName'")
	}
	if args.ClusterId == nil {
		return nil, errors.New("invalid value for required argument 'ClusterId'")
	}
	if args.RemoveAddonResourcesOnDelete == nil {
		return nil, errors.New("invalid value for required argument 'RemoveAddonResourcesOnDelete'")
	}
	opts = internal.PkgResourceDefaultOpts(opts)
	var resource Addon
	err := ctx.RegisterResource("oci:ContainerEngine/addon:Addon", name, args, &resource, opts...)
	if err != nil {
		return nil, err
	}
	return &resource, nil
}

// GetAddon gets an existing Addon resource's state with the given name, ID, and optional
// state properties that are used to uniquely qualify the lookup (nil if not required).
func GetAddon(ctx *pulumi.Context,
	name string, id pulumi.IDInput, state *AddonState, opts ...pulumi.ResourceOption) (*Addon, error) {
	var resource Addon
	err := ctx.ReadResource("oci:ContainerEngine/addon:Addon", name, id, state, &resource, opts...)
	if err != nil {
		return nil, err
	}
	return &resource, nil
}

// Input properties used for looking up and filtering Addon resources.
type addonState struct {
	// The error info of the addon.
	AddonErrors []AddonAddonError `pulumi:"addonErrors"`
	// The name of the addon.
	AddonName *string `pulumi:"addonName"`
	// The OCID of the cluster.
	ClusterId *string `pulumi:"clusterId"`
	// (Updatable) Addon configuration details
	Configurations []AddonConfiguration `pulumi:"configurations"`
	// current installed version of the addon
	CurrentInstalledVersion *string `pulumi:"currentInstalledVersion"`
	// Whether or not to override an existing addon installation. Defaults to false. If set to true, any existing addon installation would be overridden as per new installation details.
	OverrideExisting *bool `pulumi:"overrideExisting"`
	// Whether to remove addon resource in deletion.
	RemoveAddonResourcesOnDelete *bool `pulumi:"removeAddonResourcesOnDelete"`
	// The state of the addon.
	State *string `pulumi:"state"`
	// The time the cluster was created.
	TimeCreated *string `pulumi:"timeCreated"`
	// (Updatable) The version of addon to be installed.
	//
	// ** IMPORTANT **
	// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
	Version *string `pulumi:"version"`
}

type AddonState struct {
	// The error info of the addon.
	AddonErrors AddonAddonErrorArrayInput
	// The name of the addon.
	AddonName pulumi.StringPtrInput
	// The OCID of the cluster.
	ClusterId pulumi.StringPtrInput
	// (Updatable) Addon configuration details
	Configurations AddonConfigurationArrayInput
	// current installed version of the addon
	CurrentInstalledVersion pulumi.StringPtrInput
	// Whether or not to override an existing addon installation. Defaults to false. If set to true, any existing addon installation would be overridden as per new installation details.
	OverrideExisting pulumi.BoolPtrInput
	// Whether to remove addon resource in deletion.
	RemoveAddonResourcesOnDelete pulumi.BoolPtrInput
	// The state of the addon.
	State pulumi.StringPtrInput
	// The time the cluster was created.
	TimeCreated pulumi.StringPtrInput
	// (Updatable) The version of addon to be installed.
	//
	// ** IMPORTANT **
	// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
	Version pulumi.StringPtrInput
}

func (AddonState) ElementType() reflect.Type {
	return reflect.TypeOf((*addonState)(nil)).Elem()
}

type addonArgs struct {
	// The name of the addon.
	AddonName string `pulumi:"addonName"`
	// The OCID of the cluster.
	ClusterId string `pulumi:"clusterId"`
	// (Updatable) Addon configuration details
	Configurations []AddonConfiguration `pulumi:"configurations"`
	// Whether or not to override an existing addon installation. Defaults to false. If set to true, any existing addon installation would be overridden as per new installation details.
	OverrideExisting *bool `pulumi:"overrideExisting"`
	// Whether to remove addon resource in deletion.
	RemoveAddonResourcesOnDelete bool `pulumi:"removeAddonResourcesOnDelete"`
	// (Updatable) The version of addon to be installed.
	//
	// ** IMPORTANT **
	// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
	Version *string `pulumi:"version"`
}

// The set of arguments for constructing a Addon resource.
type AddonArgs struct {
	// The name of the addon.
	AddonName pulumi.StringInput
	// The OCID of the cluster.
	ClusterId pulumi.StringInput
	// (Updatable) Addon configuration details
	Configurations AddonConfigurationArrayInput
	// Whether or not to override an existing addon installation. Defaults to false. If set to true, any existing addon installation would be overridden as per new installation details.
	OverrideExisting pulumi.BoolPtrInput
	// Whether to remove addon resource in deletion.
	RemoveAddonResourcesOnDelete pulumi.BoolInput
	// (Updatable) The version of addon to be installed.
	//
	// ** IMPORTANT **
	// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
	Version pulumi.StringPtrInput
}

func (AddonArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*addonArgs)(nil)).Elem()
}

type AddonInput interface {
	pulumi.Input

	ToAddonOutput() AddonOutput
	ToAddonOutputWithContext(ctx context.Context) AddonOutput
}

func (*Addon) ElementType() reflect.Type {
	return reflect.TypeOf((**Addon)(nil)).Elem()
}

func (i *Addon) ToAddonOutput() AddonOutput {
	return i.ToAddonOutputWithContext(context.Background())
}

func (i *Addon) ToAddonOutputWithContext(ctx context.Context) AddonOutput {
	return pulumi.ToOutputWithContext(ctx, i).(AddonOutput)
}

// AddonArrayInput is an input type that accepts AddonArray and AddonArrayOutput values.
// You can construct a concrete instance of `AddonArrayInput` via:
//
//	AddonArray{ AddonArgs{...} }
type AddonArrayInput interface {
	pulumi.Input

	ToAddonArrayOutput() AddonArrayOutput
	ToAddonArrayOutputWithContext(context.Context) AddonArrayOutput
}

type AddonArray []AddonInput

func (AddonArray) ElementType() reflect.Type {
	return reflect.TypeOf((*[]*Addon)(nil)).Elem()
}

func (i AddonArray) ToAddonArrayOutput() AddonArrayOutput {
	return i.ToAddonArrayOutputWithContext(context.Background())
}

func (i AddonArray) ToAddonArrayOutputWithContext(ctx context.Context) AddonArrayOutput {
	return pulumi.ToOutputWithContext(ctx, i).(AddonArrayOutput)
}

// AddonMapInput is an input type that accepts AddonMap and AddonMapOutput values.
// You can construct a concrete instance of `AddonMapInput` via:
//
//	AddonMap{ "key": AddonArgs{...} }
type AddonMapInput interface {
	pulumi.Input

	ToAddonMapOutput() AddonMapOutput
	ToAddonMapOutputWithContext(context.Context) AddonMapOutput
}

type AddonMap map[string]AddonInput

func (AddonMap) ElementType() reflect.Type {
	return reflect.TypeOf((*map[string]*Addon)(nil)).Elem()
}

func (i AddonMap) ToAddonMapOutput() AddonMapOutput {
	return i.ToAddonMapOutputWithContext(context.Background())
}

func (i AddonMap) ToAddonMapOutputWithContext(ctx context.Context) AddonMapOutput {
	return pulumi.ToOutputWithContext(ctx, i).(AddonMapOutput)
}

type AddonOutput struct{ *pulumi.OutputState }

func (AddonOutput) ElementType() reflect.Type {
	return reflect.TypeOf((**Addon)(nil)).Elem()
}

func (o AddonOutput) ToAddonOutput() AddonOutput {
	return o
}

func (o AddonOutput) ToAddonOutputWithContext(ctx context.Context) AddonOutput {
	return o
}

// The error info of the addon.
func (o AddonOutput) AddonErrors() AddonAddonErrorArrayOutput {
	return o.ApplyT(func(v *Addon) AddonAddonErrorArrayOutput { return v.AddonErrors }).(AddonAddonErrorArrayOutput)
}

// The name of the addon.
func (o AddonOutput) AddonName() pulumi.StringOutput {
	return o.ApplyT(func(v *Addon) pulumi.StringOutput { return v.AddonName }).(pulumi.StringOutput)
}

// The OCID of the cluster.
func (o AddonOutput) ClusterId() pulumi.StringOutput {
	return o.ApplyT(func(v *Addon) pulumi.StringOutput { return v.ClusterId }).(pulumi.StringOutput)
}

// (Updatable) Addon configuration details
func (o AddonOutput) Configurations() AddonConfigurationArrayOutput {
	return o.ApplyT(func(v *Addon) AddonConfigurationArrayOutput { return v.Configurations }).(AddonConfigurationArrayOutput)
}

// current installed version of the addon
func (o AddonOutput) CurrentInstalledVersion() pulumi.StringOutput {
	return o.ApplyT(func(v *Addon) pulumi.StringOutput { return v.CurrentInstalledVersion }).(pulumi.StringOutput)
}

// Whether or not to override an existing addon installation. Defaults to false. If set to true, any existing addon installation would be overridden as per new installation details.
func (o AddonOutput) OverrideExisting() pulumi.BoolPtrOutput {
	return o.ApplyT(func(v *Addon) pulumi.BoolPtrOutput { return v.OverrideExisting }).(pulumi.BoolPtrOutput)
}

// Whether to remove addon resource in deletion.
func (o AddonOutput) RemoveAddonResourcesOnDelete() pulumi.BoolOutput {
	return o.ApplyT(func(v *Addon) pulumi.BoolOutput { return v.RemoveAddonResourcesOnDelete }).(pulumi.BoolOutput)
}

// The state of the addon.
func (o AddonOutput) State() pulumi.StringOutput {
	return o.ApplyT(func(v *Addon) pulumi.StringOutput { return v.State }).(pulumi.StringOutput)
}

// The time the cluster was created.
func (o AddonOutput) TimeCreated() pulumi.StringOutput {
	return o.ApplyT(func(v *Addon) pulumi.StringOutput { return v.TimeCreated }).(pulumi.StringOutput)
}

// (Updatable) The version of addon to be installed.
//
// ** IMPORTANT **
// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
func (o AddonOutput) Version() pulumi.StringPtrOutput {
	return o.ApplyT(func(v *Addon) pulumi.StringPtrOutput { return v.Version }).(pulumi.StringPtrOutput)
}

type AddonArrayOutput struct{ *pulumi.OutputState }

func (AddonArrayOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*[]*Addon)(nil)).Elem()
}

func (o AddonArrayOutput) ToAddonArrayOutput() AddonArrayOutput {
	return o
}

func (o AddonArrayOutput) ToAddonArrayOutputWithContext(ctx context.Context) AddonArrayOutput {
	return o
}

func (o AddonArrayOutput) Index(i pulumi.IntInput) AddonOutput {
	return pulumi.All(o, i).ApplyT(func(vs []interface{}) *Addon {
		return vs[0].([]*Addon)[vs[1].(int)]
	}).(AddonOutput)
}

type AddonMapOutput struct{ *pulumi.OutputState }

func (AddonMapOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*map[string]*Addon)(nil)).Elem()
}

func (o AddonMapOutput) ToAddonMapOutput() AddonMapOutput {
	return o
}

func (o AddonMapOutput) ToAddonMapOutputWithContext(ctx context.Context) AddonMapOutput {
	return o
}

func (o AddonMapOutput) MapIndex(k pulumi.StringInput) AddonOutput {
	return pulumi.All(o, k).ApplyT(func(vs []interface{}) *Addon {
		return vs[0].(map[string]*Addon)[vs[1].(string)]
	}).(AddonOutput)
}

func init() {
	pulumi.RegisterInputType(reflect.TypeOf((*AddonInput)(nil)).Elem(), &Addon{})
	pulumi.RegisterInputType(reflect.TypeOf((*AddonArrayInput)(nil)).Elem(), AddonArray{})
	pulumi.RegisterInputType(reflect.TypeOf((*AddonMapInput)(nil)).Elem(), AddonMap{})
	pulumi.RegisterOutputType(AddonOutput{})
	pulumi.RegisterOutputType(AddonArrayOutput{})
	pulumi.RegisterOutputType(AddonMapOutput{})
}
