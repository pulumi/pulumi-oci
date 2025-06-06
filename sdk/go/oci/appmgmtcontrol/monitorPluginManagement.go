// Code generated by pulumi-language-go DO NOT EDIT.
// *** WARNING: Do not edit by hand unless you're certain you know what you are doing! ***

package appmgmtcontrol

import (
	"context"
	"reflect"

	"errors"
	"github.com/pulumi/pulumi-oci/sdk/v3/go/oci/internal"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This resource provides the Monitor Plugin Management resource in Oracle Cloud Infrastructure Appmgmt Control service.
//
// Activates Resource Plugin for compute instance identified by the instance ocid.
// Stores monitored instances Id and its state. Tries to enable Resource Monitoring plugin by making
// remote calls to Oracle Cloud Agent and Management Agent Cloud Service.
//
// ## Example Usage
//
// ```go
// package main
//
// import (
//
//	"github.com/pulumi/pulumi-oci/sdk/v3/go/oci/appmgmtcontrol"
//	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
//
// )
//
//	func main() {
//		pulumi.Run(func(ctx *pulumi.Context) error {
//			_, err := appmgmtcontrol.NewMonitorPluginManagement(ctx, "test_monitor_plugin_management", &appmgmtcontrol.MonitorPluginManagementArgs{
//				MonitoredInstanceId: pulumi.Any(testMonitoredInstance.Id),
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
// Import is not supported for this resource.
type MonitorPluginManagement struct {
	pulumi.CustomResourceState

	CompartmentId                pulumi.StringOutput `pulumi:"compartmentId"`
	MonitoredInstanceDescription pulumi.StringOutput `pulumi:"monitoredInstanceDescription"`
	MonitoredInstanceDisplayName pulumi.StringOutput `pulumi:"monitoredInstanceDisplayName"`
	// OCID of monitored instance.
	//
	// ** IMPORTANT **
	// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
	MonitoredInstanceId                pulumi.StringOutput `pulumi:"monitoredInstanceId"`
	MonitoredInstanceManagementAgentId pulumi.StringOutput `pulumi:"monitoredInstanceManagementAgentId"`
	State                              pulumi.StringOutput `pulumi:"state"`
}

// NewMonitorPluginManagement registers a new resource with the given unique name, arguments, and options.
func NewMonitorPluginManagement(ctx *pulumi.Context,
	name string, args *MonitorPluginManagementArgs, opts ...pulumi.ResourceOption) (*MonitorPluginManagement, error) {
	if args == nil {
		return nil, errors.New("missing one or more required arguments")
	}

	if args.MonitoredInstanceId == nil {
		return nil, errors.New("invalid value for required argument 'MonitoredInstanceId'")
	}
	opts = internal.PkgResourceDefaultOpts(opts)
	var resource MonitorPluginManagement
	err := ctx.RegisterResource("oci:AppMgmtControl/monitorPluginManagement:MonitorPluginManagement", name, args, &resource, opts...)
	if err != nil {
		return nil, err
	}
	return &resource, nil
}

// GetMonitorPluginManagement gets an existing MonitorPluginManagement resource's state with the given name, ID, and optional
// state properties that are used to uniquely qualify the lookup (nil if not required).
func GetMonitorPluginManagement(ctx *pulumi.Context,
	name string, id pulumi.IDInput, state *MonitorPluginManagementState, opts ...pulumi.ResourceOption) (*MonitorPluginManagement, error) {
	var resource MonitorPluginManagement
	err := ctx.ReadResource("oci:AppMgmtControl/monitorPluginManagement:MonitorPluginManagement", name, id, state, &resource, opts...)
	if err != nil {
		return nil, err
	}
	return &resource, nil
}

// Input properties used for looking up and filtering MonitorPluginManagement resources.
type monitorPluginManagementState struct {
	CompartmentId                *string `pulumi:"compartmentId"`
	MonitoredInstanceDescription *string `pulumi:"monitoredInstanceDescription"`
	MonitoredInstanceDisplayName *string `pulumi:"monitoredInstanceDisplayName"`
	// OCID of monitored instance.
	//
	// ** IMPORTANT **
	// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
	MonitoredInstanceId                *string `pulumi:"monitoredInstanceId"`
	MonitoredInstanceManagementAgentId *string `pulumi:"monitoredInstanceManagementAgentId"`
	State                              *string `pulumi:"state"`
}

type MonitorPluginManagementState struct {
	CompartmentId                pulumi.StringPtrInput
	MonitoredInstanceDescription pulumi.StringPtrInput
	MonitoredInstanceDisplayName pulumi.StringPtrInput
	// OCID of monitored instance.
	//
	// ** IMPORTANT **
	// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
	MonitoredInstanceId                pulumi.StringPtrInput
	MonitoredInstanceManagementAgentId pulumi.StringPtrInput
	State                              pulumi.StringPtrInput
}

func (MonitorPluginManagementState) ElementType() reflect.Type {
	return reflect.TypeOf((*monitorPluginManagementState)(nil)).Elem()
}

type monitorPluginManagementArgs struct {
	// OCID of monitored instance.
	//
	// ** IMPORTANT **
	// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
	MonitoredInstanceId string `pulumi:"monitoredInstanceId"`
}

// The set of arguments for constructing a MonitorPluginManagement resource.
type MonitorPluginManagementArgs struct {
	// OCID of monitored instance.
	//
	// ** IMPORTANT **
	// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
	MonitoredInstanceId pulumi.StringInput
}

func (MonitorPluginManagementArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*monitorPluginManagementArgs)(nil)).Elem()
}

type MonitorPluginManagementInput interface {
	pulumi.Input

	ToMonitorPluginManagementOutput() MonitorPluginManagementOutput
	ToMonitorPluginManagementOutputWithContext(ctx context.Context) MonitorPluginManagementOutput
}

func (*MonitorPluginManagement) ElementType() reflect.Type {
	return reflect.TypeOf((**MonitorPluginManagement)(nil)).Elem()
}

func (i *MonitorPluginManagement) ToMonitorPluginManagementOutput() MonitorPluginManagementOutput {
	return i.ToMonitorPluginManagementOutputWithContext(context.Background())
}

func (i *MonitorPluginManagement) ToMonitorPluginManagementOutputWithContext(ctx context.Context) MonitorPluginManagementOutput {
	return pulumi.ToOutputWithContext(ctx, i).(MonitorPluginManagementOutput)
}

// MonitorPluginManagementArrayInput is an input type that accepts MonitorPluginManagementArray and MonitorPluginManagementArrayOutput values.
// You can construct a concrete instance of `MonitorPluginManagementArrayInput` via:
//
//	MonitorPluginManagementArray{ MonitorPluginManagementArgs{...} }
type MonitorPluginManagementArrayInput interface {
	pulumi.Input

	ToMonitorPluginManagementArrayOutput() MonitorPluginManagementArrayOutput
	ToMonitorPluginManagementArrayOutputWithContext(context.Context) MonitorPluginManagementArrayOutput
}

type MonitorPluginManagementArray []MonitorPluginManagementInput

func (MonitorPluginManagementArray) ElementType() reflect.Type {
	return reflect.TypeOf((*[]*MonitorPluginManagement)(nil)).Elem()
}

func (i MonitorPluginManagementArray) ToMonitorPluginManagementArrayOutput() MonitorPluginManagementArrayOutput {
	return i.ToMonitorPluginManagementArrayOutputWithContext(context.Background())
}

func (i MonitorPluginManagementArray) ToMonitorPluginManagementArrayOutputWithContext(ctx context.Context) MonitorPluginManagementArrayOutput {
	return pulumi.ToOutputWithContext(ctx, i).(MonitorPluginManagementArrayOutput)
}

// MonitorPluginManagementMapInput is an input type that accepts MonitorPluginManagementMap and MonitorPluginManagementMapOutput values.
// You can construct a concrete instance of `MonitorPluginManagementMapInput` via:
//
//	MonitorPluginManagementMap{ "key": MonitorPluginManagementArgs{...} }
type MonitorPluginManagementMapInput interface {
	pulumi.Input

	ToMonitorPluginManagementMapOutput() MonitorPluginManagementMapOutput
	ToMonitorPluginManagementMapOutputWithContext(context.Context) MonitorPluginManagementMapOutput
}

type MonitorPluginManagementMap map[string]MonitorPluginManagementInput

func (MonitorPluginManagementMap) ElementType() reflect.Type {
	return reflect.TypeOf((*map[string]*MonitorPluginManagement)(nil)).Elem()
}

func (i MonitorPluginManagementMap) ToMonitorPluginManagementMapOutput() MonitorPluginManagementMapOutput {
	return i.ToMonitorPluginManagementMapOutputWithContext(context.Background())
}

func (i MonitorPluginManagementMap) ToMonitorPluginManagementMapOutputWithContext(ctx context.Context) MonitorPluginManagementMapOutput {
	return pulumi.ToOutputWithContext(ctx, i).(MonitorPluginManagementMapOutput)
}

type MonitorPluginManagementOutput struct{ *pulumi.OutputState }

func (MonitorPluginManagementOutput) ElementType() reflect.Type {
	return reflect.TypeOf((**MonitorPluginManagement)(nil)).Elem()
}

func (o MonitorPluginManagementOutput) ToMonitorPluginManagementOutput() MonitorPluginManagementOutput {
	return o
}

func (o MonitorPluginManagementOutput) ToMonitorPluginManagementOutputWithContext(ctx context.Context) MonitorPluginManagementOutput {
	return o
}

func (o MonitorPluginManagementOutput) CompartmentId() pulumi.StringOutput {
	return o.ApplyT(func(v *MonitorPluginManagement) pulumi.StringOutput { return v.CompartmentId }).(pulumi.StringOutput)
}

func (o MonitorPluginManagementOutput) MonitoredInstanceDescription() pulumi.StringOutput {
	return o.ApplyT(func(v *MonitorPluginManagement) pulumi.StringOutput { return v.MonitoredInstanceDescription }).(pulumi.StringOutput)
}

func (o MonitorPluginManagementOutput) MonitoredInstanceDisplayName() pulumi.StringOutput {
	return o.ApplyT(func(v *MonitorPluginManagement) pulumi.StringOutput { return v.MonitoredInstanceDisplayName }).(pulumi.StringOutput)
}

// OCID of monitored instance.
//
// ** IMPORTANT **
// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
func (o MonitorPluginManagementOutput) MonitoredInstanceId() pulumi.StringOutput {
	return o.ApplyT(func(v *MonitorPluginManagement) pulumi.StringOutput { return v.MonitoredInstanceId }).(pulumi.StringOutput)
}

func (o MonitorPluginManagementOutput) MonitoredInstanceManagementAgentId() pulumi.StringOutput {
	return o.ApplyT(func(v *MonitorPluginManagement) pulumi.StringOutput { return v.MonitoredInstanceManagementAgentId }).(pulumi.StringOutput)
}

func (o MonitorPluginManagementOutput) State() pulumi.StringOutput {
	return o.ApplyT(func(v *MonitorPluginManagement) pulumi.StringOutput { return v.State }).(pulumi.StringOutput)
}

type MonitorPluginManagementArrayOutput struct{ *pulumi.OutputState }

func (MonitorPluginManagementArrayOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*[]*MonitorPluginManagement)(nil)).Elem()
}

func (o MonitorPluginManagementArrayOutput) ToMonitorPluginManagementArrayOutput() MonitorPluginManagementArrayOutput {
	return o
}

func (o MonitorPluginManagementArrayOutput) ToMonitorPluginManagementArrayOutputWithContext(ctx context.Context) MonitorPluginManagementArrayOutput {
	return o
}

func (o MonitorPluginManagementArrayOutput) Index(i pulumi.IntInput) MonitorPluginManagementOutput {
	return pulumi.All(o, i).ApplyT(func(vs []interface{}) *MonitorPluginManagement {
		return vs[0].([]*MonitorPluginManagement)[vs[1].(int)]
	}).(MonitorPluginManagementOutput)
}

type MonitorPluginManagementMapOutput struct{ *pulumi.OutputState }

func (MonitorPluginManagementMapOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*map[string]*MonitorPluginManagement)(nil)).Elem()
}

func (o MonitorPluginManagementMapOutput) ToMonitorPluginManagementMapOutput() MonitorPluginManagementMapOutput {
	return o
}

func (o MonitorPluginManagementMapOutput) ToMonitorPluginManagementMapOutputWithContext(ctx context.Context) MonitorPluginManagementMapOutput {
	return o
}

func (o MonitorPluginManagementMapOutput) MapIndex(k pulumi.StringInput) MonitorPluginManagementOutput {
	return pulumi.All(o, k).ApplyT(func(vs []interface{}) *MonitorPluginManagement {
		return vs[0].(map[string]*MonitorPluginManagement)[vs[1].(string)]
	}).(MonitorPluginManagementOutput)
}

func init() {
	pulumi.RegisterInputType(reflect.TypeOf((*MonitorPluginManagementInput)(nil)).Elem(), &MonitorPluginManagement{})
	pulumi.RegisterInputType(reflect.TypeOf((*MonitorPluginManagementArrayInput)(nil)).Elem(), MonitorPluginManagementArray{})
	pulumi.RegisterInputType(reflect.TypeOf((*MonitorPluginManagementMapInput)(nil)).Elem(), MonitorPluginManagementMap{})
	pulumi.RegisterOutputType(MonitorPluginManagementOutput{})
	pulumi.RegisterOutputType(MonitorPluginManagementArrayOutput{})
	pulumi.RegisterOutputType(MonitorPluginManagementMapOutput{})
}
