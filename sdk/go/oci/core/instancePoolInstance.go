// Code generated by the Pulumi Terraform Bridge (tfgen) Tool DO NOT EDIT.
// *** WARNING: Do not edit by hand unless you're certain you know what you are doing! ***

package core

import (
	"context"
	"reflect"

	"github.com/pkg/errors"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This resource provides the Instance Pool Instance resource in Oracle Cloud Infrastructure Core service.
//
// Attaches an instance to an instance pool. For information about the prerequisites
// that an instance must meet before you can attach it to a pool, see
// [Attaching an Instance to an Instance Pool](https://docs.cloud.oracle.com/iaas/Content/Compute/Tasks/updatinginstancepool.htm#attach-instance).
//
// # Using this resource will impact the size of the instance pool, attach will increment the size of the pool
//
// ## Example Usage
//
// ```go
// package main
//
// import (
//
//	"github.com/pulumi/pulumi-oci/sdk/go/oci/Core"
//	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
//
// )
//
//	func main() {
//		pulumi.Run(func(ctx *pulumi.Context) error {
//			_, err := Core.NewInstancePoolInstance(ctx, "testInstancePoolInstance", &Core.InstancePoolInstanceArgs{
//				InstanceId:     pulumi.Any(oci_core_instance.Test_instance.Id),
//				InstancePoolId: pulumi.Any(oci_core_instance_pool.Test_instance_pool.Id),
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
// InstancePoolInstances can be imported using the `id`, e.g.
//
// ```sh
//
//	$ pulumi import oci:Core/instancePoolInstance:InstancePoolInstance test_instance_pool_instance "instancePools/{instancePoolId}/instances/compartmentId/{compartmentId}"
//
// ```
type InstancePoolInstance struct {
	pulumi.CustomResourceState

	AutoTerminateInstanceOnDelete pulumi.BoolPtrOutput `pulumi:"autoTerminateInstanceOnDelete"`
	// The availability domain the instance is running in.
	AvailabilityDomain pulumi.StringOutput `pulumi:"availabilityDomain"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment that contains the instance.
	CompartmentId         pulumi.StringOutput  `pulumi:"compartmentId"`
	DecrementSizeOnDelete pulumi.BoolPtrOutput `pulumi:"decrementSizeOnDelete"`
	// A user-friendly name. Does not have to be unique, and it's changeable. Avoid entering confidential information.
	DisplayName pulumi.StringOutput `pulumi:"displayName"`
	// The fault domain the instance is running in.
	FaultDomain pulumi.StringOutput `pulumi:"faultDomain"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the instance configuration used to create the instance.
	InstanceConfigurationId pulumi.StringOutput `pulumi:"instanceConfigurationId"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the instance.
	InstanceId pulumi.StringOutput `pulumi:"instanceId"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the instance pool.
	InstancePoolId pulumi.StringOutput `pulumi:"instancePoolId"`
	// The load balancer backends that are configured for the instance pool instance.
	LoadBalancerBackends InstancePoolInstanceLoadBalancerBackendArrayOutput `pulumi:"loadBalancerBackends"`
	// The region that contains the availability domain the instance is running in.
	Region pulumi.StringOutput `pulumi:"region"`
	// The shape of an instance. The shape determines the number of CPUs, amount of memory, and other resources allocated to the instance.
	Shape pulumi.StringOutput `pulumi:"shape"`
	// The lifecycle state of the instance. Refer to `lifecycleState` in the [Instance](https://docs.cloud.oracle.com/iaas/api/#/en/iaas/latest/Instance) resource.
	State pulumi.StringOutput `pulumi:"state"`
	// The date and time the instance pool instance was created, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339). Example: `2016-08-25T21:10:29.600Z`
	TimeCreated pulumi.StringOutput `pulumi:"timeCreated"`
}

// NewInstancePoolInstance registers a new resource with the given unique name, arguments, and options.
func NewInstancePoolInstance(ctx *pulumi.Context,
	name string, args *InstancePoolInstanceArgs, opts ...pulumi.ResourceOption) (*InstancePoolInstance, error) {
	if args == nil {
		return nil, errors.New("missing one or more required arguments")
	}

	if args.InstanceId == nil {
		return nil, errors.New("invalid value for required argument 'InstanceId'")
	}
	if args.InstancePoolId == nil {
		return nil, errors.New("invalid value for required argument 'InstancePoolId'")
	}
	var resource InstancePoolInstance
	err := ctx.RegisterResource("oci:Core/instancePoolInstance:InstancePoolInstance", name, args, &resource, opts...)
	if err != nil {
		return nil, err
	}
	return &resource, nil
}

// GetInstancePoolInstance gets an existing InstancePoolInstance resource's state with the given name, ID, and optional
// state properties that are used to uniquely qualify the lookup (nil if not required).
func GetInstancePoolInstance(ctx *pulumi.Context,
	name string, id pulumi.IDInput, state *InstancePoolInstanceState, opts ...pulumi.ResourceOption) (*InstancePoolInstance, error) {
	var resource InstancePoolInstance
	err := ctx.ReadResource("oci:Core/instancePoolInstance:InstancePoolInstance", name, id, state, &resource, opts...)
	if err != nil {
		return nil, err
	}
	return &resource, nil
}

// Input properties used for looking up and filtering InstancePoolInstance resources.
type instancePoolInstanceState struct {
	AutoTerminateInstanceOnDelete *bool `pulumi:"autoTerminateInstanceOnDelete"`
	// The availability domain the instance is running in.
	AvailabilityDomain *string `pulumi:"availabilityDomain"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment that contains the instance.
	CompartmentId         *string `pulumi:"compartmentId"`
	DecrementSizeOnDelete *bool   `pulumi:"decrementSizeOnDelete"`
	// A user-friendly name. Does not have to be unique, and it's changeable. Avoid entering confidential information.
	DisplayName *string `pulumi:"displayName"`
	// The fault domain the instance is running in.
	FaultDomain *string `pulumi:"faultDomain"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the instance configuration used to create the instance.
	InstanceConfigurationId *string `pulumi:"instanceConfigurationId"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the instance.
	InstanceId *string `pulumi:"instanceId"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the instance pool.
	InstancePoolId *string `pulumi:"instancePoolId"`
	// The load balancer backends that are configured for the instance pool instance.
	LoadBalancerBackends []InstancePoolInstanceLoadBalancerBackend `pulumi:"loadBalancerBackends"`
	// The region that contains the availability domain the instance is running in.
	Region *string `pulumi:"region"`
	// The shape of an instance. The shape determines the number of CPUs, amount of memory, and other resources allocated to the instance.
	Shape *string `pulumi:"shape"`
	// The lifecycle state of the instance. Refer to `lifecycleState` in the [Instance](https://docs.cloud.oracle.com/iaas/api/#/en/iaas/latest/Instance) resource.
	State *string `pulumi:"state"`
	// The date and time the instance pool instance was created, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339). Example: `2016-08-25T21:10:29.600Z`
	TimeCreated *string `pulumi:"timeCreated"`
}

type InstancePoolInstanceState struct {
	AutoTerminateInstanceOnDelete pulumi.BoolPtrInput
	// The availability domain the instance is running in.
	AvailabilityDomain pulumi.StringPtrInput
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment that contains the instance.
	CompartmentId         pulumi.StringPtrInput
	DecrementSizeOnDelete pulumi.BoolPtrInput
	// A user-friendly name. Does not have to be unique, and it's changeable. Avoid entering confidential information.
	DisplayName pulumi.StringPtrInput
	// The fault domain the instance is running in.
	FaultDomain pulumi.StringPtrInput
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the instance configuration used to create the instance.
	InstanceConfigurationId pulumi.StringPtrInput
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the instance.
	InstanceId pulumi.StringPtrInput
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the instance pool.
	InstancePoolId pulumi.StringPtrInput
	// The load balancer backends that are configured for the instance pool instance.
	LoadBalancerBackends InstancePoolInstanceLoadBalancerBackendArrayInput
	// The region that contains the availability domain the instance is running in.
	Region pulumi.StringPtrInput
	// The shape of an instance. The shape determines the number of CPUs, amount of memory, and other resources allocated to the instance.
	Shape pulumi.StringPtrInput
	// The lifecycle state of the instance. Refer to `lifecycleState` in the [Instance](https://docs.cloud.oracle.com/iaas/api/#/en/iaas/latest/Instance) resource.
	State pulumi.StringPtrInput
	// The date and time the instance pool instance was created, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339). Example: `2016-08-25T21:10:29.600Z`
	TimeCreated pulumi.StringPtrInput
}

func (InstancePoolInstanceState) ElementType() reflect.Type {
	return reflect.TypeOf((*instancePoolInstanceState)(nil)).Elem()
}

type instancePoolInstanceArgs struct {
	AutoTerminateInstanceOnDelete *bool `pulumi:"autoTerminateInstanceOnDelete"`
	DecrementSizeOnDelete         *bool `pulumi:"decrementSizeOnDelete"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the instance.
	InstanceId string `pulumi:"instanceId"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the instance pool.
	InstancePoolId string `pulumi:"instancePoolId"`
}

// The set of arguments for constructing a InstancePoolInstance resource.
type InstancePoolInstanceArgs struct {
	AutoTerminateInstanceOnDelete pulumi.BoolPtrInput
	DecrementSizeOnDelete         pulumi.BoolPtrInput
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the instance.
	InstanceId pulumi.StringInput
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the instance pool.
	InstancePoolId pulumi.StringInput
}

func (InstancePoolInstanceArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*instancePoolInstanceArgs)(nil)).Elem()
}

type InstancePoolInstanceInput interface {
	pulumi.Input

	ToInstancePoolInstanceOutput() InstancePoolInstanceOutput
	ToInstancePoolInstanceOutputWithContext(ctx context.Context) InstancePoolInstanceOutput
}

func (*InstancePoolInstance) ElementType() reflect.Type {
	return reflect.TypeOf((**InstancePoolInstance)(nil)).Elem()
}

func (i *InstancePoolInstance) ToInstancePoolInstanceOutput() InstancePoolInstanceOutput {
	return i.ToInstancePoolInstanceOutputWithContext(context.Background())
}

func (i *InstancePoolInstance) ToInstancePoolInstanceOutputWithContext(ctx context.Context) InstancePoolInstanceOutput {
	return pulumi.ToOutputWithContext(ctx, i).(InstancePoolInstanceOutput)
}

// InstancePoolInstanceArrayInput is an input type that accepts InstancePoolInstanceArray and InstancePoolInstanceArrayOutput values.
// You can construct a concrete instance of `InstancePoolInstanceArrayInput` via:
//
//	InstancePoolInstanceArray{ InstancePoolInstanceArgs{...} }
type InstancePoolInstanceArrayInput interface {
	pulumi.Input

	ToInstancePoolInstanceArrayOutput() InstancePoolInstanceArrayOutput
	ToInstancePoolInstanceArrayOutputWithContext(context.Context) InstancePoolInstanceArrayOutput
}

type InstancePoolInstanceArray []InstancePoolInstanceInput

func (InstancePoolInstanceArray) ElementType() reflect.Type {
	return reflect.TypeOf((*[]*InstancePoolInstance)(nil)).Elem()
}

func (i InstancePoolInstanceArray) ToInstancePoolInstanceArrayOutput() InstancePoolInstanceArrayOutput {
	return i.ToInstancePoolInstanceArrayOutputWithContext(context.Background())
}

func (i InstancePoolInstanceArray) ToInstancePoolInstanceArrayOutputWithContext(ctx context.Context) InstancePoolInstanceArrayOutput {
	return pulumi.ToOutputWithContext(ctx, i).(InstancePoolInstanceArrayOutput)
}

// InstancePoolInstanceMapInput is an input type that accepts InstancePoolInstanceMap and InstancePoolInstanceMapOutput values.
// You can construct a concrete instance of `InstancePoolInstanceMapInput` via:
//
//	InstancePoolInstanceMap{ "key": InstancePoolInstanceArgs{...} }
type InstancePoolInstanceMapInput interface {
	pulumi.Input

	ToInstancePoolInstanceMapOutput() InstancePoolInstanceMapOutput
	ToInstancePoolInstanceMapOutputWithContext(context.Context) InstancePoolInstanceMapOutput
}

type InstancePoolInstanceMap map[string]InstancePoolInstanceInput

func (InstancePoolInstanceMap) ElementType() reflect.Type {
	return reflect.TypeOf((*map[string]*InstancePoolInstance)(nil)).Elem()
}

func (i InstancePoolInstanceMap) ToInstancePoolInstanceMapOutput() InstancePoolInstanceMapOutput {
	return i.ToInstancePoolInstanceMapOutputWithContext(context.Background())
}

func (i InstancePoolInstanceMap) ToInstancePoolInstanceMapOutputWithContext(ctx context.Context) InstancePoolInstanceMapOutput {
	return pulumi.ToOutputWithContext(ctx, i).(InstancePoolInstanceMapOutput)
}

type InstancePoolInstanceOutput struct{ *pulumi.OutputState }

func (InstancePoolInstanceOutput) ElementType() reflect.Type {
	return reflect.TypeOf((**InstancePoolInstance)(nil)).Elem()
}

func (o InstancePoolInstanceOutput) ToInstancePoolInstanceOutput() InstancePoolInstanceOutput {
	return o
}

func (o InstancePoolInstanceOutput) ToInstancePoolInstanceOutputWithContext(ctx context.Context) InstancePoolInstanceOutput {
	return o
}

func (o InstancePoolInstanceOutput) AutoTerminateInstanceOnDelete() pulumi.BoolPtrOutput {
	return o.ApplyT(func(v *InstancePoolInstance) pulumi.BoolPtrOutput { return v.AutoTerminateInstanceOnDelete }).(pulumi.BoolPtrOutput)
}

// The availability domain the instance is running in.
func (o InstancePoolInstanceOutput) AvailabilityDomain() pulumi.StringOutput {
	return o.ApplyT(func(v *InstancePoolInstance) pulumi.StringOutput { return v.AvailabilityDomain }).(pulumi.StringOutput)
}

// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment that contains the instance.
func (o InstancePoolInstanceOutput) CompartmentId() pulumi.StringOutput {
	return o.ApplyT(func(v *InstancePoolInstance) pulumi.StringOutput { return v.CompartmentId }).(pulumi.StringOutput)
}

func (o InstancePoolInstanceOutput) DecrementSizeOnDelete() pulumi.BoolPtrOutput {
	return o.ApplyT(func(v *InstancePoolInstance) pulumi.BoolPtrOutput { return v.DecrementSizeOnDelete }).(pulumi.BoolPtrOutput)
}

// A user-friendly name. Does not have to be unique, and it's changeable. Avoid entering confidential information.
func (o InstancePoolInstanceOutput) DisplayName() pulumi.StringOutput {
	return o.ApplyT(func(v *InstancePoolInstance) pulumi.StringOutput { return v.DisplayName }).(pulumi.StringOutput)
}

// The fault domain the instance is running in.
func (o InstancePoolInstanceOutput) FaultDomain() pulumi.StringOutput {
	return o.ApplyT(func(v *InstancePoolInstance) pulumi.StringOutput { return v.FaultDomain }).(pulumi.StringOutput)
}

// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the instance configuration used to create the instance.
func (o InstancePoolInstanceOutput) InstanceConfigurationId() pulumi.StringOutput {
	return o.ApplyT(func(v *InstancePoolInstance) pulumi.StringOutput { return v.InstanceConfigurationId }).(pulumi.StringOutput)
}

// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the instance.
func (o InstancePoolInstanceOutput) InstanceId() pulumi.StringOutput {
	return o.ApplyT(func(v *InstancePoolInstance) pulumi.StringOutput { return v.InstanceId }).(pulumi.StringOutput)
}

// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the instance pool.
func (o InstancePoolInstanceOutput) InstancePoolId() pulumi.StringOutput {
	return o.ApplyT(func(v *InstancePoolInstance) pulumi.StringOutput { return v.InstancePoolId }).(pulumi.StringOutput)
}

// The load balancer backends that are configured for the instance pool instance.
func (o InstancePoolInstanceOutput) LoadBalancerBackends() InstancePoolInstanceLoadBalancerBackendArrayOutput {
	return o.ApplyT(func(v *InstancePoolInstance) InstancePoolInstanceLoadBalancerBackendArrayOutput {
		return v.LoadBalancerBackends
	}).(InstancePoolInstanceLoadBalancerBackendArrayOutput)
}

// The region that contains the availability domain the instance is running in.
func (o InstancePoolInstanceOutput) Region() pulumi.StringOutput {
	return o.ApplyT(func(v *InstancePoolInstance) pulumi.StringOutput { return v.Region }).(pulumi.StringOutput)
}

// The shape of an instance. The shape determines the number of CPUs, amount of memory, and other resources allocated to the instance.
func (o InstancePoolInstanceOutput) Shape() pulumi.StringOutput {
	return o.ApplyT(func(v *InstancePoolInstance) pulumi.StringOutput { return v.Shape }).(pulumi.StringOutput)
}

// The lifecycle state of the instance. Refer to `lifecycleState` in the [Instance](https://docs.cloud.oracle.com/iaas/api/#/en/iaas/latest/Instance) resource.
func (o InstancePoolInstanceOutput) State() pulumi.StringOutput {
	return o.ApplyT(func(v *InstancePoolInstance) pulumi.StringOutput { return v.State }).(pulumi.StringOutput)
}

// The date and time the instance pool instance was created, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339). Example: `2016-08-25T21:10:29.600Z`
func (o InstancePoolInstanceOutput) TimeCreated() pulumi.StringOutput {
	return o.ApplyT(func(v *InstancePoolInstance) pulumi.StringOutput { return v.TimeCreated }).(pulumi.StringOutput)
}

type InstancePoolInstanceArrayOutput struct{ *pulumi.OutputState }

func (InstancePoolInstanceArrayOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*[]*InstancePoolInstance)(nil)).Elem()
}

func (o InstancePoolInstanceArrayOutput) ToInstancePoolInstanceArrayOutput() InstancePoolInstanceArrayOutput {
	return o
}

func (o InstancePoolInstanceArrayOutput) ToInstancePoolInstanceArrayOutputWithContext(ctx context.Context) InstancePoolInstanceArrayOutput {
	return o
}

func (o InstancePoolInstanceArrayOutput) Index(i pulumi.IntInput) InstancePoolInstanceOutput {
	return pulumi.All(o, i).ApplyT(func(vs []interface{}) *InstancePoolInstance {
		return vs[0].([]*InstancePoolInstance)[vs[1].(int)]
	}).(InstancePoolInstanceOutput)
}

type InstancePoolInstanceMapOutput struct{ *pulumi.OutputState }

func (InstancePoolInstanceMapOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*map[string]*InstancePoolInstance)(nil)).Elem()
}

func (o InstancePoolInstanceMapOutput) ToInstancePoolInstanceMapOutput() InstancePoolInstanceMapOutput {
	return o
}

func (o InstancePoolInstanceMapOutput) ToInstancePoolInstanceMapOutputWithContext(ctx context.Context) InstancePoolInstanceMapOutput {
	return o
}

func (o InstancePoolInstanceMapOutput) MapIndex(k pulumi.StringInput) InstancePoolInstanceOutput {
	return pulumi.All(o, k).ApplyT(func(vs []interface{}) *InstancePoolInstance {
		return vs[0].(map[string]*InstancePoolInstance)[vs[1].(string)]
	}).(InstancePoolInstanceOutput)
}

func init() {
	pulumi.RegisterInputType(reflect.TypeOf((*InstancePoolInstanceInput)(nil)).Elem(), &InstancePoolInstance{})
	pulumi.RegisterInputType(reflect.TypeOf((*InstancePoolInstanceArrayInput)(nil)).Elem(), InstancePoolInstanceArray{})
	pulumi.RegisterInputType(reflect.TypeOf((*InstancePoolInstanceMapInput)(nil)).Elem(), InstancePoolInstanceMap{})
	pulumi.RegisterOutputType(InstancePoolInstanceOutput{})
	pulumi.RegisterOutputType(InstancePoolInstanceArrayOutput{})
	pulumi.RegisterOutputType(InstancePoolInstanceMapOutput{})
}