// Code generated by the Pulumi Terraform Bridge (tfgen) Tool DO NOT EDIT.
// *** WARNING: Do not edit by hand unless you're certain you know what you are doing! ***

package core

import (
	"context"
	"reflect"

	"github.com/pkg/errors"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This resource provides the Instance Pool resource in Oracle Cloud Infrastructure Core service.
//
// Create an instance pool.
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
//			_, err := Core.NewInstancePool(ctx, "testInstancePool", &Core.InstancePoolArgs{
//				CompartmentId:           pulumi.Any(_var.Compartment_id),
//				InstanceConfigurationId: pulumi.Any(oci_core_instance_configuration.Test_instance_configuration.Id),
//				PlacementConfigurations: core.InstancePoolPlacementConfigurationArray{
//					&core.InstancePoolPlacementConfigurationArgs{
//						AvailabilityDomain: pulumi.Any(_var.Instance_pool_placement_configurations_availability_domain),
//						PrimarySubnetId:    pulumi.Any(oci_core_subnet.Test_subnet.Id),
//						FaultDomains:       pulumi.Any(_var.Instance_pool_placement_configurations_fault_domains),
//						SecondaryVnicSubnets: core.InstancePoolPlacementConfigurationSecondaryVnicSubnetArray{
//							&core.InstancePoolPlacementConfigurationSecondaryVnicSubnetArgs{
//								SubnetId:    pulumi.Any(oci_core_subnet.Test_subnet.Id),
//								DisplayName: pulumi.Any(_var.Instance_pool_placement_configurations_secondary_vnic_subnets_display_name),
//							},
//						},
//					},
//				},
//				Size: pulumi.Any(_var.Instance_pool_size),
//				DefinedTags: pulumi.AnyMap{
//					"Operations.CostCenter": pulumi.Any("42"),
//				},
//				DisplayName: pulumi.Any(_var.Instance_pool_display_name),
//				FreeformTags: pulumi.AnyMap{
//					"Department": pulumi.Any("Finance"),
//				},
//				LoadBalancers: core.InstancePoolLoadBalancerArray{
//					&core.InstancePoolLoadBalancerArgs{
//						BackendSetName: pulumi.Any(oci_load_balancer_backend_set.Test_backend_set.Name),
//						LoadBalancerId: pulumi.Any(oci_load_balancer_load_balancer.Test_load_balancer.Id),
//						Port:           pulumi.Any(_var.Instance_pool_load_balancers_port),
//						VnicSelection:  pulumi.Any(_var.Instance_pool_load_balancers_vnic_selection),
//					},
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
// InstancePools can be imported using the `id`, e.g.
//
// ```sh
//
//	$ pulumi import oci:Core/instancePool:InstancePool test_instance_pool "id"
//
// ```
type InstancePool struct {
	pulumi.CustomResourceState

	// The number of actual instances in the instance pool on the cloud. This attribute will be different when instance pool is used along with autoScaling Configuration.
	ActualSize pulumi.IntOutput `pulumi:"actualSize"`
	// (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment containing the instance pool.
	CompartmentId pulumi.StringOutput `pulumi:"compartmentId"`
	// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Operations.CostCenter": "42"}`
	DefinedTags pulumi.MapOutput `pulumi:"definedTags"`
	// (Updatable) The display name of the VNIC. This is also use to match against the instance configuration defined secondary VNIC.
	DisplayName pulumi.StringOutput `pulumi:"displayName"`
	// (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
	FreeformTags pulumi.MapOutput `pulumi:"freeformTags"`
	// (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the instance configuration associated with the instance pool.
	InstanceConfigurationId pulumi.StringOutput `pulumi:"instanceConfigurationId"`
	// The load balancers to attach to the instance pool.
	LoadBalancers InstancePoolLoadBalancerArrayOutput `pulumi:"loadBalancers"`
	// (Updatable) The placement configurations for the instance pool. Provide one placement configuration for each availability domain.
	PlacementConfigurations InstancePoolPlacementConfigurationArrayOutput `pulumi:"placementConfigurations"`
	// (Updatable) The number of instances that should be in the instance pool. Modifying this value will override the size of the instance pool. If the instance pool is linked with autoscaling configuration, autoscaling configuration could resize the instance pool at a later point. The instance pool's actual size may differ from the configured size if it is associated with an autoscaling configuration, instance pool's actual size will be reflected in this size attribute.
	Size pulumi.IntOutput `pulumi:"size"`
	// (Updatable) The target state for the instance pool update operation (ignored at create time and should not be set). Could be set to RUNNING or STOPPED.
	State pulumi.StringOutput `pulumi:"state"`
	// The date and time the instance pool was created, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339). Example: `2016-08-25T21:10:29.600Z`
	TimeCreated pulumi.StringOutput `pulumi:"timeCreated"`
}

// NewInstancePool registers a new resource with the given unique name, arguments, and options.
func NewInstancePool(ctx *pulumi.Context,
	name string, args *InstancePoolArgs, opts ...pulumi.ResourceOption) (*InstancePool, error) {
	if args == nil {
		return nil, errors.New("missing one or more required arguments")
	}

	if args.CompartmentId == nil {
		return nil, errors.New("invalid value for required argument 'CompartmentId'")
	}
	if args.InstanceConfigurationId == nil {
		return nil, errors.New("invalid value for required argument 'InstanceConfigurationId'")
	}
	if args.PlacementConfigurations == nil {
		return nil, errors.New("invalid value for required argument 'PlacementConfigurations'")
	}
	if args.Size == nil {
		return nil, errors.New("invalid value for required argument 'Size'")
	}
	var resource InstancePool
	err := ctx.RegisterResource("oci:Core/instancePool:InstancePool", name, args, &resource, opts...)
	if err != nil {
		return nil, err
	}
	return &resource, nil
}

// GetInstancePool gets an existing InstancePool resource's state with the given name, ID, and optional
// state properties that are used to uniquely qualify the lookup (nil if not required).
func GetInstancePool(ctx *pulumi.Context,
	name string, id pulumi.IDInput, state *InstancePoolState, opts ...pulumi.ResourceOption) (*InstancePool, error) {
	var resource InstancePool
	err := ctx.ReadResource("oci:Core/instancePool:InstancePool", name, id, state, &resource, opts...)
	if err != nil {
		return nil, err
	}
	return &resource, nil
}

// Input properties used for looking up and filtering InstancePool resources.
type instancePoolState struct {
	// The number of actual instances in the instance pool on the cloud. This attribute will be different when instance pool is used along with autoScaling Configuration.
	ActualSize *int `pulumi:"actualSize"`
	// (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment containing the instance pool.
	CompartmentId *string `pulumi:"compartmentId"`
	// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Operations.CostCenter": "42"}`
	DefinedTags map[string]interface{} `pulumi:"definedTags"`
	// (Updatable) The display name of the VNIC. This is also use to match against the instance configuration defined secondary VNIC.
	DisplayName *string `pulumi:"displayName"`
	// (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
	FreeformTags map[string]interface{} `pulumi:"freeformTags"`
	// (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the instance configuration associated with the instance pool.
	InstanceConfigurationId *string `pulumi:"instanceConfigurationId"`
	// The load balancers to attach to the instance pool.
	LoadBalancers []InstancePoolLoadBalancer `pulumi:"loadBalancers"`
	// (Updatable) The placement configurations for the instance pool. Provide one placement configuration for each availability domain.
	PlacementConfigurations []InstancePoolPlacementConfiguration `pulumi:"placementConfigurations"`
	// (Updatable) The number of instances that should be in the instance pool. Modifying this value will override the size of the instance pool. If the instance pool is linked with autoscaling configuration, autoscaling configuration could resize the instance pool at a later point. The instance pool's actual size may differ from the configured size if it is associated with an autoscaling configuration, instance pool's actual size will be reflected in this size attribute.
	Size *int `pulumi:"size"`
	// (Updatable) The target state for the instance pool update operation (ignored at create time and should not be set). Could be set to RUNNING or STOPPED.
	State *string `pulumi:"state"`
	// The date and time the instance pool was created, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339). Example: `2016-08-25T21:10:29.600Z`
	TimeCreated *string `pulumi:"timeCreated"`
}

type InstancePoolState struct {
	// The number of actual instances in the instance pool on the cloud. This attribute will be different when instance pool is used along with autoScaling Configuration.
	ActualSize pulumi.IntPtrInput
	// (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment containing the instance pool.
	CompartmentId pulumi.StringPtrInput
	// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Operations.CostCenter": "42"}`
	DefinedTags pulumi.MapInput
	// (Updatable) The display name of the VNIC. This is also use to match against the instance configuration defined secondary VNIC.
	DisplayName pulumi.StringPtrInput
	// (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
	FreeformTags pulumi.MapInput
	// (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the instance configuration associated with the instance pool.
	InstanceConfigurationId pulumi.StringPtrInput
	// The load balancers to attach to the instance pool.
	LoadBalancers InstancePoolLoadBalancerArrayInput
	// (Updatable) The placement configurations for the instance pool. Provide one placement configuration for each availability domain.
	PlacementConfigurations InstancePoolPlacementConfigurationArrayInput
	// (Updatable) The number of instances that should be in the instance pool. Modifying this value will override the size of the instance pool. If the instance pool is linked with autoscaling configuration, autoscaling configuration could resize the instance pool at a later point. The instance pool's actual size may differ from the configured size if it is associated with an autoscaling configuration, instance pool's actual size will be reflected in this size attribute.
	Size pulumi.IntPtrInput
	// (Updatable) The target state for the instance pool update operation (ignored at create time and should not be set). Could be set to RUNNING or STOPPED.
	State pulumi.StringPtrInput
	// The date and time the instance pool was created, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339). Example: `2016-08-25T21:10:29.600Z`
	TimeCreated pulumi.StringPtrInput
}

func (InstancePoolState) ElementType() reflect.Type {
	return reflect.TypeOf((*instancePoolState)(nil)).Elem()
}

type instancePoolArgs struct {
	// (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment containing the instance pool.
	CompartmentId string `pulumi:"compartmentId"`
	// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Operations.CostCenter": "42"}`
	DefinedTags map[string]interface{} `pulumi:"definedTags"`
	// (Updatable) The display name of the VNIC. This is also use to match against the instance configuration defined secondary VNIC.
	DisplayName *string `pulumi:"displayName"`
	// (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
	FreeformTags map[string]interface{} `pulumi:"freeformTags"`
	// (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the instance configuration associated with the instance pool.
	InstanceConfigurationId string `pulumi:"instanceConfigurationId"`
	// The load balancers to attach to the instance pool.
	LoadBalancers []InstancePoolLoadBalancer `pulumi:"loadBalancers"`
	// (Updatable) The placement configurations for the instance pool. Provide one placement configuration for each availability domain.
	PlacementConfigurations []InstancePoolPlacementConfiguration `pulumi:"placementConfigurations"`
	// (Updatable) The number of instances that should be in the instance pool. Modifying this value will override the size of the instance pool. If the instance pool is linked with autoscaling configuration, autoscaling configuration could resize the instance pool at a later point. The instance pool's actual size may differ from the configured size if it is associated with an autoscaling configuration, instance pool's actual size will be reflected in this size attribute.
	Size int `pulumi:"size"`
	// (Updatable) The target state for the instance pool update operation (ignored at create time and should not be set). Could be set to RUNNING or STOPPED.
	State *string `pulumi:"state"`
}

// The set of arguments for constructing a InstancePool resource.
type InstancePoolArgs struct {
	// (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment containing the instance pool.
	CompartmentId pulumi.StringInput
	// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Operations.CostCenter": "42"}`
	DefinedTags pulumi.MapInput
	// (Updatable) The display name of the VNIC. This is also use to match against the instance configuration defined secondary VNIC.
	DisplayName pulumi.StringPtrInput
	// (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
	FreeformTags pulumi.MapInput
	// (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the instance configuration associated with the instance pool.
	InstanceConfigurationId pulumi.StringInput
	// The load balancers to attach to the instance pool.
	LoadBalancers InstancePoolLoadBalancerArrayInput
	// (Updatable) The placement configurations for the instance pool. Provide one placement configuration for each availability domain.
	PlacementConfigurations InstancePoolPlacementConfigurationArrayInput
	// (Updatable) The number of instances that should be in the instance pool. Modifying this value will override the size of the instance pool. If the instance pool is linked with autoscaling configuration, autoscaling configuration could resize the instance pool at a later point. The instance pool's actual size may differ from the configured size if it is associated with an autoscaling configuration, instance pool's actual size will be reflected in this size attribute.
	Size pulumi.IntInput
	// (Updatable) The target state for the instance pool update operation (ignored at create time and should not be set). Could be set to RUNNING or STOPPED.
	State pulumi.StringPtrInput
}

func (InstancePoolArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*instancePoolArgs)(nil)).Elem()
}

type InstancePoolInput interface {
	pulumi.Input

	ToInstancePoolOutput() InstancePoolOutput
	ToInstancePoolOutputWithContext(ctx context.Context) InstancePoolOutput
}

func (*InstancePool) ElementType() reflect.Type {
	return reflect.TypeOf((**InstancePool)(nil)).Elem()
}

func (i *InstancePool) ToInstancePoolOutput() InstancePoolOutput {
	return i.ToInstancePoolOutputWithContext(context.Background())
}

func (i *InstancePool) ToInstancePoolOutputWithContext(ctx context.Context) InstancePoolOutput {
	return pulumi.ToOutputWithContext(ctx, i).(InstancePoolOutput)
}

// InstancePoolArrayInput is an input type that accepts InstancePoolArray and InstancePoolArrayOutput values.
// You can construct a concrete instance of `InstancePoolArrayInput` via:
//
//	InstancePoolArray{ InstancePoolArgs{...} }
type InstancePoolArrayInput interface {
	pulumi.Input

	ToInstancePoolArrayOutput() InstancePoolArrayOutput
	ToInstancePoolArrayOutputWithContext(context.Context) InstancePoolArrayOutput
}

type InstancePoolArray []InstancePoolInput

func (InstancePoolArray) ElementType() reflect.Type {
	return reflect.TypeOf((*[]*InstancePool)(nil)).Elem()
}

func (i InstancePoolArray) ToInstancePoolArrayOutput() InstancePoolArrayOutput {
	return i.ToInstancePoolArrayOutputWithContext(context.Background())
}

func (i InstancePoolArray) ToInstancePoolArrayOutputWithContext(ctx context.Context) InstancePoolArrayOutput {
	return pulumi.ToOutputWithContext(ctx, i).(InstancePoolArrayOutput)
}

// InstancePoolMapInput is an input type that accepts InstancePoolMap and InstancePoolMapOutput values.
// You can construct a concrete instance of `InstancePoolMapInput` via:
//
//	InstancePoolMap{ "key": InstancePoolArgs{...} }
type InstancePoolMapInput interface {
	pulumi.Input

	ToInstancePoolMapOutput() InstancePoolMapOutput
	ToInstancePoolMapOutputWithContext(context.Context) InstancePoolMapOutput
}

type InstancePoolMap map[string]InstancePoolInput

func (InstancePoolMap) ElementType() reflect.Type {
	return reflect.TypeOf((*map[string]*InstancePool)(nil)).Elem()
}

func (i InstancePoolMap) ToInstancePoolMapOutput() InstancePoolMapOutput {
	return i.ToInstancePoolMapOutputWithContext(context.Background())
}

func (i InstancePoolMap) ToInstancePoolMapOutputWithContext(ctx context.Context) InstancePoolMapOutput {
	return pulumi.ToOutputWithContext(ctx, i).(InstancePoolMapOutput)
}

type InstancePoolOutput struct{ *pulumi.OutputState }

func (InstancePoolOutput) ElementType() reflect.Type {
	return reflect.TypeOf((**InstancePool)(nil)).Elem()
}

func (o InstancePoolOutput) ToInstancePoolOutput() InstancePoolOutput {
	return o
}

func (o InstancePoolOutput) ToInstancePoolOutputWithContext(ctx context.Context) InstancePoolOutput {
	return o
}

// The number of actual instances in the instance pool on the cloud. This attribute will be different when instance pool is used along with autoScaling Configuration.
func (o InstancePoolOutput) ActualSize() pulumi.IntOutput {
	return o.ApplyT(func(v *InstancePool) pulumi.IntOutput { return v.ActualSize }).(pulumi.IntOutput)
}

// (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment containing the instance pool.
func (o InstancePoolOutput) CompartmentId() pulumi.StringOutput {
	return o.ApplyT(func(v *InstancePool) pulumi.StringOutput { return v.CompartmentId }).(pulumi.StringOutput)
}

// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Operations.CostCenter": "42"}`
func (o InstancePoolOutput) DefinedTags() pulumi.MapOutput {
	return o.ApplyT(func(v *InstancePool) pulumi.MapOutput { return v.DefinedTags }).(pulumi.MapOutput)
}

// (Updatable) The display name of the VNIC. This is also use to match against the instance configuration defined secondary VNIC.
func (o InstancePoolOutput) DisplayName() pulumi.StringOutput {
	return o.ApplyT(func(v *InstancePool) pulumi.StringOutput { return v.DisplayName }).(pulumi.StringOutput)
}

// (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
func (o InstancePoolOutput) FreeformTags() pulumi.MapOutput {
	return o.ApplyT(func(v *InstancePool) pulumi.MapOutput { return v.FreeformTags }).(pulumi.MapOutput)
}

// (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the instance configuration associated with the instance pool.
func (o InstancePoolOutput) InstanceConfigurationId() pulumi.StringOutput {
	return o.ApplyT(func(v *InstancePool) pulumi.StringOutput { return v.InstanceConfigurationId }).(pulumi.StringOutput)
}

// The load balancers to attach to the instance pool.
func (o InstancePoolOutput) LoadBalancers() InstancePoolLoadBalancerArrayOutput {
	return o.ApplyT(func(v *InstancePool) InstancePoolLoadBalancerArrayOutput { return v.LoadBalancers }).(InstancePoolLoadBalancerArrayOutput)
}

// (Updatable) The placement configurations for the instance pool. Provide one placement configuration for each availability domain.
func (o InstancePoolOutput) PlacementConfigurations() InstancePoolPlacementConfigurationArrayOutput {
	return o.ApplyT(func(v *InstancePool) InstancePoolPlacementConfigurationArrayOutput { return v.PlacementConfigurations }).(InstancePoolPlacementConfigurationArrayOutput)
}

// (Updatable) The number of instances that should be in the instance pool. Modifying this value will override the size of the instance pool. If the instance pool is linked with autoscaling configuration, autoscaling configuration could resize the instance pool at a later point. The instance pool's actual size may differ from the configured size if it is associated with an autoscaling configuration, instance pool's actual size will be reflected in this size attribute.
func (o InstancePoolOutput) Size() pulumi.IntOutput {
	return o.ApplyT(func(v *InstancePool) pulumi.IntOutput { return v.Size }).(pulumi.IntOutput)
}

// (Updatable) The target state for the instance pool update operation (ignored at create time and should not be set). Could be set to RUNNING or STOPPED.
func (o InstancePoolOutput) State() pulumi.StringOutput {
	return o.ApplyT(func(v *InstancePool) pulumi.StringOutput { return v.State }).(pulumi.StringOutput)
}

// The date and time the instance pool was created, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339). Example: `2016-08-25T21:10:29.600Z`
func (o InstancePoolOutput) TimeCreated() pulumi.StringOutput {
	return o.ApplyT(func(v *InstancePool) pulumi.StringOutput { return v.TimeCreated }).(pulumi.StringOutput)
}

type InstancePoolArrayOutput struct{ *pulumi.OutputState }

func (InstancePoolArrayOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*[]*InstancePool)(nil)).Elem()
}

func (o InstancePoolArrayOutput) ToInstancePoolArrayOutput() InstancePoolArrayOutput {
	return o
}

func (o InstancePoolArrayOutput) ToInstancePoolArrayOutputWithContext(ctx context.Context) InstancePoolArrayOutput {
	return o
}

func (o InstancePoolArrayOutput) Index(i pulumi.IntInput) InstancePoolOutput {
	return pulumi.All(o, i).ApplyT(func(vs []interface{}) *InstancePool {
		return vs[0].([]*InstancePool)[vs[1].(int)]
	}).(InstancePoolOutput)
}

type InstancePoolMapOutput struct{ *pulumi.OutputState }

func (InstancePoolMapOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*map[string]*InstancePool)(nil)).Elem()
}

func (o InstancePoolMapOutput) ToInstancePoolMapOutput() InstancePoolMapOutput {
	return o
}

func (o InstancePoolMapOutput) ToInstancePoolMapOutputWithContext(ctx context.Context) InstancePoolMapOutput {
	return o
}

func (o InstancePoolMapOutput) MapIndex(k pulumi.StringInput) InstancePoolOutput {
	return pulumi.All(o, k).ApplyT(func(vs []interface{}) *InstancePool {
		return vs[0].(map[string]*InstancePool)[vs[1].(string)]
	}).(InstancePoolOutput)
}

func init() {
	pulumi.RegisterInputType(reflect.TypeOf((*InstancePoolInput)(nil)).Elem(), &InstancePool{})
	pulumi.RegisterInputType(reflect.TypeOf((*InstancePoolArrayInput)(nil)).Elem(), InstancePoolArray{})
	pulumi.RegisterInputType(reflect.TypeOf((*InstancePoolMapInput)(nil)).Elem(), InstancePoolMap{})
	pulumi.RegisterOutputType(InstancePoolOutput{})
	pulumi.RegisterOutputType(InstancePoolArrayOutput{})
	pulumi.RegisterOutputType(InstancePoolMapOutput{})
}