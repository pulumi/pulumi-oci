// Code generated by pulumi-language-go DO NOT EDIT.
// *** WARNING: Do not edit by hand unless you're certain you know what you are doing! ***

package core

import (
	"context"
	"reflect"

	"errors"
	"github.com/pulumi/pulumi-oci/sdk/v3/go/oci/internal"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This resource provides the Cluster Network resource in Oracle Cloud Infrastructure Core service.
//
// Creates a [cluster network with instance pools](https://docs.cloud.oracle.com/iaas/Content/Compute/Tasks/managingclusternetworks.htm).
// A cluster network is a group of high performance computing (HPC), GPU, or optimized bare metal
// instances that are connected with an ultra low-latency remote direct memory access (RDMA) network.
// Cluster networks with instance pools use instance pools to manage groups of identical instances.
//
// Use cluster networks with instance pools when you want predictable capacity for a specific number of identical
// instances that are managed as a group.
//
// If you want to manage instances in the RDMA network independently of each other or use different types of instances
// in the network group, create a compute cluster by using the [CreateComputeCluster](https://docs.cloud.oracle.com/iaas/api/#/en/iaas/latest/ComputeCluster/CreateComputeCluster)
// operation.
//
// To determine whether capacity is available for a specific shape before you create a cluster network,
// use the [CreateComputeCapacityReport](https://docs.cloud.oracle.com/iaas/api/#/en/iaas/latest/ComputeCapacityReport/CreateComputeCapacityReport)
// operation.
//
// ## Example Usage
//
// ```go
// package main
//
// import (
//
//	"github.com/pulumi/pulumi-oci/sdk/v3/go/oci/core"
//	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
//
// )
//
//	func main() {
//		pulumi.Run(func(ctx *pulumi.Context) error {
//			_, err := core.NewClusterNetwork(ctx, "test_cluster_network", &core.ClusterNetworkArgs{
//				CompartmentId: pulumi.Any(compartmentId),
//				InstancePools: core.ClusterNetworkInstancePoolArray{
//					&core.ClusterNetworkInstancePoolArgs{
//						InstanceConfigurationId: pulumi.Any(testInstanceConfiguration.Id),
//						Size:                    pulumi.Any(clusterNetworkInstancePoolsSize),
//						DefinedTags: pulumi.StringMap{
//							"Operations.CostCenter": pulumi.String("42"),
//						},
//						DisplayName: pulumi.Any(clusterNetworkInstancePoolsDisplayName),
//						FreeformTags: pulumi.StringMap{
//							"Department": pulumi.String("Finance"),
//						},
//					},
//				},
//				PlacementConfiguration: &core.ClusterNetworkPlacementConfigurationArgs{
//					AvailabilityDomain: pulumi.Any(clusterNetworkPlacementConfigurationAvailabilityDomain),
//					PrimaryVnicSubnets: &core.ClusterNetworkPlacementConfigurationPrimaryVnicSubnetsArgs{
//						SubnetId: pulumi.Any(testSubnet.Id),
//						Ipv6addressIpv6subnetCidrPairDetails: core.ClusterNetworkPlacementConfigurationPrimaryVnicSubnetsIpv6addressIpv6subnetCidrPairDetailArray{
//							&core.ClusterNetworkPlacementConfigurationPrimaryVnicSubnetsIpv6addressIpv6subnetCidrPairDetailArgs{
//								Ipv6subnetCidr: pulumi.Any(clusterNetworkPlacementConfigurationPrimaryVnicSubnetsIpv6addressIpv6subnetCidrPairDetailsIpv6subnetCidr),
//							},
//						},
//						IsAssignIpv6ip: pulumi.Any(clusterNetworkPlacementConfigurationPrimaryVnicSubnetsIsAssignIpv6ip),
//					},
//					SecondaryVnicSubnets: core.ClusterNetworkPlacementConfigurationSecondaryVnicSubnetArray{
//						&core.ClusterNetworkPlacementConfigurationSecondaryVnicSubnetArgs{
//							SubnetId:    pulumi.Any(testSubnet.Id),
//							DisplayName: pulumi.Any(clusterNetworkPlacementConfigurationSecondaryVnicSubnetsDisplayName),
//							Ipv6addressIpv6subnetCidrPairDetails: core.ClusterNetworkPlacementConfigurationSecondaryVnicSubnetIpv6addressIpv6subnetCidrPairDetailArray{
//								&core.ClusterNetworkPlacementConfigurationSecondaryVnicSubnetIpv6addressIpv6subnetCidrPairDetailArgs{
//									Ipv6subnetCidr: pulumi.Any(clusterNetworkPlacementConfigurationSecondaryVnicSubnetsIpv6addressIpv6subnetCidrPairDetailsIpv6subnetCidr),
//								},
//							},
//							IsAssignIpv6ip: pulumi.Any(clusterNetworkPlacementConfigurationSecondaryVnicSubnetsIsAssignIpv6ip),
//						},
//					},
//				},
//				ClusterConfiguration: &core.ClusterNetworkClusterConfigurationArgs{
//					HpcIslandId:     pulumi.Any(testHpcIsland.Id),
//					NetworkBlockIds: pulumi.Any(clusterNetworkClusterConfigurationNetworkBlockIds),
//				},
//				DefinedTags: pulumi.StringMap{
//					"Operations.CostCenter": pulumi.String("42"),
//				},
//				DisplayName: pulumi.Any(clusterNetworkDisplayName),
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
// ClusterNetworks can be imported using the `id`, e.g.
//
// ```sh
// $ pulumi import oci:Core/clusterNetwork:ClusterNetwork test_cluster_network "id"
// ```
type ClusterNetwork struct {
	pulumi.CustomResourceState

	// The HPC cluster configuration requested when launching instances of a cluster network.
	//
	// If the parameter is provided, instances will only be placed within the HPC island and list of network blocks that you specify. If a list of network blocks are missing or not provided, the instances will be placed in any HPC blocks in the HPC island that you specify. If the values of HPC island or network block that you provide are not valid, an error is returned.
	ClusterConfiguration ClusterNetworkClusterConfigurationOutput `pulumi:"clusterConfiguration"`
	// (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment containing the cluster network.
	CompartmentId pulumi.StringOutput `pulumi:"compartmentId"`
	// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Operations.CostCenter": "42"}`
	DefinedTags pulumi.StringMapOutput `pulumi:"definedTags"`
	// (Updatable) A user-friendly name. Does not have to be unique, and it's changeable. Avoid entering confidential information.
	DisplayName pulumi.StringOutput `pulumi:"displayName"`
	// (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
	FreeformTags pulumi.StringMapOutput `pulumi:"freeformTags"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the HPC island used by the cluster network.
	HpcIslandId pulumi.StringOutput `pulumi:"hpcIslandId"`
	// (Updatable) The data to create the instance pools in the cluster network.
	//
	// Each cluster network can have one instance pool.
	InstancePools ClusterNetworkInstancePoolArrayOutput `pulumi:"instancePools"`
	// The list of network block OCIDs of the HPC island.
	NetworkBlockIds pulumi.StringArrayOutput `pulumi:"networkBlockIds"`
	// The location for where the instance pools in a cluster network will place instances.
	PlacementConfiguration ClusterNetworkPlacementConfigurationOutput `pulumi:"placementConfiguration"`
	// The current state of the cluster network.
	State pulumi.StringOutput `pulumi:"state"`
	// The date and time the resource was created, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).  Example: `2016-08-25T21:10:29.600Z`
	TimeCreated pulumi.StringOutput `pulumi:"timeCreated"`
	// The date and time the resource was updated, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).  Example: `2016-08-25T21:10:29.600Z`
	TimeUpdated pulumi.StringOutput `pulumi:"timeUpdated"`
}

// NewClusterNetwork registers a new resource with the given unique name, arguments, and options.
func NewClusterNetwork(ctx *pulumi.Context,
	name string, args *ClusterNetworkArgs, opts ...pulumi.ResourceOption) (*ClusterNetwork, error) {
	if args == nil {
		return nil, errors.New("missing one or more required arguments")
	}

	if args.CompartmentId == nil {
		return nil, errors.New("invalid value for required argument 'CompartmentId'")
	}
	if args.InstancePools == nil {
		return nil, errors.New("invalid value for required argument 'InstancePools'")
	}
	if args.PlacementConfiguration == nil {
		return nil, errors.New("invalid value for required argument 'PlacementConfiguration'")
	}
	opts = internal.PkgResourceDefaultOpts(opts)
	var resource ClusterNetwork
	err := ctx.RegisterResource("oci:Core/clusterNetwork:ClusterNetwork", name, args, &resource, opts...)
	if err != nil {
		return nil, err
	}
	return &resource, nil
}

// GetClusterNetwork gets an existing ClusterNetwork resource's state with the given name, ID, and optional
// state properties that are used to uniquely qualify the lookup (nil if not required).
func GetClusterNetwork(ctx *pulumi.Context,
	name string, id pulumi.IDInput, state *ClusterNetworkState, opts ...pulumi.ResourceOption) (*ClusterNetwork, error) {
	var resource ClusterNetwork
	err := ctx.ReadResource("oci:Core/clusterNetwork:ClusterNetwork", name, id, state, &resource, opts...)
	if err != nil {
		return nil, err
	}
	return &resource, nil
}

// Input properties used for looking up and filtering ClusterNetwork resources.
type clusterNetworkState struct {
	// The HPC cluster configuration requested when launching instances of a cluster network.
	//
	// If the parameter is provided, instances will only be placed within the HPC island and list of network blocks that you specify. If a list of network blocks are missing or not provided, the instances will be placed in any HPC blocks in the HPC island that you specify. If the values of HPC island or network block that you provide are not valid, an error is returned.
	ClusterConfiguration *ClusterNetworkClusterConfiguration `pulumi:"clusterConfiguration"`
	// (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment containing the cluster network.
	CompartmentId *string `pulumi:"compartmentId"`
	// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Operations.CostCenter": "42"}`
	DefinedTags map[string]string `pulumi:"definedTags"`
	// (Updatable) A user-friendly name. Does not have to be unique, and it's changeable. Avoid entering confidential information.
	DisplayName *string `pulumi:"displayName"`
	// (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
	FreeformTags map[string]string `pulumi:"freeformTags"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the HPC island used by the cluster network.
	HpcIslandId *string `pulumi:"hpcIslandId"`
	// (Updatable) The data to create the instance pools in the cluster network.
	//
	// Each cluster network can have one instance pool.
	InstancePools []ClusterNetworkInstancePool `pulumi:"instancePools"`
	// The list of network block OCIDs of the HPC island.
	NetworkBlockIds []string `pulumi:"networkBlockIds"`
	// The location for where the instance pools in a cluster network will place instances.
	PlacementConfiguration *ClusterNetworkPlacementConfiguration `pulumi:"placementConfiguration"`
	// The current state of the cluster network.
	State *string `pulumi:"state"`
	// The date and time the resource was created, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).  Example: `2016-08-25T21:10:29.600Z`
	TimeCreated *string `pulumi:"timeCreated"`
	// The date and time the resource was updated, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).  Example: `2016-08-25T21:10:29.600Z`
	TimeUpdated *string `pulumi:"timeUpdated"`
}

type ClusterNetworkState struct {
	// The HPC cluster configuration requested when launching instances of a cluster network.
	//
	// If the parameter is provided, instances will only be placed within the HPC island and list of network blocks that you specify. If a list of network blocks are missing or not provided, the instances will be placed in any HPC blocks in the HPC island that you specify. If the values of HPC island or network block that you provide are not valid, an error is returned.
	ClusterConfiguration ClusterNetworkClusterConfigurationPtrInput
	// (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment containing the cluster network.
	CompartmentId pulumi.StringPtrInput
	// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Operations.CostCenter": "42"}`
	DefinedTags pulumi.StringMapInput
	// (Updatable) A user-friendly name. Does not have to be unique, and it's changeable. Avoid entering confidential information.
	DisplayName pulumi.StringPtrInput
	// (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
	FreeformTags pulumi.StringMapInput
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the HPC island used by the cluster network.
	HpcIslandId pulumi.StringPtrInput
	// (Updatable) The data to create the instance pools in the cluster network.
	//
	// Each cluster network can have one instance pool.
	InstancePools ClusterNetworkInstancePoolArrayInput
	// The list of network block OCIDs of the HPC island.
	NetworkBlockIds pulumi.StringArrayInput
	// The location for where the instance pools in a cluster network will place instances.
	PlacementConfiguration ClusterNetworkPlacementConfigurationPtrInput
	// The current state of the cluster network.
	State pulumi.StringPtrInput
	// The date and time the resource was created, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).  Example: `2016-08-25T21:10:29.600Z`
	TimeCreated pulumi.StringPtrInput
	// The date and time the resource was updated, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).  Example: `2016-08-25T21:10:29.600Z`
	TimeUpdated pulumi.StringPtrInput
}

func (ClusterNetworkState) ElementType() reflect.Type {
	return reflect.TypeOf((*clusterNetworkState)(nil)).Elem()
}

type clusterNetworkArgs struct {
	// The HPC cluster configuration requested when launching instances of a cluster network.
	//
	// If the parameter is provided, instances will only be placed within the HPC island and list of network blocks that you specify. If a list of network blocks are missing or not provided, the instances will be placed in any HPC blocks in the HPC island that you specify. If the values of HPC island or network block that you provide are not valid, an error is returned.
	ClusterConfiguration *ClusterNetworkClusterConfiguration `pulumi:"clusterConfiguration"`
	// (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment containing the cluster network.
	CompartmentId string `pulumi:"compartmentId"`
	// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Operations.CostCenter": "42"}`
	DefinedTags map[string]string `pulumi:"definedTags"`
	// (Updatable) A user-friendly name. Does not have to be unique, and it's changeable. Avoid entering confidential information.
	DisplayName *string `pulumi:"displayName"`
	// (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
	FreeformTags map[string]string `pulumi:"freeformTags"`
	// (Updatable) The data to create the instance pools in the cluster network.
	//
	// Each cluster network can have one instance pool.
	InstancePools []ClusterNetworkInstancePool `pulumi:"instancePools"`
	// The location for where the instance pools in a cluster network will place instances.
	PlacementConfiguration ClusterNetworkPlacementConfiguration `pulumi:"placementConfiguration"`
}

// The set of arguments for constructing a ClusterNetwork resource.
type ClusterNetworkArgs struct {
	// The HPC cluster configuration requested when launching instances of a cluster network.
	//
	// If the parameter is provided, instances will only be placed within the HPC island and list of network blocks that you specify. If a list of network blocks are missing or not provided, the instances will be placed in any HPC blocks in the HPC island that you specify. If the values of HPC island or network block that you provide are not valid, an error is returned.
	ClusterConfiguration ClusterNetworkClusterConfigurationPtrInput
	// (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment containing the cluster network.
	CompartmentId pulumi.StringInput
	// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Operations.CostCenter": "42"}`
	DefinedTags pulumi.StringMapInput
	// (Updatable) A user-friendly name. Does not have to be unique, and it's changeable. Avoid entering confidential information.
	DisplayName pulumi.StringPtrInput
	// (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
	FreeformTags pulumi.StringMapInput
	// (Updatable) The data to create the instance pools in the cluster network.
	//
	// Each cluster network can have one instance pool.
	InstancePools ClusterNetworkInstancePoolArrayInput
	// The location for where the instance pools in a cluster network will place instances.
	PlacementConfiguration ClusterNetworkPlacementConfigurationInput
}

func (ClusterNetworkArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*clusterNetworkArgs)(nil)).Elem()
}

type ClusterNetworkInput interface {
	pulumi.Input

	ToClusterNetworkOutput() ClusterNetworkOutput
	ToClusterNetworkOutputWithContext(ctx context.Context) ClusterNetworkOutput
}

func (*ClusterNetwork) ElementType() reflect.Type {
	return reflect.TypeOf((**ClusterNetwork)(nil)).Elem()
}

func (i *ClusterNetwork) ToClusterNetworkOutput() ClusterNetworkOutput {
	return i.ToClusterNetworkOutputWithContext(context.Background())
}

func (i *ClusterNetwork) ToClusterNetworkOutputWithContext(ctx context.Context) ClusterNetworkOutput {
	return pulumi.ToOutputWithContext(ctx, i).(ClusterNetworkOutput)
}

// ClusterNetworkArrayInput is an input type that accepts ClusterNetworkArray and ClusterNetworkArrayOutput values.
// You can construct a concrete instance of `ClusterNetworkArrayInput` via:
//
//	ClusterNetworkArray{ ClusterNetworkArgs{...} }
type ClusterNetworkArrayInput interface {
	pulumi.Input

	ToClusterNetworkArrayOutput() ClusterNetworkArrayOutput
	ToClusterNetworkArrayOutputWithContext(context.Context) ClusterNetworkArrayOutput
}

type ClusterNetworkArray []ClusterNetworkInput

func (ClusterNetworkArray) ElementType() reflect.Type {
	return reflect.TypeOf((*[]*ClusterNetwork)(nil)).Elem()
}

func (i ClusterNetworkArray) ToClusterNetworkArrayOutput() ClusterNetworkArrayOutput {
	return i.ToClusterNetworkArrayOutputWithContext(context.Background())
}

func (i ClusterNetworkArray) ToClusterNetworkArrayOutputWithContext(ctx context.Context) ClusterNetworkArrayOutput {
	return pulumi.ToOutputWithContext(ctx, i).(ClusterNetworkArrayOutput)
}

// ClusterNetworkMapInput is an input type that accepts ClusterNetworkMap and ClusterNetworkMapOutput values.
// You can construct a concrete instance of `ClusterNetworkMapInput` via:
//
//	ClusterNetworkMap{ "key": ClusterNetworkArgs{...} }
type ClusterNetworkMapInput interface {
	pulumi.Input

	ToClusterNetworkMapOutput() ClusterNetworkMapOutput
	ToClusterNetworkMapOutputWithContext(context.Context) ClusterNetworkMapOutput
}

type ClusterNetworkMap map[string]ClusterNetworkInput

func (ClusterNetworkMap) ElementType() reflect.Type {
	return reflect.TypeOf((*map[string]*ClusterNetwork)(nil)).Elem()
}

func (i ClusterNetworkMap) ToClusterNetworkMapOutput() ClusterNetworkMapOutput {
	return i.ToClusterNetworkMapOutputWithContext(context.Background())
}

func (i ClusterNetworkMap) ToClusterNetworkMapOutputWithContext(ctx context.Context) ClusterNetworkMapOutput {
	return pulumi.ToOutputWithContext(ctx, i).(ClusterNetworkMapOutput)
}

type ClusterNetworkOutput struct{ *pulumi.OutputState }

func (ClusterNetworkOutput) ElementType() reflect.Type {
	return reflect.TypeOf((**ClusterNetwork)(nil)).Elem()
}

func (o ClusterNetworkOutput) ToClusterNetworkOutput() ClusterNetworkOutput {
	return o
}

func (o ClusterNetworkOutput) ToClusterNetworkOutputWithContext(ctx context.Context) ClusterNetworkOutput {
	return o
}

// The HPC cluster configuration requested when launching instances of a cluster network.
//
// If the parameter is provided, instances will only be placed within the HPC island and list of network blocks that you specify. If a list of network blocks are missing or not provided, the instances will be placed in any HPC blocks in the HPC island that you specify. If the values of HPC island or network block that you provide are not valid, an error is returned.
func (o ClusterNetworkOutput) ClusterConfiguration() ClusterNetworkClusterConfigurationOutput {
	return o.ApplyT(func(v *ClusterNetwork) ClusterNetworkClusterConfigurationOutput { return v.ClusterConfiguration }).(ClusterNetworkClusterConfigurationOutput)
}

// (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment containing the cluster network.
func (o ClusterNetworkOutput) CompartmentId() pulumi.StringOutput {
	return o.ApplyT(func(v *ClusterNetwork) pulumi.StringOutput { return v.CompartmentId }).(pulumi.StringOutput)
}

// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Operations.CostCenter": "42"}`
func (o ClusterNetworkOutput) DefinedTags() pulumi.StringMapOutput {
	return o.ApplyT(func(v *ClusterNetwork) pulumi.StringMapOutput { return v.DefinedTags }).(pulumi.StringMapOutput)
}

// (Updatable) A user-friendly name. Does not have to be unique, and it's changeable. Avoid entering confidential information.
func (o ClusterNetworkOutput) DisplayName() pulumi.StringOutput {
	return o.ApplyT(func(v *ClusterNetwork) pulumi.StringOutput { return v.DisplayName }).(pulumi.StringOutput)
}

// (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
func (o ClusterNetworkOutput) FreeformTags() pulumi.StringMapOutput {
	return o.ApplyT(func(v *ClusterNetwork) pulumi.StringMapOutput { return v.FreeformTags }).(pulumi.StringMapOutput)
}

// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the HPC island used by the cluster network.
func (o ClusterNetworkOutput) HpcIslandId() pulumi.StringOutput {
	return o.ApplyT(func(v *ClusterNetwork) pulumi.StringOutput { return v.HpcIslandId }).(pulumi.StringOutput)
}

// (Updatable) The data to create the instance pools in the cluster network.
//
// Each cluster network can have one instance pool.
func (o ClusterNetworkOutput) InstancePools() ClusterNetworkInstancePoolArrayOutput {
	return o.ApplyT(func(v *ClusterNetwork) ClusterNetworkInstancePoolArrayOutput { return v.InstancePools }).(ClusterNetworkInstancePoolArrayOutput)
}

// The list of network block OCIDs of the HPC island.
func (o ClusterNetworkOutput) NetworkBlockIds() pulumi.StringArrayOutput {
	return o.ApplyT(func(v *ClusterNetwork) pulumi.StringArrayOutput { return v.NetworkBlockIds }).(pulumi.StringArrayOutput)
}

// The location for where the instance pools in a cluster network will place instances.
func (o ClusterNetworkOutput) PlacementConfiguration() ClusterNetworkPlacementConfigurationOutput {
	return o.ApplyT(func(v *ClusterNetwork) ClusterNetworkPlacementConfigurationOutput { return v.PlacementConfiguration }).(ClusterNetworkPlacementConfigurationOutput)
}

// The current state of the cluster network.
func (o ClusterNetworkOutput) State() pulumi.StringOutput {
	return o.ApplyT(func(v *ClusterNetwork) pulumi.StringOutput { return v.State }).(pulumi.StringOutput)
}

// The date and time the resource was created, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).  Example: `2016-08-25T21:10:29.600Z`
func (o ClusterNetworkOutput) TimeCreated() pulumi.StringOutput {
	return o.ApplyT(func(v *ClusterNetwork) pulumi.StringOutput { return v.TimeCreated }).(pulumi.StringOutput)
}

// The date and time the resource was updated, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).  Example: `2016-08-25T21:10:29.600Z`
func (o ClusterNetworkOutput) TimeUpdated() pulumi.StringOutput {
	return o.ApplyT(func(v *ClusterNetwork) pulumi.StringOutput { return v.TimeUpdated }).(pulumi.StringOutput)
}

type ClusterNetworkArrayOutput struct{ *pulumi.OutputState }

func (ClusterNetworkArrayOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*[]*ClusterNetwork)(nil)).Elem()
}

func (o ClusterNetworkArrayOutput) ToClusterNetworkArrayOutput() ClusterNetworkArrayOutput {
	return o
}

func (o ClusterNetworkArrayOutput) ToClusterNetworkArrayOutputWithContext(ctx context.Context) ClusterNetworkArrayOutput {
	return o
}

func (o ClusterNetworkArrayOutput) Index(i pulumi.IntInput) ClusterNetworkOutput {
	return pulumi.All(o, i).ApplyT(func(vs []interface{}) *ClusterNetwork {
		return vs[0].([]*ClusterNetwork)[vs[1].(int)]
	}).(ClusterNetworkOutput)
}

type ClusterNetworkMapOutput struct{ *pulumi.OutputState }

func (ClusterNetworkMapOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*map[string]*ClusterNetwork)(nil)).Elem()
}

func (o ClusterNetworkMapOutput) ToClusterNetworkMapOutput() ClusterNetworkMapOutput {
	return o
}

func (o ClusterNetworkMapOutput) ToClusterNetworkMapOutputWithContext(ctx context.Context) ClusterNetworkMapOutput {
	return o
}

func (o ClusterNetworkMapOutput) MapIndex(k pulumi.StringInput) ClusterNetworkOutput {
	return pulumi.All(o, k).ApplyT(func(vs []interface{}) *ClusterNetwork {
		return vs[0].(map[string]*ClusterNetwork)[vs[1].(string)]
	}).(ClusterNetworkOutput)
}

func init() {
	pulumi.RegisterInputType(reflect.TypeOf((*ClusterNetworkInput)(nil)).Elem(), &ClusterNetwork{})
	pulumi.RegisterInputType(reflect.TypeOf((*ClusterNetworkArrayInput)(nil)).Elem(), ClusterNetworkArray{})
	pulumi.RegisterInputType(reflect.TypeOf((*ClusterNetworkMapInput)(nil)).Elem(), ClusterNetworkMap{})
	pulumi.RegisterOutputType(ClusterNetworkOutput{})
	pulumi.RegisterOutputType(ClusterNetworkArrayOutput{})
	pulumi.RegisterOutputType(ClusterNetworkMapOutput{})
}
