// Code generated by the Pulumi Terraform Bridge (tfgen) Tool DO NOT EDIT.
// *** WARNING: Do not edit by hand unless you're certain you know what you are doing! ***

package mysql

import (
	"context"
	"reflect"

	"github.com/pkg/errors"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This resource provides the HeatWave cluster resource in Oracle Cloud Infrastructure MySQL Database service.
//
// Updates the HeatWave cluster.
//
// ## Example Usage
//
// ```go
// package main
//
// import (
//
//	"github.com/pulumi/pulumi-oci/sdk/go/oci/Mysql"
//	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
//
// )
//
//	func main() {
//		pulumi.Run(func(ctx *pulumi.Context) error {
//			_, err := Mysql.NewHeatWaveCluster(ctx, "testHeatWaveCluster", &Mysql.HeatWaveClusterArgs{
//				DbSystemId:  pulumi.Any(oci_database_db_system.Test_db_system.Id),
//				ClusterSize: pulumi.Any(_var.Heat_wave_cluster_cluster_size),
//				ShapeName:   pulumi.Any(oci_mysql_shape.Test_shape.Name),
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
// HeatWaveCluster can be imported using the `id`, e.g.
//
// ```sh
//
//	$ pulumi import oci:Mysql/heatWaveCluster:HeatWaveCluster test_heat_wave_cluster "dbSystem/{dbSystemId}/heatWaveCluster"
//
// ```
type HeatWaveCluster struct {
	pulumi.CustomResourceState

	// A HeatWave node is a compute host that is part of a HeatWave cluster.
	ClusterNodes HeatWaveClusterClusterNodeArrayOutput `pulumi:"clusterNodes"`
	// (Updatable) A change to the number of nodes in the HeatWave cluster will result in the entire cluster being torn down and re-created with the new cluster of nodes. This may result in a significant downtime for the analytics capability while the HeatWave cluster is re-provisioned.
	ClusterSize pulumi.IntOutput `pulumi:"clusterSize"`
	// The DB System [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
	DbSystemId pulumi.StringOutput `pulumi:"dbSystemId"`
	// Additional information about the current lifecycleState.
	LifecycleDetails pulumi.StringOutput `pulumi:"lifecycleDetails"`
	// (Updatable) A change to the shape of the nodes in the HeatWave cluster will result in the entire cluster being torn down and re-created with Compute instances of the new Shape. This may result in significant downtime for the analytics capability while the HeatWave cluster is re-provisioned.
	ShapeName pulumi.StringOutput `pulumi:"shapeName"`
	// (Updatable) The target state for the HeatWave cluster. Could be set to `ACTIVE` or `INACTIVE`.
	State pulumi.StringOutput `pulumi:"state"`
	// The date and time the HeatWave cluster was created, as described by [RFC 3339](https://tools.ietf.org/rfc/rfc3339).
	TimeCreated pulumi.StringOutput `pulumi:"timeCreated"`
	// The time the HeatWave cluster was last updated, as described by [RFC 3339](https://tools.ietf.org/rfc/rfc3339).
	TimeUpdated pulumi.StringOutput `pulumi:"timeUpdated"`
}

// NewHeatWaveCluster registers a new resource with the given unique name, arguments, and options.
func NewHeatWaveCluster(ctx *pulumi.Context,
	name string, args *HeatWaveClusterArgs, opts ...pulumi.ResourceOption) (*HeatWaveCluster, error) {
	if args == nil {
		return nil, errors.New("missing one or more required arguments")
	}

	if args.ClusterSize == nil {
		return nil, errors.New("invalid value for required argument 'ClusterSize'")
	}
	if args.DbSystemId == nil {
		return nil, errors.New("invalid value for required argument 'DbSystemId'")
	}
	if args.ShapeName == nil {
		return nil, errors.New("invalid value for required argument 'ShapeName'")
	}
	var resource HeatWaveCluster
	err := ctx.RegisterResource("oci:Mysql/heatWaveCluster:HeatWaveCluster", name, args, &resource, opts...)
	if err != nil {
		return nil, err
	}
	return &resource, nil
}

// GetHeatWaveCluster gets an existing HeatWaveCluster resource's state with the given name, ID, and optional
// state properties that are used to uniquely qualify the lookup (nil if not required).
func GetHeatWaveCluster(ctx *pulumi.Context,
	name string, id pulumi.IDInput, state *HeatWaveClusterState, opts ...pulumi.ResourceOption) (*HeatWaveCluster, error) {
	var resource HeatWaveCluster
	err := ctx.ReadResource("oci:Mysql/heatWaveCluster:HeatWaveCluster", name, id, state, &resource, opts...)
	if err != nil {
		return nil, err
	}
	return &resource, nil
}

// Input properties used for looking up and filtering HeatWaveCluster resources.
type heatWaveClusterState struct {
	// A HeatWave node is a compute host that is part of a HeatWave cluster.
	ClusterNodes []HeatWaveClusterClusterNode `pulumi:"clusterNodes"`
	// (Updatable) A change to the number of nodes in the HeatWave cluster will result in the entire cluster being torn down and re-created with the new cluster of nodes. This may result in a significant downtime for the analytics capability while the HeatWave cluster is re-provisioned.
	ClusterSize *int `pulumi:"clusterSize"`
	// The DB System [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
	DbSystemId *string `pulumi:"dbSystemId"`
	// Additional information about the current lifecycleState.
	LifecycleDetails *string `pulumi:"lifecycleDetails"`
	// (Updatable) A change to the shape of the nodes in the HeatWave cluster will result in the entire cluster being torn down and re-created with Compute instances of the new Shape. This may result in significant downtime for the analytics capability while the HeatWave cluster is re-provisioned.
	ShapeName *string `pulumi:"shapeName"`
	// (Updatable) The target state for the HeatWave cluster. Could be set to `ACTIVE` or `INACTIVE`.
	State *string `pulumi:"state"`
	// The date and time the HeatWave cluster was created, as described by [RFC 3339](https://tools.ietf.org/rfc/rfc3339).
	TimeCreated *string `pulumi:"timeCreated"`
	// The time the HeatWave cluster was last updated, as described by [RFC 3339](https://tools.ietf.org/rfc/rfc3339).
	TimeUpdated *string `pulumi:"timeUpdated"`
}

type HeatWaveClusterState struct {
	// A HeatWave node is a compute host that is part of a HeatWave cluster.
	ClusterNodes HeatWaveClusterClusterNodeArrayInput
	// (Updatable) A change to the number of nodes in the HeatWave cluster will result in the entire cluster being torn down and re-created with the new cluster of nodes. This may result in a significant downtime for the analytics capability while the HeatWave cluster is re-provisioned.
	ClusterSize pulumi.IntPtrInput
	// The DB System [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
	DbSystemId pulumi.StringPtrInput
	// Additional information about the current lifecycleState.
	LifecycleDetails pulumi.StringPtrInput
	// (Updatable) A change to the shape of the nodes in the HeatWave cluster will result in the entire cluster being torn down and re-created with Compute instances of the new Shape. This may result in significant downtime for the analytics capability while the HeatWave cluster is re-provisioned.
	ShapeName pulumi.StringPtrInput
	// (Updatable) The target state for the HeatWave cluster. Could be set to `ACTIVE` or `INACTIVE`.
	State pulumi.StringPtrInput
	// The date and time the HeatWave cluster was created, as described by [RFC 3339](https://tools.ietf.org/rfc/rfc3339).
	TimeCreated pulumi.StringPtrInput
	// The time the HeatWave cluster was last updated, as described by [RFC 3339](https://tools.ietf.org/rfc/rfc3339).
	TimeUpdated pulumi.StringPtrInput
}

func (HeatWaveClusterState) ElementType() reflect.Type {
	return reflect.TypeOf((*heatWaveClusterState)(nil)).Elem()
}

type heatWaveClusterArgs struct {
	// (Updatable) A change to the number of nodes in the HeatWave cluster will result in the entire cluster being torn down and re-created with the new cluster of nodes. This may result in a significant downtime for the analytics capability while the HeatWave cluster is re-provisioned.
	ClusterSize int `pulumi:"clusterSize"`
	// The DB System [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
	DbSystemId string `pulumi:"dbSystemId"`
	// (Updatable) A change to the shape of the nodes in the HeatWave cluster will result in the entire cluster being torn down and re-created with Compute instances of the new Shape. This may result in significant downtime for the analytics capability while the HeatWave cluster is re-provisioned.
	ShapeName string `pulumi:"shapeName"`
	// (Updatable) The target state for the HeatWave cluster. Could be set to `ACTIVE` or `INACTIVE`.
	State *string `pulumi:"state"`
}

// The set of arguments for constructing a HeatWaveCluster resource.
type HeatWaveClusterArgs struct {
	// (Updatable) A change to the number of nodes in the HeatWave cluster will result in the entire cluster being torn down and re-created with the new cluster of nodes. This may result in a significant downtime for the analytics capability while the HeatWave cluster is re-provisioned.
	ClusterSize pulumi.IntInput
	// The DB System [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
	DbSystemId pulumi.StringInput
	// (Updatable) A change to the shape of the nodes in the HeatWave cluster will result in the entire cluster being torn down and re-created with Compute instances of the new Shape. This may result in significant downtime for the analytics capability while the HeatWave cluster is re-provisioned.
	ShapeName pulumi.StringInput
	// (Updatable) The target state for the HeatWave cluster. Could be set to `ACTIVE` or `INACTIVE`.
	State pulumi.StringPtrInput
}

func (HeatWaveClusterArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*heatWaveClusterArgs)(nil)).Elem()
}

type HeatWaveClusterInput interface {
	pulumi.Input

	ToHeatWaveClusterOutput() HeatWaveClusterOutput
	ToHeatWaveClusterOutputWithContext(ctx context.Context) HeatWaveClusterOutput
}

func (*HeatWaveCluster) ElementType() reflect.Type {
	return reflect.TypeOf((**HeatWaveCluster)(nil)).Elem()
}

func (i *HeatWaveCluster) ToHeatWaveClusterOutput() HeatWaveClusterOutput {
	return i.ToHeatWaveClusterOutputWithContext(context.Background())
}

func (i *HeatWaveCluster) ToHeatWaveClusterOutputWithContext(ctx context.Context) HeatWaveClusterOutput {
	return pulumi.ToOutputWithContext(ctx, i).(HeatWaveClusterOutput)
}

// HeatWaveClusterArrayInput is an input type that accepts HeatWaveClusterArray and HeatWaveClusterArrayOutput values.
// You can construct a concrete instance of `HeatWaveClusterArrayInput` via:
//
//	HeatWaveClusterArray{ HeatWaveClusterArgs{...} }
type HeatWaveClusterArrayInput interface {
	pulumi.Input

	ToHeatWaveClusterArrayOutput() HeatWaveClusterArrayOutput
	ToHeatWaveClusterArrayOutputWithContext(context.Context) HeatWaveClusterArrayOutput
}

type HeatWaveClusterArray []HeatWaveClusterInput

func (HeatWaveClusterArray) ElementType() reflect.Type {
	return reflect.TypeOf((*[]*HeatWaveCluster)(nil)).Elem()
}

func (i HeatWaveClusterArray) ToHeatWaveClusterArrayOutput() HeatWaveClusterArrayOutput {
	return i.ToHeatWaveClusterArrayOutputWithContext(context.Background())
}

func (i HeatWaveClusterArray) ToHeatWaveClusterArrayOutputWithContext(ctx context.Context) HeatWaveClusterArrayOutput {
	return pulumi.ToOutputWithContext(ctx, i).(HeatWaveClusterArrayOutput)
}

// HeatWaveClusterMapInput is an input type that accepts HeatWaveClusterMap and HeatWaveClusterMapOutput values.
// You can construct a concrete instance of `HeatWaveClusterMapInput` via:
//
//	HeatWaveClusterMap{ "key": HeatWaveClusterArgs{...} }
type HeatWaveClusterMapInput interface {
	pulumi.Input

	ToHeatWaveClusterMapOutput() HeatWaveClusterMapOutput
	ToHeatWaveClusterMapOutputWithContext(context.Context) HeatWaveClusterMapOutput
}

type HeatWaveClusterMap map[string]HeatWaveClusterInput

func (HeatWaveClusterMap) ElementType() reflect.Type {
	return reflect.TypeOf((*map[string]*HeatWaveCluster)(nil)).Elem()
}

func (i HeatWaveClusterMap) ToHeatWaveClusterMapOutput() HeatWaveClusterMapOutput {
	return i.ToHeatWaveClusterMapOutputWithContext(context.Background())
}

func (i HeatWaveClusterMap) ToHeatWaveClusterMapOutputWithContext(ctx context.Context) HeatWaveClusterMapOutput {
	return pulumi.ToOutputWithContext(ctx, i).(HeatWaveClusterMapOutput)
}

type HeatWaveClusterOutput struct{ *pulumi.OutputState }

func (HeatWaveClusterOutput) ElementType() reflect.Type {
	return reflect.TypeOf((**HeatWaveCluster)(nil)).Elem()
}

func (o HeatWaveClusterOutput) ToHeatWaveClusterOutput() HeatWaveClusterOutput {
	return o
}

func (o HeatWaveClusterOutput) ToHeatWaveClusterOutputWithContext(ctx context.Context) HeatWaveClusterOutput {
	return o
}

// A HeatWave node is a compute host that is part of a HeatWave cluster.
func (o HeatWaveClusterOutput) ClusterNodes() HeatWaveClusterClusterNodeArrayOutput {
	return o.ApplyT(func(v *HeatWaveCluster) HeatWaveClusterClusterNodeArrayOutput { return v.ClusterNodes }).(HeatWaveClusterClusterNodeArrayOutput)
}

// (Updatable) A change to the number of nodes in the HeatWave cluster will result in the entire cluster being torn down and re-created with the new cluster of nodes. This may result in a significant downtime for the analytics capability while the HeatWave cluster is re-provisioned.
func (o HeatWaveClusterOutput) ClusterSize() pulumi.IntOutput {
	return o.ApplyT(func(v *HeatWaveCluster) pulumi.IntOutput { return v.ClusterSize }).(pulumi.IntOutput)
}

// The DB System [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
func (o HeatWaveClusterOutput) DbSystemId() pulumi.StringOutput {
	return o.ApplyT(func(v *HeatWaveCluster) pulumi.StringOutput { return v.DbSystemId }).(pulumi.StringOutput)
}

// Additional information about the current lifecycleState.
func (o HeatWaveClusterOutput) LifecycleDetails() pulumi.StringOutput {
	return o.ApplyT(func(v *HeatWaveCluster) pulumi.StringOutput { return v.LifecycleDetails }).(pulumi.StringOutput)
}

// (Updatable) A change to the shape of the nodes in the HeatWave cluster will result in the entire cluster being torn down and re-created with Compute instances of the new Shape. This may result in significant downtime for the analytics capability while the HeatWave cluster is re-provisioned.
func (o HeatWaveClusterOutput) ShapeName() pulumi.StringOutput {
	return o.ApplyT(func(v *HeatWaveCluster) pulumi.StringOutput { return v.ShapeName }).(pulumi.StringOutput)
}

// (Updatable) The target state for the HeatWave cluster. Could be set to `ACTIVE` or `INACTIVE`.
func (o HeatWaveClusterOutput) State() pulumi.StringOutput {
	return o.ApplyT(func(v *HeatWaveCluster) pulumi.StringOutput { return v.State }).(pulumi.StringOutput)
}

// The date and time the HeatWave cluster was created, as described by [RFC 3339](https://tools.ietf.org/rfc/rfc3339).
func (o HeatWaveClusterOutput) TimeCreated() pulumi.StringOutput {
	return o.ApplyT(func(v *HeatWaveCluster) pulumi.StringOutput { return v.TimeCreated }).(pulumi.StringOutput)
}

// The time the HeatWave cluster was last updated, as described by [RFC 3339](https://tools.ietf.org/rfc/rfc3339).
func (o HeatWaveClusterOutput) TimeUpdated() pulumi.StringOutput {
	return o.ApplyT(func(v *HeatWaveCluster) pulumi.StringOutput { return v.TimeUpdated }).(pulumi.StringOutput)
}

type HeatWaveClusterArrayOutput struct{ *pulumi.OutputState }

func (HeatWaveClusterArrayOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*[]*HeatWaveCluster)(nil)).Elem()
}

func (o HeatWaveClusterArrayOutput) ToHeatWaveClusterArrayOutput() HeatWaveClusterArrayOutput {
	return o
}

func (o HeatWaveClusterArrayOutput) ToHeatWaveClusterArrayOutputWithContext(ctx context.Context) HeatWaveClusterArrayOutput {
	return o
}

func (o HeatWaveClusterArrayOutput) Index(i pulumi.IntInput) HeatWaveClusterOutput {
	return pulumi.All(o, i).ApplyT(func(vs []interface{}) *HeatWaveCluster {
		return vs[0].([]*HeatWaveCluster)[vs[1].(int)]
	}).(HeatWaveClusterOutput)
}

type HeatWaveClusterMapOutput struct{ *pulumi.OutputState }

func (HeatWaveClusterMapOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*map[string]*HeatWaveCluster)(nil)).Elem()
}

func (o HeatWaveClusterMapOutput) ToHeatWaveClusterMapOutput() HeatWaveClusterMapOutput {
	return o
}

func (o HeatWaveClusterMapOutput) ToHeatWaveClusterMapOutputWithContext(ctx context.Context) HeatWaveClusterMapOutput {
	return o
}

func (o HeatWaveClusterMapOutput) MapIndex(k pulumi.StringInput) HeatWaveClusterOutput {
	return pulumi.All(o, k).ApplyT(func(vs []interface{}) *HeatWaveCluster {
		return vs[0].(map[string]*HeatWaveCluster)[vs[1].(string)]
	}).(HeatWaveClusterOutput)
}

func init() {
	pulumi.RegisterInputType(reflect.TypeOf((*HeatWaveClusterInput)(nil)).Elem(), &HeatWaveCluster{})
	pulumi.RegisterInputType(reflect.TypeOf((*HeatWaveClusterArrayInput)(nil)).Elem(), HeatWaveClusterArray{})
	pulumi.RegisterInputType(reflect.TypeOf((*HeatWaveClusterMapInput)(nil)).Elem(), HeatWaveClusterMap{})
	pulumi.RegisterOutputType(HeatWaveClusterOutput{})
	pulumi.RegisterOutputType(HeatWaveClusterArrayOutput{})
	pulumi.RegisterOutputType(HeatWaveClusterMapOutput{})
}