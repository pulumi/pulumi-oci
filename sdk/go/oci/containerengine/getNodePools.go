// Code generated by the Pulumi Terraform Bridge (tfgen) Tool DO NOT EDIT.
// *** WARNING: Do not edit by hand unless you're certain you know what you are doing! ***

package containerengine

import (
	"context"
	"reflect"

	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This data source provides the list of Node Pools in Oracle Cloud Infrastructure Container Engine service.
//
// List all the node pools in a compartment, and optionally filter by cluster.
//
// ## Example Usage
//
// ```go
// package main
//
// import (
//
//	"github.com/pulumi/pulumi-oci/sdk/go/oci/ContainerEngine"
//	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
//
// )
//
//	func main() {
//		pulumi.Run(func(ctx *pulumi.Context) error {
//			_, err := ContainerEngine.GetNodePools(ctx, &containerengine.GetNodePoolsArgs{
//				CompartmentId: _var.Compartment_id,
//				ClusterId:     pulumi.StringRef(oci_containerengine_cluster.Test_cluster.Id),
//				Name:          pulumi.StringRef(_var.Node_pool_name),
//				States:        _var.Node_pool_state,
//			}, nil)
//			if err != nil {
//				return err
//			}
//			return nil
//		})
//	}
//
// ```
func GetNodePools(ctx *pulumi.Context, args *GetNodePoolsArgs, opts ...pulumi.InvokeOption) (*GetNodePoolsResult, error) {
	var rv GetNodePoolsResult
	err := ctx.Invoke("oci:ContainerEngine/getNodePools:getNodePools", args, &rv, opts...)
	if err != nil {
		return nil, err
	}
	return &rv, nil
}

// A collection of arguments for invoking getNodePools.
type GetNodePoolsArgs struct {
	// The OCID of the cluster.
	ClusterId *string `pulumi:"clusterId"`
	// The OCID of the compartment.
	CompartmentId string               `pulumi:"compartmentId"`
	Filters       []GetNodePoolsFilter `pulumi:"filters"`
	// The name to filter on.
	Name *string `pulumi:"name"`
	// A list of nodepool lifecycle states on which to filter on, matching any of the list items (OR logic). eg. [ACTIVE, DELETING]
	States []string `pulumi:"states"`
}

// A collection of values returned by getNodePools.
type GetNodePoolsResult struct {
	// The OCID of the cluster to which this node pool is attached.
	ClusterId *string `pulumi:"clusterId"`
	// The OCID of the compartment in which the node pool exists.
	CompartmentId string               `pulumi:"compartmentId"`
	Filters       []GetNodePoolsFilter `pulumi:"filters"`
	// The provider-assigned unique ID for this managed resource.
	Id string `pulumi:"id"`
	// The name of the node.
	Name *string `pulumi:"name"`
	// The list of node_pools.
	NodePools []GetNodePoolsNodePool `pulumi:"nodePools"`
	// The state of the nodepool.
	States []string `pulumi:"states"`
}

func GetNodePoolsOutput(ctx *pulumi.Context, args GetNodePoolsOutputArgs, opts ...pulumi.InvokeOption) GetNodePoolsResultOutput {
	return pulumi.ToOutputWithContext(context.Background(), args).
		ApplyT(func(v interface{}) (GetNodePoolsResult, error) {
			args := v.(GetNodePoolsArgs)
			r, err := GetNodePools(ctx, &args, opts...)
			var s GetNodePoolsResult
			if r != nil {
				s = *r
			}
			return s, err
		}).(GetNodePoolsResultOutput)
}

// A collection of arguments for invoking getNodePools.
type GetNodePoolsOutputArgs struct {
	// The OCID of the cluster.
	ClusterId pulumi.StringPtrInput `pulumi:"clusterId"`
	// The OCID of the compartment.
	CompartmentId pulumi.StringInput           `pulumi:"compartmentId"`
	Filters       GetNodePoolsFilterArrayInput `pulumi:"filters"`
	// The name to filter on.
	Name pulumi.StringPtrInput `pulumi:"name"`
	// A list of nodepool lifecycle states on which to filter on, matching any of the list items (OR logic). eg. [ACTIVE, DELETING]
	States pulumi.StringArrayInput `pulumi:"states"`
}

func (GetNodePoolsOutputArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*GetNodePoolsArgs)(nil)).Elem()
}

// A collection of values returned by getNodePools.
type GetNodePoolsResultOutput struct{ *pulumi.OutputState }

func (GetNodePoolsResultOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*GetNodePoolsResult)(nil)).Elem()
}

func (o GetNodePoolsResultOutput) ToGetNodePoolsResultOutput() GetNodePoolsResultOutput {
	return o
}

func (o GetNodePoolsResultOutput) ToGetNodePoolsResultOutputWithContext(ctx context.Context) GetNodePoolsResultOutput {
	return o
}

// The OCID of the cluster to which this node pool is attached.
func (o GetNodePoolsResultOutput) ClusterId() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetNodePoolsResult) *string { return v.ClusterId }).(pulumi.StringPtrOutput)
}

// The OCID of the compartment in which the node pool exists.
func (o GetNodePoolsResultOutput) CompartmentId() pulumi.StringOutput {
	return o.ApplyT(func(v GetNodePoolsResult) string { return v.CompartmentId }).(pulumi.StringOutput)
}

func (o GetNodePoolsResultOutput) Filters() GetNodePoolsFilterArrayOutput {
	return o.ApplyT(func(v GetNodePoolsResult) []GetNodePoolsFilter { return v.Filters }).(GetNodePoolsFilterArrayOutput)
}

// The provider-assigned unique ID for this managed resource.
func (o GetNodePoolsResultOutput) Id() pulumi.StringOutput {
	return o.ApplyT(func(v GetNodePoolsResult) string { return v.Id }).(pulumi.StringOutput)
}

// The name of the node.
func (o GetNodePoolsResultOutput) Name() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetNodePoolsResult) *string { return v.Name }).(pulumi.StringPtrOutput)
}

// The list of node_pools.
func (o GetNodePoolsResultOutput) NodePools() GetNodePoolsNodePoolArrayOutput {
	return o.ApplyT(func(v GetNodePoolsResult) []GetNodePoolsNodePool { return v.NodePools }).(GetNodePoolsNodePoolArrayOutput)
}

// The state of the nodepool.
func (o GetNodePoolsResultOutput) States() pulumi.StringArrayOutput {
	return o.ApplyT(func(v GetNodePoolsResult) []string { return v.States }).(pulumi.StringArrayOutput)
}

func init() {
	pulumi.RegisterOutputType(GetNodePoolsResultOutput{})
}