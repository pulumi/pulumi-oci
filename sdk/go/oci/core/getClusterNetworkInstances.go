// Code generated by pulumi-language-go DO NOT EDIT.
// *** WARNING: Do not edit by hand unless you're certain you know what you are doing! ***

package core

import (
	"context"
	"reflect"

	"github.com/pulumi/pulumi-oci/sdk/v3/go/oci/internal"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This data source provides the list of Cluster Network Instances in Oracle Cloud Infrastructure Core service.
//
// Lists the instances in a [cluster network with instance pools](https://docs.cloud.oracle.com/iaas/Content/Compute/Tasks/managingclusternetworks.htm).
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
//			_, err := core.GetClusterNetworkInstances(ctx, &core.GetClusterNetworkInstancesArgs{
//				ClusterNetworkId: testClusterNetwork.Id,
//				CompartmentId:    compartmentId,
//				DisplayName:      pulumi.StringRef(clusterNetworkInstanceDisplayName),
//			}, nil)
//			if err != nil {
//				return err
//			}
//			return nil
//		})
//	}
//
// ```
func GetClusterNetworkInstances(ctx *pulumi.Context, args *GetClusterNetworkInstancesArgs, opts ...pulumi.InvokeOption) (*GetClusterNetworkInstancesResult, error) {
	opts = internal.PkgInvokeDefaultOpts(opts)
	var rv GetClusterNetworkInstancesResult
	err := ctx.Invoke("oci:Core/getClusterNetworkInstances:getClusterNetworkInstances", args, &rv, opts...)
	if err != nil {
		return nil, err
	}
	return &rv, nil
}

// A collection of arguments for invoking getClusterNetworkInstances.
type GetClusterNetworkInstancesArgs struct {
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the cluster network.
	ClusterNetworkId string `pulumi:"clusterNetworkId"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
	CompartmentId string `pulumi:"compartmentId"`
	// A filter to return only resources that match the given display name exactly.
	DisplayName *string                            `pulumi:"displayName"`
	Filters     []GetClusterNetworkInstancesFilter `pulumi:"filters"`
}

// A collection of values returned by getClusterNetworkInstances.
type GetClusterNetworkInstancesResult struct {
	ClusterNetworkId string `pulumi:"clusterNetworkId"`
	// The OCID of the compartment that contains the instance.
	CompartmentId string `pulumi:"compartmentId"`
	// A user-friendly name. Does not have to be unique, and it's changeable. Avoid entering confidential information.
	DisplayName *string                            `pulumi:"displayName"`
	Filters     []GetClusterNetworkInstancesFilter `pulumi:"filters"`
	// The provider-assigned unique ID for this managed resource.
	Id string `pulumi:"id"`
	// The list of instances.
	Instances []GetClusterNetworkInstancesInstance `pulumi:"instances"`
}

func GetClusterNetworkInstancesOutput(ctx *pulumi.Context, args GetClusterNetworkInstancesOutputArgs, opts ...pulumi.InvokeOption) GetClusterNetworkInstancesResultOutput {
	return pulumi.ToOutputWithContext(ctx.Context(), args).
		ApplyT(func(v interface{}) (GetClusterNetworkInstancesResultOutput, error) {
			args := v.(GetClusterNetworkInstancesArgs)
			options := pulumi.InvokeOutputOptions{InvokeOptions: internal.PkgInvokeDefaultOpts(opts)}
			return ctx.InvokeOutput("oci:Core/getClusterNetworkInstances:getClusterNetworkInstances", args, GetClusterNetworkInstancesResultOutput{}, options).(GetClusterNetworkInstancesResultOutput), nil
		}).(GetClusterNetworkInstancesResultOutput)
}

// A collection of arguments for invoking getClusterNetworkInstances.
type GetClusterNetworkInstancesOutputArgs struct {
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the cluster network.
	ClusterNetworkId pulumi.StringInput `pulumi:"clusterNetworkId"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
	CompartmentId pulumi.StringInput `pulumi:"compartmentId"`
	// A filter to return only resources that match the given display name exactly.
	DisplayName pulumi.StringPtrInput                      `pulumi:"displayName"`
	Filters     GetClusterNetworkInstancesFilterArrayInput `pulumi:"filters"`
}

func (GetClusterNetworkInstancesOutputArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*GetClusterNetworkInstancesArgs)(nil)).Elem()
}

// A collection of values returned by getClusterNetworkInstances.
type GetClusterNetworkInstancesResultOutput struct{ *pulumi.OutputState }

func (GetClusterNetworkInstancesResultOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*GetClusterNetworkInstancesResult)(nil)).Elem()
}

func (o GetClusterNetworkInstancesResultOutput) ToGetClusterNetworkInstancesResultOutput() GetClusterNetworkInstancesResultOutput {
	return o
}

func (o GetClusterNetworkInstancesResultOutput) ToGetClusterNetworkInstancesResultOutputWithContext(ctx context.Context) GetClusterNetworkInstancesResultOutput {
	return o
}

func (o GetClusterNetworkInstancesResultOutput) ClusterNetworkId() pulumi.StringOutput {
	return o.ApplyT(func(v GetClusterNetworkInstancesResult) string { return v.ClusterNetworkId }).(pulumi.StringOutput)
}

// The OCID of the compartment that contains the instance.
func (o GetClusterNetworkInstancesResultOutput) CompartmentId() pulumi.StringOutput {
	return o.ApplyT(func(v GetClusterNetworkInstancesResult) string { return v.CompartmentId }).(pulumi.StringOutput)
}

// A user-friendly name. Does not have to be unique, and it's changeable. Avoid entering confidential information.
func (o GetClusterNetworkInstancesResultOutput) DisplayName() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetClusterNetworkInstancesResult) *string { return v.DisplayName }).(pulumi.StringPtrOutput)
}

func (o GetClusterNetworkInstancesResultOutput) Filters() GetClusterNetworkInstancesFilterArrayOutput {
	return o.ApplyT(func(v GetClusterNetworkInstancesResult) []GetClusterNetworkInstancesFilter { return v.Filters }).(GetClusterNetworkInstancesFilterArrayOutput)
}

// The provider-assigned unique ID for this managed resource.
func (o GetClusterNetworkInstancesResultOutput) Id() pulumi.StringOutput {
	return o.ApplyT(func(v GetClusterNetworkInstancesResult) string { return v.Id }).(pulumi.StringOutput)
}

// The list of instances.
func (o GetClusterNetworkInstancesResultOutput) Instances() GetClusterNetworkInstancesInstanceArrayOutput {
	return o.ApplyT(func(v GetClusterNetworkInstancesResult) []GetClusterNetworkInstancesInstance { return v.Instances }).(GetClusterNetworkInstancesInstanceArrayOutput)
}

func init() {
	pulumi.RegisterOutputType(GetClusterNetworkInstancesResultOutput{})
}
