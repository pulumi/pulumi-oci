// Code generated by the Pulumi Terraform Bridge (tfgen) Tool DO NOT EDIT.
// *** WARNING: Do not edit by hand unless you're certain you know what you are doing! ***

package networkloadbalancer

import (
	"context"
	"reflect"

	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This data source provides the list of Listeners in Oracle Cloud Infrastructure Network Load Balancer service.
//
// Lists all listeners associated with a given network load balancer.
//
// ## Example Usage
//
// ```go
// package main
//
// import (
//
//	"github.com/pulumi/pulumi-oci/sdk/go/oci/NetworkLoadBalancer"
//	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
//
// )
//
//	func main() {
//		pulumi.Run(func(ctx *pulumi.Context) error {
//			_, err := NetworkLoadBalancer.GetListeners(ctx, &networkloadbalancer.GetListenersArgs{
//				NetworkLoadBalancerId: oci_network_load_balancer_network_load_balancer.Test_network_load_balancer.Id,
//			}, nil)
//			if err != nil {
//				return err
//			}
//			return nil
//		})
//	}
//
// ```
func GetListeners(ctx *pulumi.Context, args *GetListenersArgs, opts ...pulumi.InvokeOption) (*GetListenersResult, error) {
	var rv GetListenersResult
	err := ctx.Invoke("oci:NetworkLoadBalancer/getListeners:getListeners", args, &rv, opts...)
	if err != nil {
		return nil, err
	}
	return &rv, nil
}

// A collection of arguments for invoking getListeners.
type GetListenersArgs struct {
	Filters []GetListenersFilter `pulumi:"filters"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the network load balancer to update.
	NetworkLoadBalancerId string `pulumi:"networkLoadBalancerId"`
}

// A collection of values returned by getListeners.
type GetListenersResult struct {
	Filters []GetListenersFilter `pulumi:"filters"`
	// The provider-assigned unique ID for this managed resource.
	Id string `pulumi:"id"`
	// The list of listener_collection.
	ListenerCollections   []GetListenersListenerCollection `pulumi:"listenerCollections"`
	NetworkLoadBalancerId string                           `pulumi:"networkLoadBalancerId"`
}

func GetListenersOutput(ctx *pulumi.Context, args GetListenersOutputArgs, opts ...pulumi.InvokeOption) GetListenersResultOutput {
	return pulumi.ToOutputWithContext(context.Background(), args).
		ApplyT(func(v interface{}) (GetListenersResult, error) {
			args := v.(GetListenersArgs)
			r, err := GetListeners(ctx, &args, opts...)
			var s GetListenersResult
			if r != nil {
				s = *r
			}
			return s, err
		}).(GetListenersResultOutput)
}

// A collection of arguments for invoking getListeners.
type GetListenersOutputArgs struct {
	Filters GetListenersFilterArrayInput `pulumi:"filters"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the network load balancer to update.
	NetworkLoadBalancerId pulumi.StringInput `pulumi:"networkLoadBalancerId"`
}

func (GetListenersOutputArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*GetListenersArgs)(nil)).Elem()
}

// A collection of values returned by getListeners.
type GetListenersResultOutput struct{ *pulumi.OutputState }

func (GetListenersResultOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*GetListenersResult)(nil)).Elem()
}

func (o GetListenersResultOutput) ToGetListenersResultOutput() GetListenersResultOutput {
	return o
}

func (o GetListenersResultOutput) ToGetListenersResultOutputWithContext(ctx context.Context) GetListenersResultOutput {
	return o
}

func (o GetListenersResultOutput) Filters() GetListenersFilterArrayOutput {
	return o.ApplyT(func(v GetListenersResult) []GetListenersFilter { return v.Filters }).(GetListenersFilterArrayOutput)
}

// The provider-assigned unique ID for this managed resource.
func (o GetListenersResultOutput) Id() pulumi.StringOutput {
	return o.ApplyT(func(v GetListenersResult) string { return v.Id }).(pulumi.StringOutput)
}

// The list of listener_collection.
func (o GetListenersResultOutput) ListenerCollections() GetListenersListenerCollectionArrayOutput {
	return o.ApplyT(func(v GetListenersResult) []GetListenersListenerCollection { return v.ListenerCollections }).(GetListenersListenerCollectionArrayOutput)
}

func (o GetListenersResultOutput) NetworkLoadBalancerId() pulumi.StringOutput {
	return o.ApplyT(func(v GetListenersResult) string { return v.NetworkLoadBalancerId }).(pulumi.StringOutput)
}

func init() {
	pulumi.RegisterOutputType(GetListenersResultOutput{})
}