// Code generated by the Pulumi Terraform Bridge (tfgen) Tool DO NOT EDIT.
// *** WARNING: Do not edit by hand unless you're certain you know what you are doing! ***

package loadbalancer

import (
	"context"
	"reflect"

	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This data source provides the list of Load Balancers in Oracle Cloud Infrastructure Load Balancer service.
//
// Lists all load balancers in the specified compartment.
//
// ## Supported Aliases
//
// * `ociLoadBalancers`
//
// ## Example Usage
//
// ```go
// package main
//
// import (
//
//	"github.com/pulumi/pulumi-oci/sdk/go/oci/LoadBalancer"
//	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
//
// )
//
//	func main() {
//		pulumi.Run(func(ctx *pulumi.Context) error {
//			_, err := LoadBalancer.GetLoadBalancers(ctx, &loadbalancer.GetLoadBalancersArgs{
//				CompartmentId: _var.Compartment_id,
//				Detail:        pulumi.StringRef(_var.Load_balancer_detail),
//				DisplayName:   pulumi.StringRef(_var.Load_balancer_display_name),
//				State:         pulumi.StringRef(_var.Load_balancer_state),
//			}, nil)
//			if err != nil {
//				return err
//			}
//			return nil
//		})
//	}
//
// ```
func GetLoadBalancers(ctx *pulumi.Context, args *GetLoadBalancersArgs, opts ...pulumi.InvokeOption) (*GetLoadBalancersResult, error) {
	var rv GetLoadBalancersResult
	err := ctx.Invoke("oci:LoadBalancer/getLoadBalancers:getLoadBalancers", args, &rv, opts...)
	if err != nil {
		return nil, err
	}
	return &rv, nil
}

// A collection of arguments for invoking getLoadBalancers.
type GetLoadBalancersArgs struct {
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment containing the load balancers to list.
	CompartmentId string `pulumi:"compartmentId"`
	// The level of detail to return for each result. Can be `full` or `simple`.  Example: `full`
	Detail *string `pulumi:"detail"`
	// A filter to return only resources that match the given display name exactly.  Example: `exampleLoadBalancer`
	DisplayName *string                  `pulumi:"displayName"`
	Filters     []GetLoadBalancersFilter `pulumi:"filters"`
	// A filter to return only resources that match the given lifecycle state.  Example: `SUCCEEDED`
	State *string `pulumi:"state"`
}

// A collection of values returned by getLoadBalancers.
type GetLoadBalancersResult struct {
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment containing the load balancer.
	CompartmentId string  `pulumi:"compartmentId"`
	Detail        *string `pulumi:"detail"`
	// A user-friendly name. It does not have to be unique, and it is changeable.  Example: `exampleLoadBalancer`
	DisplayName *string                  `pulumi:"displayName"`
	Filters     []GetLoadBalancersFilter `pulumi:"filters"`
	// The provider-assigned unique ID for this managed resource.
	Id string `pulumi:"id"`
	// The list of load_balancers.
	LoadBalancers []GetLoadBalancersLoadBalancer `pulumi:"loadBalancers"`
	// The current state of the load balancer.
	State *string `pulumi:"state"`
}

func GetLoadBalancersOutput(ctx *pulumi.Context, args GetLoadBalancersOutputArgs, opts ...pulumi.InvokeOption) GetLoadBalancersResultOutput {
	return pulumi.ToOutputWithContext(context.Background(), args).
		ApplyT(func(v interface{}) (GetLoadBalancersResult, error) {
			args := v.(GetLoadBalancersArgs)
			r, err := GetLoadBalancers(ctx, &args, opts...)
			var s GetLoadBalancersResult
			if r != nil {
				s = *r
			}
			return s, err
		}).(GetLoadBalancersResultOutput)
}

// A collection of arguments for invoking getLoadBalancers.
type GetLoadBalancersOutputArgs struct {
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment containing the load balancers to list.
	CompartmentId pulumi.StringInput `pulumi:"compartmentId"`
	// The level of detail to return for each result. Can be `full` or `simple`.  Example: `full`
	Detail pulumi.StringPtrInput `pulumi:"detail"`
	// A filter to return only resources that match the given display name exactly.  Example: `exampleLoadBalancer`
	DisplayName pulumi.StringPtrInput            `pulumi:"displayName"`
	Filters     GetLoadBalancersFilterArrayInput `pulumi:"filters"`
	// A filter to return only resources that match the given lifecycle state.  Example: `SUCCEEDED`
	State pulumi.StringPtrInput `pulumi:"state"`
}

func (GetLoadBalancersOutputArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*GetLoadBalancersArgs)(nil)).Elem()
}

// A collection of values returned by getLoadBalancers.
type GetLoadBalancersResultOutput struct{ *pulumi.OutputState }

func (GetLoadBalancersResultOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*GetLoadBalancersResult)(nil)).Elem()
}

func (o GetLoadBalancersResultOutput) ToGetLoadBalancersResultOutput() GetLoadBalancersResultOutput {
	return o
}

func (o GetLoadBalancersResultOutput) ToGetLoadBalancersResultOutputWithContext(ctx context.Context) GetLoadBalancersResultOutput {
	return o
}

// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment containing the load balancer.
func (o GetLoadBalancersResultOutput) CompartmentId() pulumi.StringOutput {
	return o.ApplyT(func(v GetLoadBalancersResult) string { return v.CompartmentId }).(pulumi.StringOutput)
}

func (o GetLoadBalancersResultOutput) Detail() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetLoadBalancersResult) *string { return v.Detail }).(pulumi.StringPtrOutput)
}

// A user-friendly name. It does not have to be unique, and it is changeable.  Example: `exampleLoadBalancer`
func (o GetLoadBalancersResultOutput) DisplayName() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetLoadBalancersResult) *string { return v.DisplayName }).(pulumi.StringPtrOutput)
}

func (o GetLoadBalancersResultOutput) Filters() GetLoadBalancersFilterArrayOutput {
	return o.ApplyT(func(v GetLoadBalancersResult) []GetLoadBalancersFilter { return v.Filters }).(GetLoadBalancersFilterArrayOutput)
}

// The provider-assigned unique ID for this managed resource.
func (o GetLoadBalancersResultOutput) Id() pulumi.StringOutput {
	return o.ApplyT(func(v GetLoadBalancersResult) string { return v.Id }).(pulumi.StringOutput)
}

// The list of load_balancers.
func (o GetLoadBalancersResultOutput) LoadBalancers() GetLoadBalancersLoadBalancerArrayOutput {
	return o.ApplyT(func(v GetLoadBalancersResult) []GetLoadBalancersLoadBalancer { return v.LoadBalancers }).(GetLoadBalancersLoadBalancerArrayOutput)
}

// The current state of the load balancer.
func (o GetLoadBalancersResultOutput) State() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetLoadBalancersResult) *string { return v.State }).(pulumi.StringPtrOutput)
}

func init() {
	pulumi.RegisterOutputType(GetLoadBalancersResultOutput{})
}