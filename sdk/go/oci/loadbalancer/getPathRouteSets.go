// Code generated by the Pulumi Terraform Bridge (tfgen) Tool DO NOT EDIT.
// *** WARNING: Do not edit by hand unless you're certain you know what you are doing! ***

package loadbalancer

import (
	"context"
	"reflect"

	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This data source provides the list of Path Route Sets in Oracle Cloud Infrastructure Load Balancer service.
//
// Lists all path route sets associated with the specified load balancer.
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
//			_, err := LoadBalancer.GetPathRouteSets(ctx, &loadbalancer.GetPathRouteSetsArgs{
//				LoadBalancerId: oci_load_balancer_load_balancer.Test_load_balancer.Id,
//			}, nil)
//			if err != nil {
//				return err
//			}
//			return nil
//		})
//	}
//
// ```
func GetPathRouteSets(ctx *pulumi.Context, args *GetPathRouteSetsArgs, opts ...pulumi.InvokeOption) (*GetPathRouteSetsResult, error) {
	var rv GetPathRouteSetsResult
	err := ctx.Invoke("oci:LoadBalancer/getPathRouteSets:getPathRouteSets", args, &rv, opts...)
	if err != nil {
		return nil, err
	}
	return &rv, nil
}

// A collection of arguments for invoking getPathRouteSets.
type GetPathRouteSetsArgs struct {
	Filters []GetPathRouteSetsFilter `pulumi:"filters"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the load balancer associated with the path route sets to retrieve.
	LoadBalancerId string `pulumi:"loadBalancerId"`
}

// A collection of values returned by getPathRouteSets.
type GetPathRouteSetsResult struct {
	Filters []GetPathRouteSetsFilter `pulumi:"filters"`
	// The provider-assigned unique ID for this managed resource.
	Id             string `pulumi:"id"`
	LoadBalancerId string `pulumi:"loadBalancerId"`
	// The list of path_route_sets.
	PathRouteSets []GetPathRouteSetsPathRouteSet `pulumi:"pathRouteSets"`
}

func GetPathRouteSetsOutput(ctx *pulumi.Context, args GetPathRouteSetsOutputArgs, opts ...pulumi.InvokeOption) GetPathRouteSetsResultOutput {
	return pulumi.ToOutputWithContext(context.Background(), args).
		ApplyT(func(v interface{}) (GetPathRouteSetsResult, error) {
			args := v.(GetPathRouteSetsArgs)
			r, err := GetPathRouteSets(ctx, &args, opts...)
			var s GetPathRouteSetsResult
			if r != nil {
				s = *r
			}
			return s, err
		}).(GetPathRouteSetsResultOutput)
}

// A collection of arguments for invoking getPathRouteSets.
type GetPathRouteSetsOutputArgs struct {
	Filters GetPathRouteSetsFilterArrayInput `pulumi:"filters"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the load balancer associated with the path route sets to retrieve.
	LoadBalancerId pulumi.StringInput `pulumi:"loadBalancerId"`
}

func (GetPathRouteSetsOutputArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*GetPathRouteSetsArgs)(nil)).Elem()
}

// A collection of values returned by getPathRouteSets.
type GetPathRouteSetsResultOutput struct{ *pulumi.OutputState }

func (GetPathRouteSetsResultOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*GetPathRouteSetsResult)(nil)).Elem()
}

func (o GetPathRouteSetsResultOutput) ToGetPathRouteSetsResultOutput() GetPathRouteSetsResultOutput {
	return o
}

func (o GetPathRouteSetsResultOutput) ToGetPathRouteSetsResultOutputWithContext(ctx context.Context) GetPathRouteSetsResultOutput {
	return o
}

func (o GetPathRouteSetsResultOutput) Filters() GetPathRouteSetsFilterArrayOutput {
	return o.ApplyT(func(v GetPathRouteSetsResult) []GetPathRouteSetsFilter { return v.Filters }).(GetPathRouteSetsFilterArrayOutput)
}

// The provider-assigned unique ID for this managed resource.
func (o GetPathRouteSetsResultOutput) Id() pulumi.StringOutput {
	return o.ApplyT(func(v GetPathRouteSetsResult) string { return v.Id }).(pulumi.StringOutput)
}

func (o GetPathRouteSetsResultOutput) LoadBalancerId() pulumi.StringOutput {
	return o.ApplyT(func(v GetPathRouteSetsResult) string { return v.LoadBalancerId }).(pulumi.StringOutput)
}

// The list of path_route_sets.
func (o GetPathRouteSetsResultOutput) PathRouteSets() GetPathRouteSetsPathRouteSetArrayOutput {
	return o.ApplyT(func(v GetPathRouteSetsResult) []GetPathRouteSetsPathRouteSet { return v.PathRouteSets }).(GetPathRouteSetsPathRouteSetArrayOutput)
}

func init() {
	pulumi.RegisterOutputType(GetPathRouteSetsResultOutput{})
}