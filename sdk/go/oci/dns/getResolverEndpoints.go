// Code generated by pulumi-language-go DO NOT EDIT.
// *** WARNING: Do not edit by hand unless you're certain you know what you are doing! ***

package dns

import (
	"context"
	"reflect"

	"github.com/pulumi/pulumi-oci/sdk/v3/go/oci/internal"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This data source provides the list of Resolver Endpoints in Oracle Cloud Infrastructure DNS service.
//
// Gets a list of all endpoints within a resolver. The collection can be filtered by name or lifecycle state.
// It can be sorted on creation time or name both in ASC or DESC order. Note that when no lifecycleState
// query parameter is provided, the collection does not include resolver endpoints in the DELETED
// lifecycle state to be consistent with other operations of the API.
//
// ## Example Usage
//
// ```go
// package main
//
// import (
//
//	"github.com/pulumi/pulumi-oci/sdk/v3/go/oci/dns"
//	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
//
// )
//
//	func main() {
//		pulumi.Run(func(ctx *pulumi.Context) error {
//			_, err := dns.GetResolverEndpoints(ctx, &dns.GetResolverEndpointsArgs{
//				ResolverId: testResolver.Id,
//				Scope:      "PRIVATE",
//				Name:       pulumi.StringRef(resolverEndpointName),
//				State:      pulumi.StringRef(resolverEndpointState),
//			}, nil)
//			if err != nil {
//				return err
//			}
//			return nil
//		})
//	}
//
// ```
func GetResolverEndpoints(ctx *pulumi.Context, args *GetResolverEndpointsArgs, opts ...pulumi.InvokeOption) (*GetResolverEndpointsResult, error) {
	opts = internal.PkgInvokeDefaultOpts(opts)
	var rv GetResolverEndpointsResult
	err := ctx.Invoke("oci:Dns/getResolverEndpoints:getResolverEndpoints", args, &rv, opts...)
	if err != nil {
		return nil, err
	}
	return &rv, nil
}

// A collection of arguments for invoking getResolverEndpoints.
type GetResolverEndpointsArgs struct {
	Filters []GetResolverEndpointsFilter `pulumi:"filters"`
	// The name of a resource.
	Name *string `pulumi:"name"`
	// The OCID of the target resolver.
	ResolverId string `pulumi:"resolverId"`
	// Value must be `PRIVATE` when listing private name resolver endpoints.
	Scope string `pulumi:"scope"`
	// The state of a resource.
	State *string `pulumi:"state"`
}

// A collection of values returned by getResolverEndpoints.
type GetResolverEndpointsResult struct {
	Filters []GetResolverEndpointsFilter `pulumi:"filters"`
	// The provider-assigned unique ID for this managed resource.
	Id string `pulumi:"id"`
	// The name of the resolver endpoint. Must be unique, case-insensitive, within the resolver.
	Name *string `pulumi:"name"`
	// The list of resolver_endpoints.
	ResolverEndpoints []GetResolverEndpointsResolverEndpoint `pulumi:"resolverEndpoints"`
	ResolverId        string                                 `pulumi:"resolverId"`
	Scope             string                                 `pulumi:"scope"`
	// The current state of the resource.
	State *string `pulumi:"state"`
}

func GetResolverEndpointsOutput(ctx *pulumi.Context, args GetResolverEndpointsOutputArgs, opts ...pulumi.InvokeOption) GetResolverEndpointsResultOutput {
	return pulumi.ToOutputWithContext(ctx.Context(), args).
		ApplyT(func(v interface{}) (GetResolverEndpointsResultOutput, error) {
			args := v.(GetResolverEndpointsArgs)
			options := pulumi.InvokeOutputOptions{InvokeOptions: internal.PkgInvokeDefaultOpts(opts)}
			return ctx.InvokeOutput("oci:Dns/getResolverEndpoints:getResolverEndpoints", args, GetResolverEndpointsResultOutput{}, options).(GetResolverEndpointsResultOutput), nil
		}).(GetResolverEndpointsResultOutput)
}

// A collection of arguments for invoking getResolverEndpoints.
type GetResolverEndpointsOutputArgs struct {
	Filters GetResolverEndpointsFilterArrayInput `pulumi:"filters"`
	// The name of a resource.
	Name pulumi.StringPtrInput `pulumi:"name"`
	// The OCID of the target resolver.
	ResolverId pulumi.StringInput `pulumi:"resolverId"`
	// Value must be `PRIVATE` when listing private name resolver endpoints.
	Scope pulumi.StringInput `pulumi:"scope"`
	// The state of a resource.
	State pulumi.StringPtrInput `pulumi:"state"`
}

func (GetResolverEndpointsOutputArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*GetResolverEndpointsArgs)(nil)).Elem()
}

// A collection of values returned by getResolverEndpoints.
type GetResolverEndpointsResultOutput struct{ *pulumi.OutputState }

func (GetResolverEndpointsResultOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*GetResolverEndpointsResult)(nil)).Elem()
}

func (o GetResolverEndpointsResultOutput) ToGetResolverEndpointsResultOutput() GetResolverEndpointsResultOutput {
	return o
}

func (o GetResolverEndpointsResultOutput) ToGetResolverEndpointsResultOutputWithContext(ctx context.Context) GetResolverEndpointsResultOutput {
	return o
}

func (o GetResolverEndpointsResultOutput) Filters() GetResolverEndpointsFilterArrayOutput {
	return o.ApplyT(func(v GetResolverEndpointsResult) []GetResolverEndpointsFilter { return v.Filters }).(GetResolverEndpointsFilterArrayOutput)
}

// The provider-assigned unique ID for this managed resource.
func (o GetResolverEndpointsResultOutput) Id() pulumi.StringOutput {
	return o.ApplyT(func(v GetResolverEndpointsResult) string { return v.Id }).(pulumi.StringOutput)
}

// The name of the resolver endpoint. Must be unique, case-insensitive, within the resolver.
func (o GetResolverEndpointsResultOutput) Name() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetResolverEndpointsResult) *string { return v.Name }).(pulumi.StringPtrOutput)
}

// The list of resolver_endpoints.
func (o GetResolverEndpointsResultOutput) ResolverEndpoints() GetResolverEndpointsResolverEndpointArrayOutput {
	return o.ApplyT(func(v GetResolverEndpointsResult) []GetResolverEndpointsResolverEndpoint { return v.ResolverEndpoints }).(GetResolverEndpointsResolverEndpointArrayOutput)
}

func (o GetResolverEndpointsResultOutput) ResolverId() pulumi.StringOutput {
	return o.ApplyT(func(v GetResolverEndpointsResult) string { return v.ResolverId }).(pulumi.StringOutput)
}

func (o GetResolverEndpointsResultOutput) Scope() pulumi.StringOutput {
	return o.ApplyT(func(v GetResolverEndpointsResult) string { return v.Scope }).(pulumi.StringOutput)
}

// The current state of the resource.
func (o GetResolverEndpointsResultOutput) State() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetResolverEndpointsResult) *string { return v.State }).(pulumi.StringPtrOutput)
}

func init() {
	pulumi.RegisterOutputType(GetResolverEndpointsResultOutput{})
}
