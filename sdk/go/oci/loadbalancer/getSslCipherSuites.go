// Code generated by pulumi-language-go DO NOT EDIT.
// *** WARNING: Do not edit by hand unless you're certain you know what you are doing! ***

package loadbalancer

import (
	"context"
	"reflect"

	"github.com/pulumi/pulumi-oci/sdk/v3/go/oci/internal"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This data source provides the list of Ssl Cipher Suites in Oracle Cloud Infrastructure Load Balancer service.
//
// Lists all SSL cipher suites associated with the specified load balancer.
//
// ## Example Usage
//
// ```go
// package main
//
// import (
//
//	"github.com/pulumi/pulumi-oci/sdk/v3/go/oci/loadbalancer"
//	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
//
// )
//
//	func main() {
//		pulumi.Run(func(ctx *pulumi.Context) error {
//			_, err := loadbalancer.GetSslCipherSuites(ctx, &loadbalancer.GetSslCipherSuitesArgs{
//				LoadBalancerId: testLoadBalancer.Id,
//			}, nil)
//			if err != nil {
//				return err
//			}
//			return nil
//		})
//	}
//
// ```
func GetSslCipherSuites(ctx *pulumi.Context, args *GetSslCipherSuitesArgs, opts ...pulumi.InvokeOption) (*GetSslCipherSuitesResult, error) {
	opts = internal.PkgInvokeDefaultOpts(opts)
	var rv GetSslCipherSuitesResult
	err := ctx.Invoke("oci:LoadBalancer/getSslCipherSuites:getSslCipherSuites", args, &rv, opts...)
	if err != nil {
		return nil, err
	}
	return &rv, nil
}

// A collection of arguments for invoking getSslCipherSuites.
type GetSslCipherSuitesArgs struct {
	Filters []GetSslCipherSuitesFilter `pulumi:"filters"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the associated load balancer.
	LoadBalancerId string `pulumi:"loadBalancerId"`
}

// A collection of values returned by getSslCipherSuites.
type GetSslCipherSuitesResult struct {
	Filters []GetSslCipherSuitesFilter `pulumi:"filters"`
	// The provider-assigned unique ID for this managed resource.
	Id             string `pulumi:"id"`
	LoadBalancerId string `pulumi:"loadBalancerId"`
	// The list of ssl_cipher_suites.
	SslCipherSuites []GetSslCipherSuitesSslCipherSuite `pulumi:"sslCipherSuites"`
}

func GetSslCipherSuitesOutput(ctx *pulumi.Context, args GetSslCipherSuitesOutputArgs, opts ...pulumi.InvokeOption) GetSslCipherSuitesResultOutput {
	return pulumi.ToOutputWithContext(ctx.Context(), args).
		ApplyT(func(v interface{}) (GetSslCipherSuitesResultOutput, error) {
			args := v.(GetSslCipherSuitesArgs)
			options := pulumi.InvokeOutputOptions{InvokeOptions: internal.PkgInvokeDefaultOpts(opts)}
			return ctx.InvokeOutput("oci:LoadBalancer/getSslCipherSuites:getSslCipherSuites", args, GetSslCipherSuitesResultOutput{}, options).(GetSslCipherSuitesResultOutput), nil
		}).(GetSslCipherSuitesResultOutput)
}

// A collection of arguments for invoking getSslCipherSuites.
type GetSslCipherSuitesOutputArgs struct {
	Filters GetSslCipherSuitesFilterArrayInput `pulumi:"filters"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the associated load balancer.
	LoadBalancerId pulumi.StringInput `pulumi:"loadBalancerId"`
}

func (GetSslCipherSuitesOutputArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*GetSslCipherSuitesArgs)(nil)).Elem()
}

// A collection of values returned by getSslCipherSuites.
type GetSslCipherSuitesResultOutput struct{ *pulumi.OutputState }

func (GetSslCipherSuitesResultOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*GetSslCipherSuitesResult)(nil)).Elem()
}

func (o GetSslCipherSuitesResultOutput) ToGetSslCipherSuitesResultOutput() GetSslCipherSuitesResultOutput {
	return o
}

func (o GetSslCipherSuitesResultOutput) ToGetSslCipherSuitesResultOutputWithContext(ctx context.Context) GetSslCipherSuitesResultOutput {
	return o
}

func (o GetSslCipherSuitesResultOutput) Filters() GetSslCipherSuitesFilterArrayOutput {
	return o.ApplyT(func(v GetSslCipherSuitesResult) []GetSslCipherSuitesFilter { return v.Filters }).(GetSslCipherSuitesFilterArrayOutput)
}

// The provider-assigned unique ID for this managed resource.
func (o GetSslCipherSuitesResultOutput) Id() pulumi.StringOutput {
	return o.ApplyT(func(v GetSslCipherSuitesResult) string { return v.Id }).(pulumi.StringOutput)
}

func (o GetSslCipherSuitesResultOutput) LoadBalancerId() pulumi.StringOutput {
	return o.ApplyT(func(v GetSslCipherSuitesResult) string { return v.LoadBalancerId }).(pulumi.StringOutput)
}

// The list of ssl_cipher_suites.
func (o GetSslCipherSuitesResultOutput) SslCipherSuites() GetSslCipherSuitesSslCipherSuiteArrayOutput {
	return o.ApplyT(func(v GetSslCipherSuitesResult) []GetSslCipherSuitesSslCipherSuite { return v.SslCipherSuites }).(GetSslCipherSuitesSslCipherSuiteArrayOutput)
}

func init() {
	pulumi.RegisterOutputType(GetSslCipherSuitesResultOutput{})
}
