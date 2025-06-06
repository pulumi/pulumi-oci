// Code generated by pulumi-language-go DO NOT EDIT.
// *** WARNING: Do not edit by hand unless you're certain you know what you are doing! ***

package loadbalancer

import (
	"context"
	"reflect"

	"github.com/pulumi/pulumi-oci/sdk/v3/go/oci/internal"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This data source provides details about a specific Rule Set resource in Oracle Cloud Infrastructure Load Balancer service.
//
// Gets the specified set of rules.
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
//			_, err := loadbalancer.GetRuleSet(ctx, &loadbalancer.GetRuleSetArgs{
//				LoadBalancerId: testLoadBalancer.Id,
//				Name:           ruleSetName,
//			}, nil)
//			if err != nil {
//				return err
//			}
//			return nil
//		})
//	}
//
// ```
func LookupRuleSet(ctx *pulumi.Context, args *LookupRuleSetArgs, opts ...pulumi.InvokeOption) (*LookupRuleSetResult, error) {
	opts = internal.PkgInvokeDefaultOpts(opts)
	var rv LookupRuleSetResult
	err := ctx.Invoke("oci:LoadBalancer/getRuleSet:getRuleSet", args, &rv, opts...)
	if err != nil {
		return nil, err
	}
	return &rv, nil
}

// A collection of arguments for invoking getRuleSet.
type LookupRuleSetArgs struct {
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the specified load balancer.
	LoadBalancerId string `pulumi:"loadBalancerId"`
	// The name of the rule set to retrieve.  Example: `exampleRuleSet`
	Name string `pulumi:"name"`
}

// A collection of values returned by getRuleSet.
type LookupRuleSetResult struct {
	Id string `pulumi:"id"`
	// An array of rules that compose the rule set.
	Items          []GetRuleSetItem `pulumi:"items"`
	LoadBalancerId string           `pulumi:"loadBalancerId"`
	// The name for this set of rules. It must be unique and it cannot be changed. Avoid entering confidential information.  Example: `exampleRuleSet`
	Name  string `pulumi:"name"`
	State string `pulumi:"state"`
}

func LookupRuleSetOutput(ctx *pulumi.Context, args LookupRuleSetOutputArgs, opts ...pulumi.InvokeOption) LookupRuleSetResultOutput {
	return pulumi.ToOutputWithContext(ctx.Context(), args).
		ApplyT(func(v interface{}) (LookupRuleSetResultOutput, error) {
			args := v.(LookupRuleSetArgs)
			options := pulumi.InvokeOutputOptions{InvokeOptions: internal.PkgInvokeDefaultOpts(opts)}
			return ctx.InvokeOutput("oci:LoadBalancer/getRuleSet:getRuleSet", args, LookupRuleSetResultOutput{}, options).(LookupRuleSetResultOutput), nil
		}).(LookupRuleSetResultOutput)
}

// A collection of arguments for invoking getRuleSet.
type LookupRuleSetOutputArgs struct {
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the specified load balancer.
	LoadBalancerId pulumi.StringInput `pulumi:"loadBalancerId"`
	// The name of the rule set to retrieve.  Example: `exampleRuleSet`
	Name pulumi.StringInput `pulumi:"name"`
}

func (LookupRuleSetOutputArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*LookupRuleSetArgs)(nil)).Elem()
}

// A collection of values returned by getRuleSet.
type LookupRuleSetResultOutput struct{ *pulumi.OutputState }

func (LookupRuleSetResultOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*LookupRuleSetResult)(nil)).Elem()
}

func (o LookupRuleSetResultOutput) ToLookupRuleSetResultOutput() LookupRuleSetResultOutput {
	return o
}

func (o LookupRuleSetResultOutput) ToLookupRuleSetResultOutputWithContext(ctx context.Context) LookupRuleSetResultOutput {
	return o
}

func (o LookupRuleSetResultOutput) Id() pulumi.StringOutput {
	return o.ApplyT(func(v LookupRuleSetResult) string { return v.Id }).(pulumi.StringOutput)
}

// An array of rules that compose the rule set.
func (o LookupRuleSetResultOutput) Items() GetRuleSetItemArrayOutput {
	return o.ApplyT(func(v LookupRuleSetResult) []GetRuleSetItem { return v.Items }).(GetRuleSetItemArrayOutput)
}

func (o LookupRuleSetResultOutput) LoadBalancerId() pulumi.StringOutput {
	return o.ApplyT(func(v LookupRuleSetResult) string { return v.LoadBalancerId }).(pulumi.StringOutput)
}

// The name for this set of rules. It must be unique and it cannot be changed. Avoid entering confidential information.  Example: `exampleRuleSet`
func (o LookupRuleSetResultOutput) Name() pulumi.StringOutput {
	return o.ApplyT(func(v LookupRuleSetResult) string { return v.Name }).(pulumi.StringOutput)
}

func (o LookupRuleSetResultOutput) State() pulumi.StringOutput {
	return o.ApplyT(func(v LookupRuleSetResult) string { return v.State }).(pulumi.StringOutput)
}

func init() {
	pulumi.RegisterOutputType(LookupRuleSetResultOutput{})
}
