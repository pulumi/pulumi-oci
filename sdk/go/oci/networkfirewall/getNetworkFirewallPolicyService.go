// Code generated by pulumi-language-go DO NOT EDIT.
// *** WARNING: Do not edit by hand unless you're certain you know what you are doing! ***

package networkfirewall

import (
	"context"
	"reflect"

	"github.com/pulumi/pulumi-oci/sdk/v3/go/oci/internal"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This data source provides details about a specific Network Firewall Policy Service resource in Oracle Cloud Infrastructure Network Firewall service.
//
// Get Service by the given name in the context of network firewall policy.
func LookupNetworkFirewallPolicyService(ctx *pulumi.Context, args *LookupNetworkFirewallPolicyServiceArgs, opts ...pulumi.InvokeOption) (*LookupNetworkFirewallPolicyServiceResult, error) {
	opts = internal.PkgInvokeDefaultOpts(opts)
	var rv LookupNetworkFirewallPolicyServiceResult
	err := ctx.Invoke("oci:NetworkFirewall/getNetworkFirewallPolicyService:getNetworkFirewallPolicyService", args, &rv, opts...)
	if err != nil {
		return nil, err
	}
	return &rv, nil
}

// A collection of arguments for invoking getNetworkFirewallPolicyService.
type LookupNetworkFirewallPolicyServiceArgs struct {
	// Name of the service.
	Name string `pulumi:"name"`
	// Unique Network Firewall Policy identifier
	NetworkFirewallPolicyId string `pulumi:"networkFirewallPolicyId"`
}

// A collection of values returned by getNetworkFirewallPolicyService.
type LookupNetworkFirewallPolicyServiceResult struct {
	Id string `pulumi:"id"`
	// Name of the service.
	Name                    string `pulumi:"name"`
	NetworkFirewallPolicyId string `pulumi:"networkFirewallPolicyId"`
	// OCID of the Network Firewall Policy this service belongs to.
	ParentResourceId string `pulumi:"parentResourceId"`
	// List of port-ranges used.
	PortRanges []GetNetworkFirewallPolicyServicePortRange `pulumi:"portRanges"`
	// Describes the type of Service.
	Type string `pulumi:"type"`
}

func LookupNetworkFirewallPolicyServiceOutput(ctx *pulumi.Context, args LookupNetworkFirewallPolicyServiceOutputArgs, opts ...pulumi.InvokeOption) LookupNetworkFirewallPolicyServiceResultOutput {
	return pulumi.ToOutputWithContext(ctx.Context(), args).
		ApplyT(func(v interface{}) (LookupNetworkFirewallPolicyServiceResultOutput, error) {
			args := v.(LookupNetworkFirewallPolicyServiceArgs)
			options := pulumi.InvokeOutputOptions{InvokeOptions: internal.PkgInvokeDefaultOpts(opts)}
			return ctx.InvokeOutput("oci:NetworkFirewall/getNetworkFirewallPolicyService:getNetworkFirewallPolicyService", args, LookupNetworkFirewallPolicyServiceResultOutput{}, options).(LookupNetworkFirewallPolicyServiceResultOutput), nil
		}).(LookupNetworkFirewallPolicyServiceResultOutput)
}

// A collection of arguments for invoking getNetworkFirewallPolicyService.
type LookupNetworkFirewallPolicyServiceOutputArgs struct {
	// Name of the service.
	Name pulumi.StringInput `pulumi:"name"`
	// Unique Network Firewall Policy identifier
	NetworkFirewallPolicyId pulumi.StringInput `pulumi:"networkFirewallPolicyId"`
}

func (LookupNetworkFirewallPolicyServiceOutputArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*LookupNetworkFirewallPolicyServiceArgs)(nil)).Elem()
}

// A collection of values returned by getNetworkFirewallPolicyService.
type LookupNetworkFirewallPolicyServiceResultOutput struct{ *pulumi.OutputState }

func (LookupNetworkFirewallPolicyServiceResultOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*LookupNetworkFirewallPolicyServiceResult)(nil)).Elem()
}

func (o LookupNetworkFirewallPolicyServiceResultOutput) ToLookupNetworkFirewallPolicyServiceResultOutput() LookupNetworkFirewallPolicyServiceResultOutput {
	return o
}

func (o LookupNetworkFirewallPolicyServiceResultOutput) ToLookupNetworkFirewallPolicyServiceResultOutputWithContext(ctx context.Context) LookupNetworkFirewallPolicyServiceResultOutput {
	return o
}

func (o LookupNetworkFirewallPolicyServiceResultOutput) Id() pulumi.StringOutput {
	return o.ApplyT(func(v LookupNetworkFirewallPolicyServiceResult) string { return v.Id }).(pulumi.StringOutput)
}

// Name of the service.
func (o LookupNetworkFirewallPolicyServiceResultOutput) Name() pulumi.StringOutput {
	return o.ApplyT(func(v LookupNetworkFirewallPolicyServiceResult) string { return v.Name }).(pulumi.StringOutput)
}

func (o LookupNetworkFirewallPolicyServiceResultOutput) NetworkFirewallPolicyId() pulumi.StringOutput {
	return o.ApplyT(func(v LookupNetworkFirewallPolicyServiceResult) string { return v.NetworkFirewallPolicyId }).(pulumi.StringOutput)
}

// OCID of the Network Firewall Policy this service belongs to.
func (o LookupNetworkFirewallPolicyServiceResultOutput) ParentResourceId() pulumi.StringOutput {
	return o.ApplyT(func(v LookupNetworkFirewallPolicyServiceResult) string { return v.ParentResourceId }).(pulumi.StringOutput)
}

// List of port-ranges used.
func (o LookupNetworkFirewallPolicyServiceResultOutput) PortRanges() GetNetworkFirewallPolicyServicePortRangeArrayOutput {
	return o.ApplyT(func(v LookupNetworkFirewallPolicyServiceResult) []GetNetworkFirewallPolicyServicePortRange {
		return v.PortRanges
	}).(GetNetworkFirewallPolicyServicePortRangeArrayOutput)
}

// Describes the type of Service.
func (o LookupNetworkFirewallPolicyServiceResultOutput) Type() pulumi.StringOutput {
	return o.ApplyT(func(v LookupNetworkFirewallPolicyServiceResult) string { return v.Type }).(pulumi.StringOutput)
}

func init() {
	pulumi.RegisterOutputType(LookupNetworkFirewallPolicyServiceResultOutput{})
}
