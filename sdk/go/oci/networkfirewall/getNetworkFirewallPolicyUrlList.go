// Code generated by pulumi-language-go DO NOT EDIT.
// *** WARNING: Do not edit by hand unless you're certain you know what you are doing! ***

package networkfirewall

import (
	"context"
	"reflect"

	"github.com/pulumi/pulumi-oci/sdk/v3/go/oci/internal"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This data source provides details about a specific Network Firewall Policy Url List resource in Oracle Cloud Infrastructure Network Firewall service.
//
// Get Url List by the given name in the context of network firewall policy.
func LookupNetworkFirewallPolicyUrlList(ctx *pulumi.Context, args *LookupNetworkFirewallPolicyUrlListArgs, opts ...pulumi.InvokeOption) (*LookupNetworkFirewallPolicyUrlListResult, error) {
	opts = internal.PkgInvokeDefaultOpts(opts)
	var rv LookupNetworkFirewallPolicyUrlListResult
	err := ctx.Invoke("oci:NetworkFirewall/getNetworkFirewallPolicyUrlList:getNetworkFirewallPolicyUrlList", args, &rv, opts...)
	if err != nil {
		return nil, err
	}
	return &rv, nil
}

// A collection of arguments for invoking getNetworkFirewallPolicyUrlList.
type LookupNetworkFirewallPolicyUrlListArgs struct {
	// Unique name identifier for the URL list.
	Name string `pulumi:"name"`
	// Unique Network Firewall Policy identifier
	NetworkFirewallPolicyId string `pulumi:"networkFirewallPolicyId"`
}

// A collection of values returned by getNetworkFirewallPolicyUrlList.
type LookupNetworkFirewallPolicyUrlListResult struct {
	Id string `pulumi:"id"`
	// Unique name identifier for the URL list.
	Name                    string `pulumi:"name"`
	NetworkFirewallPolicyId string `pulumi:"networkFirewallPolicyId"`
	// OCID of the Network Firewall Policy this URL List belongs to.
	ParentResourceId string `pulumi:"parentResourceId"`
	// Total count of URLs in the URL List
	TotalUrls int `pulumi:"totalUrls"`
	// List of urls.
	Urls []GetNetworkFirewallPolicyUrlListUrl `pulumi:"urls"`
}

func LookupNetworkFirewallPolicyUrlListOutput(ctx *pulumi.Context, args LookupNetworkFirewallPolicyUrlListOutputArgs, opts ...pulumi.InvokeOption) LookupNetworkFirewallPolicyUrlListResultOutput {
	return pulumi.ToOutputWithContext(ctx.Context(), args).
		ApplyT(func(v interface{}) (LookupNetworkFirewallPolicyUrlListResultOutput, error) {
			args := v.(LookupNetworkFirewallPolicyUrlListArgs)
			options := pulumi.InvokeOutputOptions{InvokeOptions: internal.PkgInvokeDefaultOpts(opts)}
			return ctx.InvokeOutput("oci:NetworkFirewall/getNetworkFirewallPolicyUrlList:getNetworkFirewallPolicyUrlList", args, LookupNetworkFirewallPolicyUrlListResultOutput{}, options).(LookupNetworkFirewallPolicyUrlListResultOutput), nil
		}).(LookupNetworkFirewallPolicyUrlListResultOutput)
}

// A collection of arguments for invoking getNetworkFirewallPolicyUrlList.
type LookupNetworkFirewallPolicyUrlListOutputArgs struct {
	// Unique name identifier for the URL list.
	Name pulumi.StringInput `pulumi:"name"`
	// Unique Network Firewall Policy identifier
	NetworkFirewallPolicyId pulumi.StringInput `pulumi:"networkFirewallPolicyId"`
}

func (LookupNetworkFirewallPolicyUrlListOutputArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*LookupNetworkFirewallPolicyUrlListArgs)(nil)).Elem()
}

// A collection of values returned by getNetworkFirewallPolicyUrlList.
type LookupNetworkFirewallPolicyUrlListResultOutput struct{ *pulumi.OutputState }

func (LookupNetworkFirewallPolicyUrlListResultOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*LookupNetworkFirewallPolicyUrlListResult)(nil)).Elem()
}

func (o LookupNetworkFirewallPolicyUrlListResultOutput) ToLookupNetworkFirewallPolicyUrlListResultOutput() LookupNetworkFirewallPolicyUrlListResultOutput {
	return o
}

func (o LookupNetworkFirewallPolicyUrlListResultOutput) ToLookupNetworkFirewallPolicyUrlListResultOutputWithContext(ctx context.Context) LookupNetworkFirewallPolicyUrlListResultOutput {
	return o
}

func (o LookupNetworkFirewallPolicyUrlListResultOutput) Id() pulumi.StringOutput {
	return o.ApplyT(func(v LookupNetworkFirewallPolicyUrlListResult) string { return v.Id }).(pulumi.StringOutput)
}

// Unique name identifier for the URL list.
func (o LookupNetworkFirewallPolicyUrlListResultOutput) Name() pulumi.StringOutput {
	return o.ApplyT(func(v LookupNetworkFirewallPolicyUrlListResult) string { return v.Name }).(pulumi.StringOutput)
}

func (o LookupNetworkFirewallPolicyUrlListResultOutput) NetworkFirewallPolicyId() pulumi.StringOutput {
	return o.ApplyT(func(v LookupNetworkFirewallPolicyUrlListResult) string { return v.NetworkFirewallPolicyId }).(pulumi.StringOutput)
}

// OCID of the Network Firewall Policy this URL List belongs to.
func (o LookupNetworkFirewallPolicyUrlListResultOutput) ParentResourceId() pulumi.StringOutput {
	return o.ApplyT(func(v LookupNetworkFirewallPolicyUrlListResult) string { return v.ParentResourceId }).(pulumi.StringOutput)
}

// Total count of URLs in the URL List
func (o LookupNetworkFirewallPolicyUrlListResultOutput) TotalUrls() pulumi.IntOutput {
	return o.ApplyT(func(v LookupNetworkFirewallPolicyUrlListResult) int { return v.TotalUrls }).(pulumi.IntOutput)
}

// List of urls.
func (o LookupNetworkFirewallPolicyUrlListResultOutput) Urls() GetNetworkFirewallPolicyUrlListUrlArrayOutput {
	return o.ApplyT(func(v LookupNetworkFirewallPolicyUrlListResult) []GetNetworkFirewallPolicyUrlListUrl { return v.Urls }).(GetNetworkFirewallPolicyUrlListUrlArrayOutput)
}

func init() {
	pulumi.RegisterOutputType(LookupNetworkFirewallPolicyUrlListResultOutput{})
}
