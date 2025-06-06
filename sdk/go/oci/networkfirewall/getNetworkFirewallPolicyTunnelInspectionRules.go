// Code generated by pulumi-language-go DO NOT EDIT.
// *** WARNING: Do not edit by hand unless you're certain you know what you are doing! ***

package networkfirewall

import (
	"context"
	"reflect"

	"github.com/pulumi/pulumi-oci/sdk/v3/go/oci/internal"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This data source provides the list of Network Firewall Policy Tunnel Inspection Rules in Oracle Cloud Infrastructure Network Firewall service.
//
// Returns a list of tunnel inspection rules for the network firewall policy.
//
// ## Example Usage
//
// ```go
// package main
//
// import (
//
//	"github.com/pulumi/pulumi-oci/sdk/v3/go/oci/networkfirewall"
//	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
//
// )
//
//	func main() {
//		pulumi.Run(func(ctx *pulumi.Context) error {
//			_, err := networkfirewall.GetNetworkFirewallPolicyTunnelInspectionRules(ctx, &networkfirewall.GetNetworkFirewallPolicyTunnelInspectionRulesArgs{
//				NetworkFirewallPolicyId:           testNetworkFirewallPolicy.Id,
//				DisplayName:                       pulumi.StringRef(networkFirewallPolicyTunnelInspectionRuleDisplayName),
//				TunnelInspectionRulePriorityOrder: pulumi.IntRef(networkFirewallPolicyTunnelInspectionRuleTunnelInspectionRulePriorityOrder),
//			}, nil)
//			if err != nil {
//				return err
//			}
//			return nil
//		})
//	}
//
// ```
func GetNetworkFirewallPolicyTunnelInspectionRules(ctx *pulumi.Context, args *GetNetworkFirewallPolicyTunnelInspectionRulesArgs, opts ...pulumi.InvokeOption) (*GetNetworkFirewallPolicyTunnelInspectionRulesResult, error) {
	opts = internal.PkgInvokeDefaultOpts(opts)
	var rv GetNetworkFirewallPolicyTunnelInspectionRulesResult
	err := ctx.Invoke("oci:NetworkFirewall/getNetworkFirewallPolicyTunnelInspectionRules:getNetworkFirewallPolicyTunnelInspectionRules", args, &rv, opts...)
	if err != nil {
		return nil, err
	}
	return &rv, nil
}

// A collection of arguments for invoking getNetworkFirewallPolicyTunnelInspectionRules.
type GetNetworkFirewallPolicyTunnelInspectionRulesArgs struct {
	// A filter to return only resources that match the entire display name given.
	DisplayName *string                                               `pulumi:"displayName"`
	Filters     []GetNetworkFirewallPolicyTunnelInspectionRulesFilter `pulumi:"filters"`
	// Unique Network Firewall Policy identifier
	NetworkFirewallPolicyId string `pulumi:"networkFirewallPolicyId"`
	// Unique priority order for Tunnel Inspection rules in the network firewall policy.
	TunnelInspectionRulePriorityOrder *int `pulumi:"tunnelInspectionRulePriorityOrder"`
}

// A collection of values returned by getNetworkFirewallPolicyTunnelInspectionRules.
type GetNetworkFirewallPolicyTunnelInspectionRulesResult struct {
	DisplayName *string                                               `pulumi:"displayName"`
	Filters     []GetNetworkFirewallPolicyTunnelInspectionRulesFilter `pulumi:"filters"`
	// The provider-assigned unique ID for this managed resource.
	Id                                string `pulumi:"id"`
	NetworkFirewallPolicyId           string `pulumi:"networkFirewallPolicyId"`
	TunnelInspectionRulePriorityOrder *int   `pulumi:"tunnelInspectionRulePriorityOrder"`
	// The list of tunnel_inspection_rule_summary_collection.
	TunnelInspectionRuleSummaryCollections []GetNetworkFirewallPolicyTunnelInspectionRulesTunnelInspectionRuleSummaryCollection `pulumi:"tunnelInspectionRuleSummaryCollections"`
}

func GetNetworkFirewallPolicyTunnelInspectionRulesOutput(ctx *pulumi.Context, args GetNetworkFirewallPolicyTunnelInspectionRulesOutputArgs, opts ...pulumi.InvokeOption) GetNetworkFirewallPolicyTunnelInspectionRulesResultOutput {
	return pulumi.ToOutputWithContext(ctx.Context(), args).
		ApplyT(func(v interface{}) (GetNetworkFirewallPolicyTunnelInspectionRulesResultOutput, error) {
			args := v.(GetNetworkFirewallPolicyTunnelInspectionRulesArgs)
			options := pulumi.InvokeOutputOptions{InvokeOptions: internal.PkgInvokeDefaultOpts(opts)}
			return ctx.InvokeOutput("oci:NetworkFirewall/getNetworkFirewallPolicyTunnelInspectionRules:getNetworkFirewallPolicyTunnelInspectionRules", args, GetNetworkFirewallPolicyTunnelInspectionRulesResultOutput{}, options).(GetNetworkFirewallPolicyTunnelInspectionRulesResultOutput), nil
		}).(GetNetworkFirewallPolicyTunnelInspectionRulesResultOutput)
}

// A collection of arguments for invoking getNetworkFirewallPolicyTunnelInspectionRules.
type GetNetworkFirewallPolicyTunnelInspectionRulesOutputArgs struct {
	// A filter to return only resources that match the entire display name given.
	DisplayName pulumi.StringPtrInput                                         `pulumi:"displayName"`
	Filters     GetNetworkFirewallPolicyTunnelInspectionRulesFilterArrayInput `pulumi:"filters"`
	// Unique Network Firewall Policy identifier
	NetworkFirewallPolicyId pulumi.StringInput `pulumi:"networkFirewallPolicyId"`
	// Unique priority order for Tunnel Inspection rules in the network firewall policy.
	TunnelInspectionRulePriorityOrder pulumi.IntPtrInput `pulumi:"tunnelInspectionRulePriorityOrder"`
}

func (GetNetworkFirewallPolicyTunnelInspectionRulesOutputArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*GetNetworkFirewallPolicyTunnelInspectionRulesArgs)(nil)).Elem()
}

// A collection of values returned by getNetworkFirewallPolicyTunnelInspectionRules.
type GetNetworkFirewallPolicyTunnelInspectionRulesResultOutput struct{ *pulumi.OutputState }

func (GetNetworkFirewallPolicyTunnelInspectionRulesResultOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*GetNetworkFirewallPolicyTunnelInspectionRulesResult)(nil)).Elem()
}

func (o GetNetworkFirewallPolicyTunnelInspectionRulesResultOutput) ToGetNetworkFirewallPolicyTunnelInspectionRulesResultOutput() GetNetworkFirewallPolicyTunnelInspectionRulesResultOutput {
	return o
}

func (o GetNetworkFirewallPolicyTunnelInspectionRulesResultOutput) ToGetNetworkFirewallPolicyTunnelInspectionRulesResultOutputWithContext(ctx context.Context) GetNetworkFirewallPolicyTunnelInspectionRulesResultOutput {
	return o
}

func (o GetNetworkFirewallPolicyTunnelInspectionRulesResultOutput) DisplayName() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetNetworkFirewallPolicyTunnelInspectionRulesResult) *string { return v.DisplayName }).(pulumi.StringPtrOutput)
}

func (o GetNetworkFirewallPolicyTunnelInspectionRulesResultOutput) Filters() GetNetworkFirewallPolicyTunnelInspectionRulesFilterArrayOutput {
	return o.ApplyT(func(v GetNetworkFirewallPolicyTunnelInspectionRulesResult) []GetNetworkFirewallPolicyTunnelInspectionRulesFilter {
		return v.Filters
	}).(GetNetworkFirewallPolicyTunnelInspectionRulesFilterArrayOutput)
}

// The provider-assigned unique ID for this managed resource.
func (o GetNetworkFirewallPolicyTunnelInspectionRulesResultOutput) Id() pulumi.StringOutput {
	return o.ApplyT(func(v GetNetworkFirewallPolicyTunnelInspectionRulesResult) string { return v.Id }).(pulumi.StringOutput)
}

func (o GetNetworkFirewallPolicyTunnelInspectionRulesResultOutput) NetworkFirewallPolicyId() pulumi.StringOutput {
	return o.ApplyT(func(v GetNetworkFirewallPolicyTunnelInspectionRulesResult) string { return v.NetworkFirewallPolicyId }).(pulumi.StringOutput)
}

func (o GetNetworkFirewallPolicyTunnelInspectionRulesResultOutput) TunnelInspectionRulePriorityOrder() pulumi.IntPtrOutput {
	return o.ApplyT(func(v GetNetworkFirewallPolicyTunnelInspectionRulesResult) *int {
		return v.TunnelInspectionRulePriorityOrder
	}).(pulumi.IntPtrOutput)
}

// The list of tunnel_inspection_rule_summary_collection.
func (o GetNetworkFirewallPolicyTunnelInspectionRulesResultOutput) TunnelInspectionRuleSummaryCollections() GetNetworkFirewallPolicyTunnelInspectionRulesTunnelInspectionRuleSummaryCollectionArrayOutput {
	return o.ApplyT(func(v GetNetworkFirewallPolicyTunnelInspectionRulesResult) []GetNetworkFirewallPolicyTunnelInspectionRulesTunnelInspectionRuleSummaryCollection {
		return v.TunnelInspectionRuleSummaryCollections
	}).(GetNetworkFirewallPolicyTunnelInspectionRulesTunnelInspectionRuleSummaryCollectionArrayOutput)
}

func init() {
	pulumi.RegisterOutputType(GetNetworkFirewallPolicyTunnelInspectionRulesResultOutput{})
}
