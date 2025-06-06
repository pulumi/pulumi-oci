// Code generated by pulumi-language-go DO NOT EDIT.
// *** WARNING: Do not edit by hand unless you're certain you know what you are doing! ***

package networkfirewall

import (
	"context"
	"reflect"

	"github.com/pulumi/pulumi-oci/sdk/v3/go/oci/internal"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This data source provides details about a specific Network Firewall Policy Nat Rule resource in Oracle Cloud Infrastructure Network Firewall service.
//
// Get NAT Rule by the given name in the context of network firewall policy.
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
//			_, err := networkfirewall.GetNetworkFirewallPolicyNatRule(ctx, &networkfirewall.GetNetworkFirewallPolicyNatRuleArgs{
//				NatRuleName:             testRule.Name,
//				NetworkFirewallPolicyId: testNetworkFirewallPolicy.Id,
//			}, nil)
//			if err != nil {
//				return err
//			}
//			return nil
//		})
//	}
//
// ```
func LookupNetworkFirewallPolicyNatRule(ctx *pulumi.Context, args *LookupNetworkFirewallPolicyNatRuleArgs, opts ...pulumi.InvokeOption) (*LookupNetworkFirewallPolicyNatRuleResult, error) {
	opts = internal.PkgInvokeDefaultOpts(opts)
	var rv LookupNetworkFirewallPolicyNatRuleResult
	err := ctx.Invoke("oci:NetworkFirewall/getNetworkFirewallPolicyNatRule:getNetworkFirewallPolicyNatRule", args, &rv, opts...)
	if err != nil {
		return nil, err
	}
	return &rv, nil
}

// A collection of arguments for invoking getNetworkFirewallPolicyNatRule.
type LookupNetworkFirewallPolicyNatRuleArgs struct {
	// Unique identifier for NAT Rules in the network firewall policy.
	NatRuleName string `pulumi:"natRuleName"`
	// Unique Network Firewall Policy identifier
	NetworkFirewallPolicyId string `pulumi:"networkFirewallPolicyId"`
}

// A collection of values returned by getNetworkFirewallPolicyNatRule.
type LookupNetworkFirewallPolicyNatRuleResult struct {
	// action:
	// * DIPP_SRC_NAT - Dynamic-ip-port source NAT.
	Action string `pulumi:"action"`
	// Match criteria used in NAT Rule used on the firewall policy.
	Conditions []GetNetworkFirewallPolicyNatRuleCondition `pulumi:"conditions"`
	// Description of a NAT rule. This field can be used to add additional info.
	Description string `pulumi:"description"`
	Id          string `pulumi:"id"`
	// Name for the NAT rule, must be unique within the policy.
	Name                    string `pulumi:"name"`
	NatRuleName             string `pulumi:"natRuleName"`
	NetworkFirewallPolicyId string `pulumi:"networkFirewallPolicyId"`
	// OCID of the Network Firewall Policy this decryption profile belongs to.
	ParentResourceId string `pulumi:"parentResourceId"`
	// An object which defines the position of the rule.
	Positions []GetNetworkFirewallPolicyNatRulePosition `pulumi:"positions"`
	// The priority order in which this rule should be evaluated
	PriorityOrder string `pulumi:"priorityOrder"`
	// NAT type:
	// * NATV4 - NATV4 type NAT.
	Type string `pulumi:"type"`
}

func LookupNetworkFirewallPolicyNatRuleOutput(ctx *pulumi.Context, args LookupNetworkFirewallPolicyNatRuleOutputArgs, opts ...pulumi.InvokeOption) LookupNetworkFirewallPolicyNatRuleResultOutput {
	return pulumi.ToOutputWithContext(ctx.Context(), args).
		ApplyT(func(v interface{}) (LookupNetworkFirewallPolicyNatRuleResultOutput, error) {
			args := v.(LookupNetworkFirewallPolicyNatRuleArgs)
			options := pulumi.InvokeOutputOptions{InvokeOptions: internal.PkgInvokeDefaultOpts(opts)}
			return ctx.InvokeOutput("oci:NetworkFirewall/getNetworkFirewallPolicyNatRule:getNetworkFirewallPolicyNatRule", args, LookupNetworkFirewallPolicyNatRuleResultOutput{}, options).(LookupNetworkFirewallPolicyNatRuleResultOutput), nil
		}).(LookupNetworkFirewallPolicyNatRuleResultOutput)
}

// A collection of arguments for invoking getNetworkFirewallPolicyNatRule.
type LookupNetworkFirewallPolicyNatRuleOutputArgs struct {
	// Unique identifier for NAT Rules in the network firewall policy.
	NatRuleName pulumi.StringInput `pulumi:"natRuleName"`
	// Unique Network Firewall Policy identifier
	NetworkFirewallPolicyId pulumi.StringInput `pulumi:"networkFirewallPolicyId"`
}

func (LookupNetworkFirewallPolicyNatRuleOutputArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*LookupNetworkFirewallPolicyNatRuleArgs)(nil)).Elem()
}

// A collection of values returned by getNetworkFirewallPolicyNatRule.
type LookupNetworkFirewallPolicyNatRuleResultOutput struct{ *pulumi.OutputState }

func (LookupNetworkFirewallPolicyNatRuleResultOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*LookupNetworkFirewallPolicyNatRuleResult)(nil)).Elem()
}

func (o LookupNetworkFirewallPolicyNatRuleResultOutput) ToLookupNetworkFirewallPolicyNatRuleResultOutput() LookupNetworkFirewallPolicyNatRuleResultOutput {
	return o
}

func (o LookupNetworkFirewallPolicyNatRuleResultOutput) ToLookupNetworkFirewallPolicyNatRuleResultOutputWithContext(ctx context.Context) LookupNetworkFirewallPolicyNatRuleResultOutput {
	return o
}

// action:
// * DIPP_SRC_NAT - Dynamic-ip-port source NAT.
func (o LookupNetworkFirewallPolicyNatRuleResultOutput) Action() pulumi.StringOutput {
	return o.ApplyT(func(v LookupNetworkFirewallPolicyNatRuleResult) string { return v.Action }).(pulumi.StringOutput)
}

// Match criteria used in NAT Rule used on the firewall policy.
func (o LookupNetworkFirewallPolicyNatRuleResultOutput) Conditions() GetNetworkFirewallPolicyNatRuleConditionArrayOutput {
	return o.ApplyT(func(v LookupNetworkFirewallPolicyNatRuleResult) []GetNetworkFirewallPolicyNatRuleCondition {
		return v.Conditions
	}).(GetNetworkFirewallPolicyNatRuleConditionArrayOutput)
}

// Description of a NAT rule. This field can be used to add additional info.
func (o LookupNetworkFirewallPolicyNatRuleResultOutput) Description() pulumi.StringOutput {
	return o.ApplyT(func(v LookupNetworkFirewallPolicyNatRuleResult) string { return v.Description }).(pulumi.StringOutput)
}

func (o LookupNetworkFirewallPolicyNatRuleResultOutput) Id() pulumi.StringOutput {
	return o.ApplyT(func(v LookupNetworkFirewallPolicyNatRuleResult) string { return v.Id }).(pulumi.StringOutput)
}

// Name for the NAT rule, must be unique within the policy.
func (o LookupNetworkFirewallPolicyNatRuleResultOutput) Name() pulumi.StringOutput {
	return o.ApplyT(func(v LookupNetworkFirewallPolicyNatRuleResult) string { return v.Name }).(pulumi.StringOutput)
}

func (o LookupNetworkFirewallPolicyNatRuleResultOutput) NatRuleName() pulumi.StringOutput {
	return o.ApplyT(func(v LookupNetworkFirewallPolicyNatRuleResult) string { return v.NatRuleName }).(pulumi.StringOutput)
}

func (o LookupNetworkFirewallPolicyNatRuleResultOutput) NetworkFirewallPolicyId() pulumi.StringOutput {
	return o.ApplyT(func(v LookupNetworkFirewallPolicyNatRuleResult) string { return v.NetworkFirewallPolicyId }).(pulumi.StringOutput)
}

// OCID of the Network Firewall Policy this decryption profile belongs to.
func (o LookupNetworkFirewallPolicyNatRuleResultOutput) ParentResourceId() pulumi.StringOutput {
	return o.ApplyT(func(v LookupNetworkFirewallPolicyNatRuleResult) string { return v.ParentResourceId }).(pulumi.StringOutput)
}

// An object which defines the position of the rule.
func (o LookupNetworkFirewallPolicyNatRuleResultOutput) Positions() GetNetworkFirewallPolicyNatRulePositionArrayOutput {
	return o.ApplyT(func(v LookupNetworkFirewallPolicyNatRuleResult) []GetNetworkFirewallPolicyNatRulePosition {
		return v.Positions
	}).(GetNetworkFirewallPolicyNatRulePositionArrayOutput)
}

// The priority order in which this rule should be evaluated
func (o LookupNetworkFirewallPolicyNatRuleResultOutput) PriorityOrder() pulumi.StringOutput {
	return o.ApplyT(func(v LookupNetworkFirewallPolicyNatRuleResult) string { return v.PriorityOrder }).(pulumi.StringOutput)
}

// NAT type:
// * NATV4 - NATV4 type NAT.
func (o LookupNetworkFirewallPolicyNatRuleResultOutput) Type() pulumi.StringOutput {
	return o.ApplyT(func(v LookupNetworkFirewallPolicyNatRuleResult) string { return v.Type }).(pulumi.StringOutput)
}

func init() {
	pulumi.RegisterOutputType(LookupNetworkFirewallPolicyNatRuleResultOutput{})
}
