// Code generated by the Pulumi Terraform Bridge (tfgen) Tool DO NOT EDIT.
// *** WARNING: Do not edit by hand unless you're certain you know what you are doing! ***

package networkfirewall

import (
	"context"
	"reflect"

	"github.com/pulumi/pulumi-oci/sdk/go/oci/internal"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumix"
)

// This data source provides details about a specific Network Firewall Policy Decryption Rule resource in Oracle Cloud Infrastructure Network Firewall service.
//
// Get Decryption Rule by the given name in the context of network firewall policy.
func LookupNetworkFirewallPolicyDecryptionRule(ctx *pulumi.Context, args *LookupNetworkFirewallPolicyDecryptionRuleArgs, opts ...pulumi.InvokeOption) (*LookupNetworkFirewallPolicyDecryptionRuleResult, error) {
	opts = internal.PkgInvokeDefaultOpts(opts)
	var rv LookupNetworkFirewallPolicyDecryptionRuleResult
	err := ctx.Invoke("oci:NetworkFirewall/getNetworkFirewallPolicyDecryptionRule:getNetworkFirewallPolicyDecryptionRule", args, &rv, opts...)
	if err != nil {
		return nil, err
	}
	return &rv, nil
}

// A collection of arguments for invoking getNetworkFirewallPolicyDecryptionRule.
type LookupNetworkFirewallPolicyDecryptionRuleArgs struct {
	// Name for the decryption rule, must be unique within the policy.
	Name string `pulumi:"name"`
	// Unique Network Firewall Policy identifier
	NetworkFirewallPolicyId string `pulumi:"networkFirewallPolicyId"`
}

// A collection of values returned by getNetworkFirewallPolicyDecryptionRule.
type LookupNetworkFirewallPolicyDecryptionRuleResult struct {
	// Action:
	// * NO_DECRYPT - Matching traffic is not decrypted.
	// * DECRYPT - Matching traffic is decrypted with the specified `secret` according to the specified `decryptionProfile`.
	Action string `pulumi:"action"`
	// Match criteria used in Decryption Rule used on the firewall policy rules.
	Conditions []GetNetworkFirewallPolicyDecryptionRuleCondition `pulumi:"conditions"`
	// The name of the decryption profile to use.
	DecryptionProfile string `pulumi:"decryptionProfile"`
	Id                string `pulumi:"id"`
	// Name for the decryption rule, must be unique within the policy.
	Name                    string `pulumi:"name"`
	NetworkFirewallPolicyId string `pulumi:"networkFirewallPolicyId"`
	// OCID of the Network Firewall Policy this decryption rule belongs to.
	ParentResourceId string `pulumi:"parentResourceId"`
	// An object which defines the position of the rule.
	Positions     []GetNetworkFirewallPolicyDecryptionRulePosition `pulumi:"positions"`
	PriorityOrder string                                           `pulumi:"priorityOrder"`
	// The name of a mapped secret. Its `type` must match that of the specified decryption profile.
	Secret string `pulumi:"secret"`
}

func LookupNetworkFirewallPolicyDecryptionRuleOutput(ctx *pulumi.Context, args LookupNetworkFirewallPolicyDecryptionRuleOutputArgs, opts ...pulumi.InvokeOption) LookupNetworkFirewallPolicyDecryptionRuleResultOutput {
	return pulumi.ToOutputWithContext(context.Background(), args).
		ApplyT(func(v interface{}) (LookupNetworkFirewallPolicyDecryptionRuleResult, error) {
			args := v.(LookupNetworkFirewallPolicyDecryptionRuleArgs)
			r, err := LookupNetworkFirewallPolicyDecryptionRule(ctx, &args, opts...)
			var s LookupNetworkFirewallPolicyDecryptionRuleResult
			if r != nil {
				s = *r
			}
			return s, err
		}).(LookupNetworkFirewallPolicyDecryptionRuleResultOutput)
}

// A collection of arguments for invoking getNetworkFirewallPolicyDecryptionRule.
type LookupNetworkFirewallPolicyDecryptionRuleOutputArgs struct {
	// Name for the decryption rule, must be unique within the policy.
	Name pulumi.StringInput `pulumi:"name"`
	// Unique Network Firewall Policy identifier
	NetworkFirewallPolicyId pulumi.StringInput `pulumi:"networkFirewallPolicyId"`
}

func (LookupNetworkFirewallPolicyDecryptionRuleOutputArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*LookupNetworkFirewallPolicyDecryptionRuleArgs)(nil)).Elem()
}

// A collection of values returned by getNetworkFirewallPolicyDecryptionRule.
type LookupNetworkFirewallPolicyDecryptionRuleResultOutput struct{ *pulumi.OutputState }

func (LookupNetworkFirewallPolicyDecryptionRuleResultOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*LookupNetworkFirewallPolicyDecryptionRuleResult)(nil)).Elem()
}

func (o LookupNetworkFirewallPolicyDecryptionRuleResultOutput) ToLookupNetworkFirewallPolicyDecryptionRuleResultOutput() LookupNetworkFirewallPolicyDecryptionRuleResultOutput {
	return o
}

func (o LookupNetworkFirewallPolicyDecryptionRuleResultOutput) ToLookupNetworkFirewallPolicyDecryptionRuleResultOutputWithContext(ctx context.Context) LookupNetworkFirewallPolicyDecryptionRuleResultOutput {
	return o
}

func (o LookupNetworkFirewallPolicyDecryptionRuleResultOutput) ToOutput(ctx context.Context) pulumix.Output[LookupNetworkFirewallPolicyDecryptionRuleResult] {
	return pulumix.Output[LookupNetworkFirewallPolicyDecryptionRuleResult]{
		OutputState: o.OutputState,
	}
}

// Action:
// * NO_DECRYPT - Matching traffic is not decrypted.
// * DECRYPT - Matching traffic is decrypted with the specified `secret` according to the specified `decryptionProfile`.
func (o LookupNetworkFirewallPolicyDecryptionRuleResultOutput) Action() pulumi.StringOutput {
	return o.ApplyT(func(v LookupNetworkFirewallPolicyDecryptionRuleResult) string { return v.Action }).(pulumi.StringOutput)
}

// Match criteria used in Decryption Rule used on the firewall policy rules.
func (o LookupNetworkFirewallPolicyDecryptionRuleResultOutput) Conditions() GetNetworkFirewallPolicyDecryptionRuleConditionArrayOutput {
	return o.ApplyT(func(v LookupNetworkFirewallPolicyDecryptionRuleResult) []GetNetworkFirewallPolicyDecryptionRuleCondition {
		return v.Conditions
	}).(GetNetworkFirewallPolicyDecryptionRuleConditionArrayOutput)
}

// The name of the decryption profile to use.
func (o LookupNetworkFirewallPolicyDecryptionRuleResultOutput) DecryptionProfile() pulumi.StringOutput {
	return o.ApplyT(func(v LookupNetworkFirewallPolicyDecryptionRuleResult) string { return v.DecryptionProfile }).(pulumi.StringOutput)
}

func (o LookupNetworkFirewallPolicyDecryptionRuleResultOutput) Id() pulumi.StringOutput {
	return o.ApplyT(func(v LookupNetworkFirewallPolicyDecryptionRuleResult) string { return v.Id }).(pulumi.StringOutput)
}

// Name for the decryption rule, must be unique within the policy.
func (o LookupNetworkFirewallPolicyDecryptionRuleResultOutput) Name() pulumi.StringOutput {
	return o.ApplyT(func(v LookupNetworkFirewallPolicyDecryptionRuleResult) string { return v.Name }).(pulumi.StringOutput)
}

func (o LookupNetworkFirewallPolicyDecryptionRuleResultOutput) NetworkFirewallPolicyId() pulumi.StringOutput {
	return o.ApplyT(func(v LookupNetworkFirewallPolicyDecryptionRuleResult) string { return v.NetworkFirewallPolicyId }).(pulumi.StringOutput)
}

// OCID of the Network Firewall Policy this decryption rule belongs to.
func (o LookupNetworkFirewallPolicyDecryptionRuleResultOutput) ParentResourceId() pulumi.StringOutput {
	return o.ApplyT(func(v LookupNetworkFirewallPolicyDecryptionRuleResult) string { return v.ParentResourceId }).(pulumi.StringOutput)
}

// An object which defines the position of the rule.
func (o LookupNetworkFirewallPolicyDecryptionRuleResultOutput) Positions() GetNetworkFirewallPolicyDecryptionRulePositionArrayOutput {
	return o.ApplyT(func(v LookupNetworkFirewallPolicyDecryptionRuleResult) []GetNetworkFirewallPolicyDecryptionRulePosition {
		return v.Positions
	}).(GetNetworkFirewallPolicyDecryptionRulePositionArrayOutput)
}

func (o LookupNetworkFirewallPolicyDecryptionRuleResultOutput) PriorityOrder() pulumi.StringOutput {
	return o.ApplyT(func(v LookupNetworkFirewallPolicyDecryptionRuleResult) string { return v.PriorityOrder }).(pulumi.StringOutput)
}

// The name of a mapped secret. Its `type` must match that of the specified decryption profile.
func (o LookupNetworkFirewallPolicyDecryptionRuleResultOutput) Secret() pulumi.StringOutput {
	return o.ApplyT(func(v LookupNetworkFirewallPolicyDecryptionRuleResult) string { return v.Secret }).(pulumi.StringOutput)
}

func init() {
	pulumi.RegisterOutputType(LookupNetworkFirewallPolicyDecryptionRuleResultOutput{})
}