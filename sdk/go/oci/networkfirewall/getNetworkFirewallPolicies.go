// Code generated by the Pulumi Terraform Bridge (tfgen) Tool DO NOT EDIT.
// *** WARNING: Do not edit by hand unless you're certain you know what you are doing! ***

package networkfirewall

import (
	"context"
	"reflect"

	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This data source provides the list of Network Firewall Policies in Oracle Cloud Infrastructure Network Firewall service.
//
// Returns a list of Network Firewall Policies.
//
// ## Example Usage
//
// ```go
// package main
//
// import (
//
//	"github.com/pulumi/pulumi-oci/sdk/go/oci/NetworkFirewall"
//	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
//
// )
//
//	func main() {
//		pulumi.Run(func(ctx *pulumi.Context) error {
//			_, err := NetworkFirewall.GetNetworkFirewallPolicies(ctx, &networkfirewall.GetNetworkFirewallPoliciesArgs{
//				CompartmentId: _var.Compartment_id,
//				DisplayName:   pulumi.StringRef(_var.Network_firewall_policy_display_name),
//				Id:            pulumi.StringRef(_var.Network_firewall_policy_id),
//				State:         pulumi.StringRef(_var.Network_firewall_policy_state),
//			}, nil)
//			if err != nil {
//				return err
//			}
//			return nil
//		})
//	}
//
// ```
func GetNetworkFirewallPolicies(ctx *pulumi.Context, args *GetNetworkFirewallPoliciesArgs, opts ...pulumi.InvokeOption) (*GetNetworkFirewallPoliciesResult, error) {
	var rv GetNetworkFirewallPoliciesResult
	err := ctx.Invoke("oci:NetworkFirewall/getNetworkFirewallPolicies:getNetworkFirewallPolicies", args, &rv, opts...)
	if err != nil {
		return nil, err
	}
	return &rv, nil
}

// A collection of arguments for invoking getNetworkFirewallPolicies.
type GetNetworkFirewallPoliciesArgs struct {
	// The ID of the compartment in which to list resources.
	CompartmentId string `pulumi:"compartmentId"`
	// A filter to return only resources that match the entire display name given.
	DisplayName *string                            `pulumi:"displayName"`
	Filters     []GetNetworkFirewallPoliciesFilter `pulumi:"filters"`
	// Unique Network Firewall Policy identifier
	Id *string `pulumi:"id"`
	// A filter to return only resources with a lifecycleState matching the given value.
	State *string `pulumi:"state"`
}

// A collection of values returned by getNetworkFirewallPolicies.
type GetNetworkFirewallPoliciesResult struct {
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment containing the NetworkFirewall Policy.
	CompartmentId string `pulumi:"compartmentId"`
	// A user-friendly optional name for the firewall policy. Avoid entering confidential information.
	DisplayName *string                            `pulumi:"displayName"`
	Filters     []GetNetworkFirewallPoliciesFilter `pulumi:"filters"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the resource - Network Firewall Policy.
	Id *string `pulumi:"id"`
	// The list of network_firewall_policy_summary_collection.
	NetworkFirewallPolicySummaryCollections []GetNetworkFirewallPoliciesNetworkFirewallPolicySummaryCollection `pulumi:"networkFirewallPolicySummaryCollections"`
	// The current state of the Network Firewall Policy.
	State *string `pulumi:"state"`
}

func GetNetworkFirewallPoliciesOutput(ctx *pulumi.Context, args GetNetworkFirewallPoliciesOutputArgs, opts ...pulumi.InvokeOption) GetNetworkFirewallPoliciesResultOutput {
	return pulumi.ToOutputWithContext(context.Background(), args).
		ApplyT(func(v interface{}) (GetNetworkFirewallPoliciesResult, error) {
			args := v.(GetNetworkFirewallPoliciesArgs)
			r, err := GetNetworkFirewallPolicies(ctx, &args, opts...)
			var s GetNetworkFirewallPoliciesResult
			if r != nil {
				s = *r
			}
			return s, err
		}).(GetNetworkFirewallPoliciesResultOutput)
}

// A collection of arguments for invoking getNetworkFirewallPolicies.
type GetNetworkFirewallPoliciesOutputArgs struct {
	// The ID of the compartment in which to list resources.
	CompartmentId pulumi.StringInput `pulumi:"compartmentId"`
	// A filter to return only resources that match the entire display name given.
	DisplayName pulumi.StringPtrInput                      `pulumi:"displayName"`
	Filters     GetNetworkFirewallPoliciesFilterArrayInput `pulumi:"filters"`
	// Unique Network Firewall Policy identifier
	Id pulumi.StringPtrInput `pulumi:"id"`
	// A filter to return only resources with a lifecycleState matching the given value.
	State pulumi.StringPtrInput `pulumi:"state"`
}

func (GetNetworkFirewallPoliciesOutputArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*GetNetworkFirewallPoliciesArgs)(nil)).Elem()
}

// A collection of values returned by getNetworkFirewallPolicies.
type GetNetworkFirewallPoliciesResultOutput struct{ *pulumi.OutputState }

func (GetNetworkFirewallPoliciesResultOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*GetNetworkFirewallPoliciesResult)(nil)).Elem()
}

func (o GetNetworkFirewallPoliciesResultOutput) ToGetNetworkFirewallPoliciesResultOutput() GetNetworkFirewallPoliciesResultOutput {
	return o
}

func (o GetNetworkFirewallPoliciesResultOutput) ToGetNetworkFirewallPoliciesResultOutputWithContext(ctx context.Context) GetNetworkFirewallPoliciesResultOutput {
	return o
}

// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment containing the NetworkFirewall Policy.
func (o GetNetworkFirewallPoliciesResultOutput) CompartmentId() pulumi.StringOutput {
	return o.ApplyT(func(v GetNetworkFirewallPoliciesResult) string { return v.CompartmentId }).(pulumi.StringOutput)
}

// A user-friendly optional name for the firewall policy. Avoid entering confidential information.
func (o GetNetworkFirewallPoliciesResultOutput) DisplayName() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetNetworkFirewallPoliciesResult) *string { return v.DisplayName }).(pulumi.StringPtrOutput)
}

func (o GetNetworkFirewallPoliciesResultOutput) Filters() GetNetworkFirewallPoliciesFilterArrayOutput {
	return o.ApplyT(func(v GetNetworkFirewallPoliciesResult) []GetNetworkFirewallPoliciesFilter { return v.Filters }).(GetNetworkFirewallPoliciesFilterArrayOutput)
}

// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the resource - Network Firewall Policy.
func (o GetNetworkFirewallPoliciesResultOutput) Id() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetNetworkFirewallPoliciesResult) *string { return v.Id }).(pulumi.StringPtrOutput)
}

// The list of network_firewall_policy_summary_collection.
func (o GetNetworkFirewallPoliciesResultOutput) NetworkFirewallPolicySummaryCollections() GetNetworkFirewallPoliciesNetworkFirewallPolicySummaryCollectionArrayOutput {
	return o.ApplyT(func(v GetNetworkFirewallPoliciesResult) []GetNetworkFirewallPoliciesNetworkFirewallPolicySummaryCollection {
		return v.NetworkFirewallPolicySummaryCollections
	}).(GetNetworkFirewallPoliciesNetworkFirewallPolicySummaryCollectionArrayOutput)
}

// The current state of the Network Firewall Policy.
func (o GetNetworkFirewallPoliciesResultOutput) State() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetNetworkFirewallPoliciesResult) *string { return v.State }).(pulumi.StringPtrOutput)
}

func init() {
	pulumi.RegisterOutputType(GetNetworkFirewallPoliciesResultOutput{})
}