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

// This data source provides the list of Network Firewall Policy Service Lists in Oracle Cloud Infrastructure Network Firewall service.
//
// Returns a list of ServiceLists for the policy.
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
//			_, err := NetworkFirewall.GetNetworkFirewallPolicyServiceLists(ctx, &networkfirewall.GetNetworkFirewallPolicyServiceListsArgs{
//				NetworkFirewallPolicyId: oci_network_firewall_network_firewall_policy.Test_network_firewall_policy.Id,
//				DisplayName:             pulumi.StringRef(_var.Network_firewall_policy_service_list_display_name),
//			}, nil)
//			if err != nil {
//				return err
//			}
//			return nil
//		})
//	}
//
// ```
func GetNetworkFirewallPolicyServiceLists(ctx *pulumi.Context, args *GetNetworkFirewallPolicyServiceListsArgs, opts ...pulumi.InvokeOption) (*GetNetworkFirewallPolicyServiceListsResult, error) {
	opts = internal.PkgInvokeDefaultOpts(opts)
	var rv GetNetworkFirewallPolicyServiceListsResult
	err := ctx.Invoke("oci:NetworkFirewall/getNetworkFirewallPolicyServiceLists:getNetworkFirewallPolicyServiceLists", args, &rv, opts...)
	if err != nil {
		return nil, err
	}
	return &rv, nil
}

// A collection of arguments for invoking getNetworkFirewallPolicyServiceLists.
type GetNetworkFirewallPolicyServiceListsArgs struct {
	// A filter to return only resources that match the entire display name given.
	DisplayName *string                                      `pulumi:"displayName"`
	Filters     []GetNetworkFirewallPolicyServiceListsFilter `pulumi:"filters"`
	// Unique Network Firewall Policy identifier
	NetworkFirewallPolicyId string `pulumi:"networkFirewallPolicyId"`
}

// A collection of values returned by getNetworkFirewallPolicyServiceLists.
type GetNetworkFirewallPolicyServiceListsResult struct {
	DisplayName *string                                      `pulumi:"displayName"`
	Filters     []GetNetworkFirewallPolicyServiceListsFilter `pulumi:"filters"`
	// The provider-assigned unique ID for this managed resource.
	Id                      string `pulumi:"id"`
	NetworkFirewallPolicyId string `pulumi:"networkFirewallPolicyId"`
	// The list of service_list_summary_collection.
	ServiceListSummaryCollections []GetNetworkFirewallPolicyServiceListsServiceListSummaryCollection `pulumi:"serviceListSummaryCollections"`
}

func GetNetworkFirewallPolicyServiceListsOutput(ctx *pulumi.Context, args GetNetworkFirewallPolicyServiceListsOutputArgs, opts ...pulumi.InvokeOption) GetNetworkFirewallPolicyServiceListsResultOutput {
	return pulumi.ToOutputWithContext(context.Background(), args).
		ApplyT(func(v interface{}) (GetNetworkFirewallPolicyServiceListsResult, error) {
			args := v.(GetNetworkFirewallPolicyServiceListsArgs)
			r, err := GetNetworkFirewallPolicyServiceLists(ctx, &args, opts...)
			var s GetNetworkFirewallPolicyServiceListsResult
			if r != nil {
				s = *r
			}
			return s, err
		}).(GetNetworkFirewallPolicyServiceListsResultOutput)
}

// A collection of arguments for invoking getNetworkFirewallPolicyServiceLists.
type GetNetworkFirewallPolicyServiceListsOutputArgs struct {
	// A filter to return only resources that match the entire display name given.
	DisplayName pulumi.StringPtrInput                                `pulumi:"displayName"`
	Filters     GetNetworkFirewallPolicyServiceListsFilterArrayInput `pulumi:"filters"`
	// Unique Network Firewall Policy identifier
	NetworkFirewallPolicyId pulumi.StringInput `pulumi:"networkFirewallPolicyId"`
}

func (GetNetworkFirewallPolicyServiceListsOutputArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*GetNetworkFirewallPolicyServiceListsArgs)(nil)).Elem()
}

// A collection of values returned by getNetworkFirewallPolicyServiceLists.
type GetNetworkFirewallPolicyServiceListsResultOutput struct{ *pulumi.OutputState }

func (GetNetworkFirewallPolicyServiceListsResultOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*GetNetworkFirewallPolicyServiceListsResult)(nil)).Elem()
}

func (o GetNetworkFirewallPolicyServiceListsResultOutput) ToGetNetworkFirewallPolicyServiceListsResultOutput() GetNetworkFirewallPolicyServiceListsResultOutput {
	return o
}

func (o GetNetworkFirewallPolicyServiceListsResultOutput) ToGetNetworkFirewallPolicyServiceListsResultOutputWithContext(ctx context.Context) GetNetworkFirewallPolicyServiceListsResultOutput {
	return o
}

func (o GetNetworkFirewallPolicyServiceListsResultOutput) ToOutput(ctx context.Context) pulumix.Output[GetNetworkFirewallPolicyServiceListsResult] {
	return pulumix.Output[GetNetworkFirewallPolicyServiceListsResult]{
		OutputState: o.OutputState,
	}
}

func (o GetNetworkFirewallPolicyServiceListsResultOutput) DisplayName() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetNetworkFirewallPolicyServiceListsResult) *string { return v.DisplayName }).(pulumi.StringPtrOutput)
}

func (o GetNetworkFirewallPolicyServiceListsResultOutput) Filters() GetNetworkFirewallPolicyServiceListsFilterArrayOutput {
	return o.ApplyT(func(v GetNetworkFirewallPolicyServiceListsResult) []GetNetworkFirewallPolicyServiceListsFilter {
		return v.Filters
	}).(GetNetworkFirewallPolicyServiceListsFilterArrayOutput)
}

// The provider-assigned unique ID for this managed resource.
func (o GetNetworkFirewallPolicyServiceListsResultOutput) Id() pulumi.StringOutput {
	return o.ApplyT(func(v GetNetworkFirewallPolicyServiceListsResult) string { return v.Id }).(pulumi.StringOutput)
}

func (o GetNetworkFirewallPolicyServiceListsResultOutput) NetworkFirewallPolicyId() pulumi.StringOutput {
	return o.ApplyT(func(v GetNetworkFirewallPolicyServiceListsResult) string { return v.NetworkFirewallPolicyId }).(pulumi.StringOutput)
}

// The list of service_list_summary_collection.
func (o GetNetworkFirewallPolicyServiceListsResultOutput) ServiceListSummaryCollections() GetNetworkFirewallPolicyServiceListsServiceListSummaryCollectionArrayOutput {
	return o.ApplyT(func(v GetNetworkFirewallPolicyServiceListsResult) []GetNetworkFirewallPolicyServiceListsServiceListSummaryCollection {
		return v.ServiceListSummaryCollections
	}).(GetNetworkFirewallPolicyServiceListsServiceListSummaryCollectionArrayOutput)
}

func init() {
	pulumi.RegisterOutputType(GetNetworkFirewallPolicyServiceListsResultOutput{})
}