// Code generated by the Pulumi Terraform Bridge (tfgen) Tool DO NOT EDIT.
// *** WARNING: Do not edit by hand unless you're certain you know what you are doing! ***

package networkloadbalancer

import (
	"context"
	"reflect"

	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This data source provides details about a specific Network Load Balancer resource in Oracle Cloud Infrastructure Network Load Balancer service.
//
// Retrieves network load balancer configuration information by identifier.
//
// ## Example Usage
//
// ```go
// package main
//
// import (
//
//	"github.com/pulumi/pulumi-oci/sdk/go/oci/NetworkLoadBalancer"
//	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
//
// )
//
//	func main() {
//		pulumi.Run(func(ctx *pulumi.Context) error {
//			_, err := NetworkLoadBalancer.GetNetworkLoadBalancer(ctx, &networkloadbalancer.GetNetworkLoadBalancerArgs{
//				NetworkLoadBalancerId: oci_network_load_balancer_network_load_balancer.Test_network_load_balancer.Id,
//			}, nil)
//			if err != nil {
//				return err
//			}
//			return nil
//		})
//	}
//
// ```
func LookupNetworkLoadBalancer(ctx *pulumi.Context, args *LookupNetworkLoadBalancerArgs, opts ...pulumi.InvokeOption) (*LookupNetworkLoadBalancerResult, error) {
	var rv LookupNetworkLoadBalancerResult
	err := ctx.Invoke("oci:NetworkLoadBalancer/getNetworkLoadBalancer:getNetworkLoadBalancer", args, &rv, opts...)
	if err != nil {
		return nil, err
	}
	return &rv, nil
}

// A collection of arguments for invoking getNetworkLoadBalancer.
type LookupNetworkLoadBalancerArgs struct {
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the network load balancer to update.
	NetworkLoadBalancerId string `pulumi:"networkLoadBalancerId"`
}

// A collection of values returned by getNetworkLoadBalancer.
type LookupNetworkLoadBalancerResult struct {
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment containing the network load balancer.
	CompartmentId string `pulumi:"compartmentId"`
	// Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Operations.CostCenter": "42"}`
	DefinedTags map[string]interface{} `pulumi:"definedTags"`
	// A user-friendly name, which does not have to be unique, and can be changed.  Example: `exampleLoadBalancer`
	DisplayName string `pulumi:"displayName"`
	// Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
	FreeformTags map[string]interface{} `pulumi:"freeformTags"`
	// OCID of the reserved public IP address created with the virtual cloud network.
	Id string `pulumi:"id"`
	// An array of IP addresses.
	IpAddresses []GetNetworkLoadBalancerIpAddress `pulumi:"ipAddresses"`
	// When enabled, the skipSourceDestinationCheck parameter is automatically enabled on the load balancer VNIC. Packets are sent to the backend set without any changes to the source and destination IP.
	IsPreserveSourceDestination bool `pulumi:"isPreserveSourceDestination"`
	// Whether the network load balancer has a virtual cloud network-local (private) IP address.
	IsPrivate bool `pulumi:"isPrivate"`
	// A message describing the current state in more detail. For example, can be used to provide actionable information for a resource in Failed state.
	LifecycleDetails      string `pulumi:"lifecycleDetails"`
	NetworkLoadBalancerId string `pulumi:"networkLoadBalancerId"`
	// An array of network security groups [OCIDs](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) associated with the network load balancer.
	NetworkSecurityGroupIds []string `pulumi:"networkSecurityGroupIds"`
	// IP version associated with the NLB.
	NlbIpVersion string                             `pulumi:"nlbIpVersion"`
	ReservedIps  []GetNetworkLoadBalancerReservedIp `pulumi:"reservedIps"`
	// The current state of the network load balancer.
	State string `pulumi:"state"`
	// The subnet in which the network load balancer is spawned [OCIDs](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm)."
	SubnetId string `pulumi:"subnetId"`
	// Key-value pair representing system tags' keys and values scoped to a namespace. Example: `{"bar-key": "value"}`
	SystemTags map[string]interface{} `pulumi:"systemTags"`
	// The date and time the network load balancer was created, in the format defined by RFC3339.  Example: `2020-05-01T21:10:29.600Z`
	TimeCreated string `pulumi:"timeCreated"`
	// The time the network load balancer was updated. An RFC3339 formatted date-time string.  Example: `2020-05-01T22:10:29.600Z`
	TimeUpdated string `pulumi:"timeUpdated"`
}

func LookupNetworkLoadBalancerOutput(ctx *pulumi.Context, args LookupNetworkLoadBalancerOutputArgs, opts ...pulumi.InvokeOption) LookupNetworkLoadBalancerResultOutput {
	return pulumi.ToOutputWithContext(context.Background(), args).
		ApplyT(func(v interface{}) (LookupNetworkLoadBalancerResult, error) {
			args := v.(LookupNetworkLoadBalancerArgs)
			r, err := LookupNetworkLoadBalancer(ctx, &args, opts...)
			var s LookupNetworkLoadBalancerResult
			if r != nil {
				s = *r
			}
			return s, err
		}).(LookupNetworkLoadBalancerResultOutput)
}

// A collection of arguments for invoking getNetworkLoadBalancer.
type LookupNetworkLoadBalancerOutputArgs struct {
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the network load balancer to update.
	NetworkLoadBalancerId pulumi.StringInput `pulumi:"networkLoadBalancerId"`
}

func (LookupNetworkLoadBalancerOutputArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*LookupNetworkLoadBalancerArgs)(nil)).Elem()
}

// A collection of values returned by getNetworkLoadBalancer.
type LookupNetworkLoadBalancerResultOutput struct{ *pulumi.OutputState }

func (LookupNetworkLoadBalancerResultOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*LookupNetworkLoadBalancerResult)(nil)).Elem()
}

func (o LookupNetworkLoadBalancerResultOutput) ToLookupNetworkLoadBalancerResultOutput() LookupNetworkLoadBalancerResultOutput {
	return o
}

func (o LookupNetworkLoadBalancerResultOutput) ToLookupNetworkLoadBalancerResultOutputWithContext(ctx context.Context) LookupNetworkLoadBalancerResultOutput {
	return o
}

// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment containing the network load balancer.
func (o LookupNetworkLoadBalancerResultOutput) CompartmentId() pulumi.StringOutput {
	return o.ApplyT(func(v LookupNetworkLoadBalancerResult) string { return v.CompartmentId }).(pulumi.StringOutput)
}

// Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Operations.CostCenter": "42"}`
func (o LookupNetworkLoadBalancerResultOutput) DefinedTags() pulumi.MapOutput {
	return o.ApplyT(func(v LookupNetworkLoadBalancerResult) map[string]interface{} { return v.DefinedTags }).(pulumi.MapOutput)
}

// A user-friendly name, which does not have to be unique, and can be changed.  Example: `exampleLoadBalancer`
func (o LookupNetworkLoadBalancerResultOutput) DisplayName() pulumi.StringOutput {
	return o.ApplyT(func(v LookupNetworkLoadBalancerResult) string { return v.DisplayName }).(pulumi.StringOutput)
}

// Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
func (o LookupNetworkLoadBalancerResultOutput) FreeformTags() pulumi.MapOutput {
	return o.ApplyT(func(v LookupNetworkLoadBalancerResult) map[string]interface{} { return v.FreeformTags }).(pulumi.MapOutput)
}

// OCID of the reserved public IP address created with the virtual cloud network.
func (o LookupNetworkLoadBalancerResultOutput) Id() pulumi.StringOutput {
	return o.ApplyT(func(v LookupNetworkLoadBalancerResult) string { return v.Id }).(pulumi.StringOutput)
}

// An array of IP addresses.
func (o LookupNetworkLoadBalancerResultOutput) IpAddresses() GetNetworkLoadBalancerIpAddressArrayOutput {
	return o.ApplyT(func(v LookupNetworkLoadBalancerResult) []GetNetworkLoadBalancerIpAddress { return v.IpAddresses }).(GetNetworkLoadBalancerIpAddressArrayOutput)
}

// When enabled, the skipSourceDestinationCheck parameter is automatically enabled on the load balancer VNIC. Packets are sent to the backend set without any changes to the source and destination IP.
func (o LookupNetworkLoadBalancerResultOutput) IsPreserveSourceDestination() pulumi.BoolOutput {
	return o.ApplyT(func(v LookupNetworkLoadBalancerResult) bool { return v.IsPreserveSourceDestination }).(pulumi.BoolOutput)
}

// Whether the network load balancer has a virtual cloud network-local (private) IP address.
func (o LookupNetworkLoadBalancerResultOutput) IsPrivate() pulumi.BoolOutput {
	return o.ApplyT(func(v LookupNetworkLoadBalancerResult) bool { return v.IsPrivate }).(pulumi.BoolOutput)
}

// A message describing the current state in more detail. For example, can be used to provide actionable information for a resource in Failed state.
func (o LookupNetworkLoadBalancerResultOutput) LifecycleDetails() pulumi.StringOutput {
	return o.ApplyT(func(v LookupNetworkLoadBalancerResult) string { return v.LifecycleDetails }).(pulumi.StringOutput)
}

func (o LookupNetworkLoadBalancerResultOutput) NetworkLoadBalancerId() pulumi.StringOutput {
	return o.ApplyT(func(v LookupNetworkLoadBalancerResult) string { return v.NetworkLoadBalancerId }).(pulumi.StringOutput)
}

// An array of network security groups [OCIDs](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) associated with the network load balancer.
func (o LookupNetworkLoadBalancerResultOutput) NetworkSecurityGroupIds() pulumi.StringArrayOutput {
	return o.ApplyT(func(v LookupNetworkLoadBalancerResult) []string { return v.NetworkSecurityGroupIds }).(pulumi.StringArrayOutput)
}

// IP version associated with the NLB.
func (o LookupNetworkLoadBalancerResultOutput) NlbIpVersion() pulumi.StringOutput {
	return o.ApplyT(func(v LookupNetworkLoadBalancerResult) string { return v.NlbIpVersion }).(pulumi.StringOutput)
}

func (o LookupNetworkLoadBalancerResultOutput) ReservedIps() GetNetworkLoadBalancerReservedIpArrayOutput {
	return o.ApplyT(func(v LookupNetworkLoadBalancerResult) []GetNetworkLoadBalancerReservedIp { return v.ReservedIps }).(GetNetworkLoadBalancerReservedIpArrayOutput)
}

// The current state of the network load balancer.
func (o LookupNetworkLoadBalancerResultOutput) State() pulumi.StringOutput {
	return o.ApplyT(func(v LookupNetworkLoadBalancerResult) string { return v.State }).(pulumi.StringOutput)
}

// The subnet in which the network load balancer is spawned [OCIDs](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm)."
func (o LookupNetworkLoadBalancerResultOutput) SubnetId() pulumi.StringOutput {
	return o.ApplyT(func(v LookupNetworkLoadBalancerResult) string { return v.SubnetId }).(pulumi.StringOutput)
}

// Key-value pair representing system tags' keys and values scoped to a namespace. Example: `{"bar-key": "value"}`
func (o LookupNetworkLoadBalancerResultOutput) SystemTags() pulumi.MapOutput {
	return o.ApplyT(func(v LookupNetworkLoadBalancerResult) map[string]interface{} { return v.SystemTags }).(pulumi.MapOutput)
}

// The date and time the network load balancer was created, in the format defined by RFC3339.  Example: `2020-05-01T21:10:29.600Z`
func (o LookupNetworkLoadBalancerResultOutput) TimeCreated() pulumi.StringOutput {
	return o.ApplyT(func(v LookupNetworkLoadBalancerResult) string { return v.TimeCreated }).(pulumi.StringOutput)
}

// The time the network load balancer was updated. An RFC3339 formatted date-time string.  Example: `2020-05-01T22:10:29.600Z`
func (o LookupNetworkLoadBalancerResultOutput) TimeUpdated() pulumi.StringOutput {
	return o.ApplyT(func(v LookupNetworkLoadBalancerResult) string { return v.TimeUpdated }).(pulumi.StringOutput)
}

func init() {
	pulumi.RegisterOutputType(LookupNetworkLoadBalancerResultOutput{})
}