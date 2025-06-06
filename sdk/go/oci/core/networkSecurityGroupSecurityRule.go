// Code generated by pulumi-language-go DO NOT EDIT.
// *** WARNING: Do not edit by hand unless you're certain you know what you are doing! ***

package core

import (
	"context"
	"reflect"

	"errors"
	"github.com/pulumi/pulumi-oci/sdk/v3/go/oci/internal"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This resource provides the Network Security Group Security Rule resource in Oracle Cloud Infrastructure Core service.
//
// Adds up to 25 security rules to the specified network security group. Adding more than 25 rules requires multiple operations.
//
// ## Example Usage
//
// ```go
// package main
//
// import (
//
//	"github.com/pulumi/pulumi-oci/sdk/v3/go/oci/core"
//	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
//
// )
//
//	func main() {
//		pulumi.Run(func(ctx *pulumi.Context) error {
//			_, err := core.NewNetworkSecurityGroupSecurityRule(ctx, "test_network_security_group_security_rule", &core.NetworkSecurityGroupSecurityRuleArgs{
//				NetworkSecurityGroupId: pulumi.Any(testNetworkSecurityGroup.Id),
//				Direction:              pulumi.Any(networkSecurityGroupSecurityRuleDirection),
//				Protocol:               pulumi.Any(networkSecurityGroupSecurityRuleProtocol),
//				Description:            pulumi.Any(networkSecurityGroupSecurityRuleDescription),
//				Destination:            pulumi.Any(networkSecurityGroupSecurityRuleDestination),
//				DestinationType:        pulumi.Any(networkSecurityGroupSecurityRuleDestinationType),
//				IcmpOptions: &core.NetworkSecurityGroupSecurityRuleIcmpOptionsArgs{
//					Type: pulumi.Any(networkSecurityGroupSecurityRuleIcmpOptionsType),
//					Code: pulumi.Any(networkSecurityGroupSecurityRuleIcmpOptionsCode),
//				},
//				Source:     pulumi.Any(networkSecurityGroupSecurityRuleSource),
//				SourceType: pulumi.Any(networkSecurityGroupSecurityRuleSourceType),
//				Stateless:  pulumi.Any(networkSecurityGroupSecurityRuleStateless),
//				TcpOptions: &core.NetworkSecurityGroupSecurityRuleTcpOptionsArgs{
//					DestinationPortRange: &core.NetworkSecurityGroupSecurityRuleTcpOptionsDestinationPortRangeArgs{
//						Max: pulumi.Any(networkSecurityGroupSecurityRuleTcpOptionsDestinationPortRangeMax),
//						Min: pulumi.Any(networkSecurityGroupSecurityRuleTcpOptionsDestinationPortRangeMin),
//					},
//					SourcePortRange: &core.NetworkSecurityGroupSecurityRuleTcpOptionsSourcePortRangeArgs{
//						Max: pulumi.Any(networkSecurityGroupSecurityRuleTcpOptionsSourcePortRangeMax),
//						Min: pulumi.Any(networkSecurityGroupSecurityRuleTcpOptionsSourcePortRangeMin),
//					},
//				},
//				UdpOptions: &core.NetworkSecurityGroupSecurityRuleUdpOptionsArgs{
//					DestinationPortRange: &core.NetworkSecurityGroupSecurityRuleUdpOptionsDestinationPortRangeArgs{
//						Max: pulumi.Any(networkSecurityGroupSecurityRuleUdpOptionsDestinationPortRangeMax),
//						Min: pulumi.Any(networkSecurityGroupSecurityRuleUdpOptionsDestinationPortRangeMin),
//					},
//					SourcePortRange: &core.NetworkSecurityGroupSecurityRuleUdpOptionsSourcePortRangeArgs{
//						Max: pulumi.Any(networkSecurityGroupSecurityRuleUdpOptionsSourcePortRangeMax),
//						Min: pulumi.Any(networkSecurityGroupSecurityRuleUdpOptionsSourcePortRangeMin),
//					},
//				},
//			})
//			if err != nil {
//				return err
//			}
//			return nil
//		})
//	}
//
// ```
//
// ## Import
//
// NetworkSecurityGroupSecurityRule can be imported using the `id`, e.g.
//
// ```sh
// $ pulumi import oci:Core/networkSecurityGroupSecurityRule:NetworkSecurityGroupSecurityRule test_network_security_group_security_rule "networkSecurityGroups/{networkSecurityGroupId}/securityRules/{securityRuleId}"
// ```
type NetworkSecurityGroupSecurityRule struct {
	pulumi.CustomResourceState

	// An optional description of your choice for the rule.
	Description pulumi.StringOutput `pulumi:"description"`
	// Conceptually, this is the range of IP addresses that a packet originating from the instance can go to.
	Destination pulumi.StringOutput `pulumi:"destination"`
	// Type of destination for the rule. Required if `direction` = `EGRESS`.
	DestinationType pulumi.StringOutput `pulumi:"destinationType"`
	// Direction of the security rule. Set to `EGRESS` for rules to allow outbound IP packets, or `INGRESS` for rules to allow inbound IP packets.
	Direction pulumi.StringOutput `pulumi:"direction"`
	// Optional and valid only for ICMP and ICMPv6. Use to specify a particular ICMP type and code as defined in:
	// * [ICMP Parameters](http://www.iana.org/assignments/icmp-parameters/icmp-parameters.xhtml)
	// * [ICMPv6 Parameters](https://www.iana.org/assignments/icmpv6-parameters/icmpv6-parameters.xhtml)
	IcmpOptions NetworkSecurityGroupSecurityRuleIcmpOptionsPtrOutput `pulumi:"icmpOptions"`
	// Whether the rule is valid. The value is `True` when the rule is first created. If the rule's `source` or `destination` is a network security group, the value changes to `False` if that network security group is deleted.
	IsValid pulumi.BoolOutput `pulumi:"isValid"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the network security group.
	NetworkSecurityGroupId pulumi.StringOutput `pulumi:"networkSecurityGroupId"`
	// The transport protocol. Specify either `all` or an IPv4 protocol number as defined in [Protocol Numbers](http://www.iana.org/assignments/protocol-numbers/protocol-numbers.xhtml). Options are supported only for ICMP ("1"), TCP ("6"), UDP ("17"), and ICMPv6 ("58").
	Protocol pulumi.StringOutput `pulumi:"protocol"`
	// Conceptually, this is the range of IP addresses that a packet coming into the instance can come from.
	Source pulumi.StringPtrOutput `pulumi:"source"`
	// Type of source for the rule. Required if `direction` = `INGRESS`.
	// * `CIDR_BLOCK`: If the rule's `source` is an IP address range in CIDR notation.
	// * `SERVICE_CIDR_BLOCK`: If the rule's `source` is the `cidrBlock` value for a [Service](https://docs.cloud.oracle.com/iaas/api/#/en/iaas/latest/Service/) (the rule is for traffic coming from a particular `Service` through a service gateway).
	// * `NETWORK_SECURITY_GROUP`: If the rule's `source` is the [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of a [NetworkSecurityGroup](https://docs.cloud.oracle.com/iaas/api/#/en/iaas/latest/NetworkSecurityGroup/).
	SourceType pulumi.StringOutput `pulumi:"sourceType"`
	// A stateless rule allows traffic in one direction. Remember to add a corresponding stateless rule in the other direction if you need to support bidirectional traffic. For example, if egress traffic allows TCP destination port 80, there should be an ingress rule to allow TCP source port 80. Defaults to false, which means the rule is stateful and a corresponding rule is not necessary for bidirectional traffic.
	Stateless pulumi.BoolOutput `pulumi:"stateless"`
	// Optional and valid only for TCP. Use to specify particular destination ports for TCP rules. If you specify TCP as the protocol but omit this object, then all destination ports are allowed.
	TcpOptions NetworkSecurityGroupSecurityRuleTcpOptionsPtrOutput `pulumi:"tcpOptions"`
	// The date and time the security rule was created. Format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).
	TimeCreated pulumi.StringOutput `pulumi:"timeCreated"`
	// Optional and valid only for UDP. Use to specify particular destination ports for UDP rules. If you specify UDP as the protocol but omit this object, then all destination ports are allowed.
	UdpOptions NetworkSecurityGroupSecurityRuleUdpOptionsPtrOutput `pulumi:"udpOptions"`
}

// NewNetworkSecurityGroupSecurityRule registers a new resource with the given unique name, arguments, and options.
func NewNetworkSecurityGroupSecurityRule(ctx *pulumi.Context,
	name string, args *NetworkSecurityGroupSecurityRuleArgs, opts ...pulumi.ResourceOption) (*NetworkSecurityGroupSecurityRule, error) {
	if args == nil {
		return nil, errors.New("missing one or more required arguments")
	}

	if args.Direction == nil {
		return nil, errors.New("invalid value for required argument 'Direction'")
	}
	if args.NetworkSecurityGroupId == nil {
		return nil, errors.New("invalid value for required argument 'NetworkSecurityGroupId'")
	}
	if args.Protocol == nil {
		return nil, errors.New("invalid value for required argument 'Protocol'")
	}
	opts = internal.PkgResourceDefaultOpts(opts)
	var resource NetworkSecurityGroupSecurityRule
	err := ctx.RegisterResource("oci:Core/networkSecurityGroupSecurityRule:NetworkSecurityGroupSecurityRule", name, args, &resource, opts...)
	if err != nil {
		return nil, err
	}
	return &resource, nil
}

// GetNetworkSecurityGroupSecurityRule gets an existing NetworkSecurityGroupSecurityRule resource's state with the given name, ID, and optional
// state properties that are used to uniquely qualify the lookup (nil if not required).
func GetNetworkSecurityGroupSecurityRule(ctx *pulumi.Context,
	name string, id pulumi.IDInput, state *NetworkSecurityGroupSecurityRuleState, opts ...pulumi.ResourceOption) (*NetworkSecurityGroupSecurityRule, error) {
	var resource NetworkSecurityGroupSecurityRule
	err := ctx.ReadResource("oci:Core/networkSecurityGroupSecurityRule:NetworkSecurityGroupSecurityRule", name, id, state, &resource, opts...)
	if err != nil {
		return nil, err
	}
	return &resource, nil
}

// Input properties used for looking up and filtering NetworkSecurityGroupSecurityRule resources.
type networkSecurityGroupSecurityRuleState struct {
	// An optional description of your choice for the rule.
	Description *string `pulumi:"description"`
	// Conceptually, this is the range of IP addresses that a packet originating from the instance can go to.
	Destination *string `pulumi:"destination"`
	// Type of destination for the rule. Required if `direction` = `EGRESS`.
	DestinationType *string `pulumi:"destinationType"`
	// Direction of the security rule. Set to `EGRESS` for rules to allow outbound IP packets, or `INGRESS` for rules to allow inbound IP packets.
	Direction *string `pulumi:"direction"`
	// Optional and valid only for ICMP and ICMPv6. Use to specify a particular ICMP type and code as defined in:
	// * [ICMP Parameters](http://www.iana.org/assignments/icmp-parameters/icmp-parameters.xhtml)
	// * [ICMPv6 Parameters](https://www.iana.org/assignments/icmpv6-parameters/icmpv6-parameters.xhtml)
	IcmpOptions *NetworkSecurityGroupSecurityRuleIcmpOptions `pulumi:"icmpOptions"`
	// Whether the rule is valid. The value is `True` when the rule is first created. If the rule's `source` or `destination` is a network security group, the value changes to `False` if that network security group is deleted.
	IsValid *bool `pulumi:"isValid"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the network security group.
	NetworkSecurityGroupId *string `pulumi:"networkSecurityGroupId"`
	// The transport protocol. Specify either `all` or an IPv4 protocol number as defined in [Protocol Numbers](http://www.iana.org/assignments/protocol-numbers/protocol-numbers.xhtml). Options are supported only for ICMP ("1"), TCP ("6"), UDP ("17"), and ICMPv6 ("58").
	Protocol *string `pulumi:"protocol"`
	// Conceptually, this is the range of IP addresses that a packet coming into the instance can come from.
	Source *string `pulumi:"source"`
	// Type of source for the rule. Required if `direction` = `INGRESS`.
	// * `CIDR_BLOCK`: If the rule's `source` is an IP address range in CIDR notation.
	// * `SERVICE_CIDR_BLOCK`: If the rule's `source` is the `cidrBlock` value for a [Service](https://docs.cloud.oracle.com/iaas/api/#/en/iaas/latest/Service/) (the rule is for traffic coming from a particular `Service` through a service gateway).
	// * `NETWORK_SECURITY_GROUP`: If the rule's `source` is the [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of a [NetworkSecurityGroup](https://docs.cloud.oracle.com/iaas/api/#/en/iaas/latest/NetworkSecurityGroup/).
	SourceType *string `pulumi:"sourceType"`
	// A stateless rule allows traffic in one direction. Remember to add a corresponding stateless rule in the other direction if you need to support bidirectional traffic. For example, if egress traffic allows TCP destination port 80, there should be an ingress rule to allow TCP source port 80. Defaults to false, which means the rule is stateful and a corresponding rule is not necessary for bidirectional traffic.
	Stateless *bool `pulumi:"stateless"`
	// Optional and valid only for TCP. Use to specify particular destination ports for TCP rules. If you specify TCP as the protocol but omit this object, then all destination ports are allowed.
	TcpOptions *NetworkSecurityGroupSecurityRuleTcpOptions `pulumi:"tcpOptions"`
	// The date and time the security rule was created. Format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).
	TimeCreated *string `pulumi:"timeCreated"`
	// Optional and valid only for UDP. Use to specify particular destination ports for UDP rules. If you specify UDP as the protocol but omit this object, then all destination ports are allowed.
	UdpOptions *NetworkSecurityGroupSecurityRuleUdpOptions `pulumi:"udpOptions"`
}

type NetworkSecurityGroupSecurityRuleState struct {
	// An optional description of your choice for the rule.
	Description pulumi.StringPtrInput
	// Conceptually, this is the range of IP addresses that a packet originating from the instance can go to.
	Destination pulumi.StringPtrInput
	// Type of destination for the rule. Required if `direction` = `EGRESS`.
	DestinationType pulumi.StringPtrInput
	// Direction of the security rule. Set to `EGRESS` for rules to allow outbound IP packets, or `INGRESS` for rules to allow inbound IP packets.
	Direction pulumi.StringPtrInput
	// Optional and valid only for ICMP and ICMPv6. Use to specify a particular ICMP type and code as defined in:
	// * [ICMP Parameters](http://www.iana.org/assignments/icmp-parameters/icmp-parameters.xhtml)
	// * [ICMPv6 Parameters](https://www.iana.org/assignments/icmpv6-parameters/icmpv6-parameters.xhtml)
	IcmpOptions NetworkSecurityGroupSecurityRuleIcmpOptionsPtrInput
	// Whether the rule is valid. The value is `True` when the rule is first created. If the rule's `source` or `destination` is a network security group, the value changes to `False` if that network security group is deleted.
	IsValid pulumi.BoolPtrInput
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the network security group.
	NetworkSecurityGroupId pulumi.StringPtrInput
	// The transport protocol. Specify either `all` or an IPv4 protocol number as defined in [Protocol Numbers](http://www.iana.org/assignments/protocol-numbers/protocol-numbers.xhtml). Options are supported only for ICMP ("1"), TCP ("6"), UDP ("17"), and ICMPv6 ("58").
	Protocol pulumi.StringPtrInput
	// Conceptually, this is the range of IP addresses that a packet coming into the instance can come from.
	Source pulumi.StringPtrInput
	// Type of source for the rule. Required if `direction` = `INGRESS`.
	// * `CIDR_BLOCK`: If the rule's `source` is an IP address range in CIDR notation.
	// * `SERVICE_CIDR_BLOCK`: If the rule's `source` is the `cidrBlock` value for a [Service](https://docs.cloud.oracle.com/iaas/api/#/en/iaas/latest/Service/) (the rule is for traffic coming from a particular `Service` through a service gateway).
	// * `NETWORK_SECURITY_GROUP`: If the rule's `source` is the [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of a [NetworkSecurityGroup](https://docs.cloud.oracle.com/iaas/api/#/en/iaas/latest/NetworkSecurityGroup/).
	SourceType pulumi.StringPtrInput
	// A stateless rule allows traffic in one direction. Remember to add a corresponding stateless rule in the other direction if you need to support bidirectional traffic. For example, if egress traffic allows TCP destination port 80, there should be an ingress rule to allow TCP source port 80. Defaults to false, which means the rule is stateful and a corresponding rule is not necessary for bidirectional traffic.
	Stateless pulumi.BoolPtrInput
	// Optional and valid only for TCP. Use to specify particular destination ports for TCP rules. If you specify TCP as the protocol but omit this object, then all destination ports are allowed.
	TcpOptions NetworkSecurityGroupSecurityRuleTcpOptionsPtrInput
	// The date and time the security rule was created. Format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).
	TimeCreated pulumi.StringPtrInput
	// Optional and valid only for UDP. Use to specify particular destination ports for UDP rules. If you specify UDP as the protocol but omit this object, then all destination ports are allowed.
	UdpOptions NetworkSecurityGroupSecurityRuleUdpOptionsPtrInput
}

func (NetworkSecurityGroupSecurityRuleState) ElementType() reflect.Type {
	return reflect.TypeOf((*networkSecurityGroupSecurityRuleState)(nil)).Elem()
}

type networkSecurityGroupSecurityRuleArgs struct {
	// An optional description of your choice for the rule.
	Description *string `pulumi:"description"`
	// Conceptually, this is the range of IP addresses that a packet originating from the instance can go to.
	Destination *string `pulumi:"destination"`
	// Type of destination for the rule. Required if `direction` = `EGRESS`.
	DestinationType *string `pulumi:"destinationType"`
	// Direction of the security rule. Set to `EGRESS` for rules to allow outbound IP packets, or `INGRESS` for rules to allow inbound IP packets.
	Direction string `pulumi:"direction"`
	// Optional and valid only for ICMP and ICMPv6. Use to specify a particular ICMP type and code as defined in:
	// * [ICMP Parameters](http://www.iana.org/assignments/icmp-parameters/icmp-parameters.xhtml)
	// * [ICMPv6 Parameters](https://www.iana.org/assignments/icmpv6-parameters/icmpv6-parameters.xhtml)
	IcmpOptions *NetworkSecurityGroupSecurityRuleIcmpOptions `pulumi:"icmpOptions"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the network security group.
	NetworkSecurityGroupId string `pulumi:"networkSecurityGroupId"`
	// The transport protocol. Specify either `all` or an IPv4 protocol number as defined in [Protocol Numbers](http://www.iana.org/assignments/protocol-numbers/protocol-numbers.xhtml). Options are supported only for ICMP ("1"), TCP ("6"), UDP ("17"), and ICMPv6 ("58").
	Protocol string `pulumi:"protocol"`
	// Conceptually, this is the range of IP addresses that a packet coming into the instance can come from.
	Source *string `pulumi:"source"`
	// Type of source for the rule. Required if `direction` = `INGRESS`.
	// * `CIDR_BLOCK`: If the rule's `source` is an IP address range in CIDR notation.
	// * `SERVICE_CIDR_BLOCK`: If the rule's `source` is the `cidrBlock` value for a [Service](https://docs.cloud.oracle.com/iaas/api/#/en/iaas/latest/Service/) (the rule is for traffic coming from a particular `Service` through a service gateway).
	// * `NETWORK_SECURITY_GROUP`: If the rule's `source` is the [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of a [NetworkSecurityGroup](https://docs.cloud.oracle.com/iaas/api/#/en/iaas/latest/NetworkSecurityGroup/).
	SourceType *string `pulumi:"sourceType"`
	// A stateless rule allows traffic in one direction. Remember to add a corresponding stateless rule in the other direction if you need to support bidirectional traffic. For example, if egress traffic allows TCP destination port 80, there should be an ingress rule to allow TCP source port 80. Defaults to false, which means the rule is stateful and a corresponding rule is not necessary for bidirectional traffic.
	Stateless *bool `pulumi:"stateless"`
	// Optional and valid only for TCP. Use to specify particular destination ports for TCP rules. If you specify TCP as the protocol but omit this object, then all destination ports are allowed.
	TcpOptions *NetworkSecurityGroupSecurityRuleTcpOptions `pulumi:"tcpOptions"`
	// Optional and valid only for UDP. Use to specify particular destination ports for UDP rules. If you specify UDP as the protocol but omit this object, then all destination ports are allowed.
	UdpOptions *NetworkSecurityGroupSecurityRuleUdpOptions `pulumi:"udpOptions"`
}

// The set of arguments for constructing a NetworkSecurityGroupSecurityRule resource.
type NetworkSecurityGroupSecurityRuleArgs struct {
	// An optional description of your choice for the rule.
	Description pulumi.StringPtrInput
	// Conceptually, this is the range of IP addresses that a packet originating from the instance can go to.
	Destination pulumi.StringPtrInput
	// Type of destination for the rule. Required if `direction` = `EGRESS`.
	DestinationType pulumi.StringPtrInput
	// Direction of the security rule. Set to `EGRESS` for rules to allow outbound IP packets, or `INGRESS` for rules to allow inbound IP packets.
	Direction pulumi.StringInput
	// Optional and valid only for ICMP and ICMPv6. Use to specify a particular ICMP type and code as defined in:
	// * [ICMP Parameters](http://www.iana.org/assignments/icmp-parameters/icmp-parameters.xhtml)
	// * [ICMPv6 Parameters](https://www.iana.org/assignments/icmpv6-parameters/icmpv6-parameters.xhtml)
	IcmpOptions NetworkSecurityGroupSecurityRuleIcmpOptionsPtrInput
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the network security group.
	NetworkSecurityGroupId pulumi.StringInput
	// The transport protocol. Specify either `all` or an IPv4 protocol number as defined in [Protocol Numbers](http://www.iana.org/assignments/protocol-numbers/protocol-numbers.xhtml). Options are supported only for ICMP ("1"), TCP ("6"), UDP ("17"), and ICMPv6 ("58").
	Protocol pulumi.StringInput
	// Conceptually, this is the range of IP addresses that a packet coming into the instance can come from.
	Source pulumi.StringPtrInput
	// Type of source for the rule. Required if `direction` = `INGRESS`.
	// * `CIDR_BLOCK`: If the rule's `source` is an IP address range in CIDR notation.
	// * `SERVICE_CIDR_BLOCK`: If the rule's `source` is the `cidrBlock` value for a [Service](https://docs.cloud.oracle.com/iaas/api/#/en/iaas/latest/Service/) (the rule is for traffic coming from a particular `Service` through a service gateway).
	// * `NETWORK_SECURITY_GROUP`: If the rule's `source` is the [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of a [NetworkSecurityGroup](https://docs.cloud.oracle.com/iaas/api/#/en/iaas/latest/NetworkSecurityGroup/).
	SourceType pulumi.StringPtrInput
	// A stateless rule allows traffic in one direction. Remember to add a corresponding stateless rule in the other direction if you need to support bidirectional traffic. For example, if egress traffic allows TCP destination port 80, there should be an ingress rule to allow TCP source port 80. Defaults to false, which means the rule is stateful and a corresponding rule is not necessary for bidirectional traffic.
	Stateless pulumi.BoolPtrInput
	// Optional and valid only for TCP. Use to specify particular destination ports for TCP rules. If you specify TCP as the protocol but omit this object, then all destination ports are allowed.
	TcpOptions NetworkSecurityGroupSecurityRuleTcpOptionsPtrInput
	// Optional and valid only for UDP. Use to specify particular destination ports for UDP rules. If you specify UDP as the protocol but omit this object, then all destination ports are allowed.
	UdpOptions NetworkSecurityGroupSecurityRuleUdpOptionsPtrInput
}

func (NetworkSecurityGroupSecurityRuleArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*networkSecurityGroupSecurityRuleArgs)(nil)).Elem()
}

type NetworkSecurityGroupSecurityRuleInput interface {
	pulumi.Input

	ToNetworkSecurityGroupSecurityRuleOutput() NetworkSecurityGroupSecurityRuleOutput
	ToNetworkSecurityGroupSecurityRuleOutputWithContext(ctx context.Context) NetworkSecurityGroupSecurityRuleOutput
}

func (*NetworkSecurityGroupSecurityRule) ElementType() reflect.Type {
	return reflect.TypeOf((**NetworkSecurityGroupSecurityRule)(nil)).Elem()
}

func (i *NetworkSecurityGroupSecurityRule) ToNetworkSecurityGroupSecurityRuleOutput() NetworkSecurityGroupSecurityRuleOutput {
	return i.ToNetworkSecurityGroupSecurityRuleOutputWithContext(context.Background())
}

func (i *NetworkSecurityGroupSecurityRule) ToNetworkSecurityGroupSecurityRuleOutputWithContext(ctx context.Context) NetworkSecurityGroupSecurityRuleOutput {
	return pulumi.ToOutputWithContext(ctx, i).(NetworkSecurityGroupSecurityRuleOutput)
}

// NetworkSecurityGroupSecurityRuleArrayInput is an input type that accepts NetworkSecurityGroupSecurityRuleArray and NetworkSecurityGroupSecurityRuleArrayOutput values.
// You can construct a concrete instance of `NetworkSecurityGroupSecurityRuleArrayInput` via:
//
//	NetworkSecurityGroupSecurityRuleArray{ NetworkSecurityGroupSecurityRuleArgs{...} }
type NetworkSecurityGroupSecurityRuleArrayInput interface {
	pulumi.Input

	ToNetworkSecurityGroupSecurityRuleArrayOutput() NetworkSecurityGroupSecurityRuleArrayOutput
	ToNetworkSecurityGroupSecurityRuleArrayOutputWithContext(context.Context) NetworkSecurityGroupSecurityRuleArrayOutput
}

type NetworkSecurityGroupSecurityRuleArray []NetworkSecurityGroupSecurityRuleInput

func (NetworkSecurityGroupSecurityRuleArray) ElementType() reflect.Type {
	return reflect.TypeOf((*[]*NetworkSecurityGroupSecurityRule)(nil)).Elem()
}

func (i NetworkSecurityGroupSecurityRuleArray) ToNetworkSecurityGroupSecurityRuleArrayOutput() NetworkSecurityGroupSecurityRuleArrayOutput {
	return i.ToNetworkSecurityGroupSecurityRuleArrayOutputWithContext(context.Background())
}

func (i NetworkSecurityGroupSecurityRuleArray) ToNetworkSecurityGroupSecurityRuleArrayOutputWithContext(ctx context.Context) NetworkSecurityGroupSecurityRuleArrayOutput {
	return pulumi.ToOutputWithContext(ctx, i).(NetworkSecurityGroupSecurityRuleArrayOutput)
}

// NetworkSecurityGroupSecurityRuleMapInput is an input type that accepts NetworkSecurityGroupSecurityRuleMap and NetworkSecurityGroupSecurityRuleMapOutput values.
// You can construct a concrete instance of `NetworkSecurityGroupSecurityRuleMapInput` via:
//
//	NetworkSecurityGroupSecurityRuleMap{ "key": NetworkSecurityGroupSecurityRuleArgs{...} }
type NetworkSecurityGroupSecurityRuleMapInput interface {
	pulumi.Input

	ToNetworkSecurityGroupSecurityRuleMapOutput() NetworkSecurityGroupSecurityRuleMapOutput
	ToNetworkSecurityGroupSecurityRuleMapOutputWithContext(context.Context) NetworkSecurityGroupSecurityRuleMapOutput
}

type NetworkSecurityGroupSecurityRuleMap map[string]NetworkSecurityGroupSecurityRuleInput

func (NetworkSecurityGroupSecurityRuleMap) ElementType() reflect.Type {
	return reflect.TypeOf((*map[string]*NetworkSecurityGroupSecurityRule)(nil)).Elem()
}

func (i NetworkSecurityGroupSecurityRuleMap) ToNetworkSecurityGroupSecurityRuleMapOutput() NetworkSecurityGroupSecurityRuleMapOutput {
	return i.ToNetworkSecurityGroupSecurityRuleMapOutputWithContext(context.Background())
}

func (i NetworkSecurityGroupSecurityRuleMap) ToNetworkSecurityGroupSecurityRuleMapOutputWithContext(ctx context.Context) NetworkSecurityGroupSecurityRuleMapOutput {
	return pulumi.ToOutputWithContext(ctx, i).(NetworkSecurityGroupSecurityRuleMapOutput)
}

type NetworkSecurityGroupSecurityRuleOutput struct{ *pulumi.OutputState }

func (NetworkSecurityGroupSecurityRuleOutput) ElementType() reflect.Type {
	return reflect.TypeOf((**NetworkSecurityGroupSecurityRule)(nil)).Elem()
}

func (o NetworkSecurityGroupSecurityRuleOutput) ToNetworkSecurityGroupSecurityRuleOutput() NetworkSecurityGroupSecurityRuleOutput {
	return o
}

func (o NetworkSecurityGroupSecurityRuleOutput) ToNetworkSecurityGroupSecurityRuleOutputWithContext(ctx context.Context) NetworkSecurityGroupSecurityRuleOutput {
	return o
}

// An optional description of your choice for the rule.
func (o NetworkSecurityGroupSecurityRuleOutput) Description() pulumi.StringOutput {
	return o.ApplyT(func(v *NetworkSecurityGroupSecurityRule) pulumi.StringOutput { return v.Description }).(pulumi.StringOutput)
}

// Conceptually, this is the range of IP addresses that a packet originating from the instance can go to.
func (o NetworkSecurityGroupSecurityRuleOutput) Destination() pulumi.StringOutput {
	return o.ApplyT(func(v *NetworkSecurityGroupSecurityRule) pulumi.StringOutput { return v.Destination }).(pulumi.StringOutput)
}

// Type of destination for the rule. Required if `direction` = `EGRESS`.
func (o NetworkSecurityGroupSecurityRuleOutput) DestinationType() pulumi.StringOutput {
	return o.ApplyT(func(v *NetworkSecurityGroupSecurityRule) pulumi.StringOutput { return v.DestinationType }).(pulumi.StringOutput)
}

// Direction of the security rule. Set to `EGRESS` for rules to allow outbound IP packets, or `INGRESS` for rules to allow inbound IP packets.
func (o NetworkSecurityGroupSecurityRuleOutput) Direction() pulumi.StringOutput {
	return o.ApplyT(func(v *NetworkSecurityGroupSecurityRule) pulumi.StringOutput { return v.Direction }).(pulumi.StringOutput)
}

// Optional and valid only for ICMP and ICMPv6. Use to specify a particular ICMP type and code as defined in:
// * [ICMP Parameters](http://www.iana.org/assignments/icmp-parameters/icmp-parameters.xhtml)
// * [ICMPv6 Parameters](https://www.iana.org/assignments/icmpv6-parameters/icmpv6-parameters.xhtml)
func (o NetworkSecurityGroupSecurityRuleOutput) IcmpOptions() NetworkSecurityGroupSecurityRuleIcmpOptionsPtrOutput {
	return o.ApplyT(func(v *NetworkSecurityGroupSecurityRule) NetworkSecurityGroupSecurityRuleIcmpOptionsPtrOutput {
		return v.IcmpOptions
	}).(NetworkSecurityGroupSecurityRuleIcmpOptionsPtrOutput)
}

// Whether the rule is valid. The value is `True` when the rule is first created. If the rule's `source` or `destination` is a network security group, the value changes to `False` if that network security group is deleted.
func (o NetworkSecurityGroupSecurityRuleOutput) IsValid() pulumi.BoolOutput {
	return o.ApplyT(func(v *NetworkSecurityGroupSecurityRule) pulumi.BoolOutput { return v.IsValid }).(pulumi.BoolOutput)
}

// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the network security group.
func (o NetworkSecurityGroupSecurityRuleOutput) NetworkSecurityGroupId() pulumi.StringOutput {
	return o.ApplyT(func(v *NetworkSecurityGroupSecurityRule) pulumi.StringOutput { return v.NetworkSecurityGroupId }).(pulumi.StringOutput)
}

// The transport protocol. Specify either `all` or an IPv4 protocol number as defined in [Protocol Numbers](http://www.iana.org/assignments/protocol-numbers/protocol-numbers.xhtml). Options are supported only for ICMP ("1"), TCP ("6"), UDP ("17"), and ICMPv6 ("58").
func (o NetworkSecurityGroupSecurityRuleOutput) Protocol() pulumi.StringOutput {
	return o.ApplyT(func(v *NetworkSecurityGroupSecurityRule) pulumi.StringOutput { return v.Protocol }).(pulumi.StringOutput)
}

// Conceptually, this is the range of IP addresses that a packet coming into the instance can come from.
func (o NetworkSecurityGroupSecurityRuleOutput) Source() pulumi.StringPtrOutput {
	return o.ApplyT(func(v *NetworkSecurityGroupSecurityRule) pulumi.StringPtrOutput { return v.Source }).(pulumi.StringPtrOutput)
}

// Type of source for the rule. Required if `direction` = `INGRESS`.
// * `CIDR_BLOCK`: If the rule's `source` is an IP address range in CIDR notation.
// * `SERVICE_CIDR_BLOCK`: If the rule's `source` is the `cidrBlock` value for a [Service](https://docs.cloud.oracle.com/iaas/api/#/en/iaas/latest/Service/) (the rule is for traffic coming from a particular `Service` through a service gateway).
// * `NETWORK_SECURITY_GROUP`: If the rule's `source` is the [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of a [NetworkSecurityGroup](https://docs.cloud.oracle.com/iaas/api/#/en/iaas/latest/NetworkSecurityGroup/).
func (o NetworkSecurityGroupSecurityRuleOutput) SourceType() pulumi.StringOutput {
	return o.ApplyT(func(v *NetworkSecurityGroupSecurityRule) pulumi.StringOutput { return v.SourceType }).(pulumi.StringOutput)
}

// A stateless rule allows traffic in one direction. Remember to add a corresponding stateless rule in the other direction if you need to support bidirectional traffic. For example, if egress traffic allows TCP destination port 80, there should be an ingress rule to allow TCP source port 80. Defaults to false, which means the rule is stateful and a corresponding rule is not necessary for bidirectional traffic.
func (o NetworkSecurityGroupSecurityRuleOutput) Stateless() pulumi.BoolOutput {
	return o.ApplyT(func(v *NetworkSecurityGroupSecurityRule) pulumi.BoolOutput { return v.Stateless }).(pulumi.BoolOutput)
}

// Optional and valid only for TCP. Use to specify particular destination ports for TCP rules. If you specify TCP as the protocol but omit this object, then all destination ports are allowed.
func (o NetworkSecurityGroupSecurityRuleOutput) TcpOptions() NetworkSecurityGroupSecurityRuleTcpOptionsPtrOutput {
	return o.ApplyT(func(v *NetworkSecurityGroupSecurityRule) NetworkSecurityGroupSecurityRuleTcpOptionsPtrOutput {
		return v.TcpOptions
	}).(NetworkSecurityGroupSecurityRuleTcpOptionsPtrOutput)
}

// The date and time the security rule was created. Format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).
func (o NetworkSecurityGroupSecurityRuleOutput) TimeCreated() pulumi.StringOutput {
	return o.ApplyT(func(v *NetworkSecurityGroupSecurityRule) pulumi.StringOutput { return v.TimeCreated }).(pulumi.StringOutput)
}

// Optional and valid only for UDP. Use to specify particular destination ports for UDP rules. If you specify UDP as the protocol but omit this object, then all destination ports are allowed.
func (o NetworkSecurityGroupSecurityRuleOutput) UdpOptions() NetworkSecurityGroupSecurityRuleUdpOptionsPtrOutput {
	return o.ApplyT(func(v *NetworkSecurityGroupSecurityRule) NetworkSecurityGroupSecurityRuleUdpOptionsPtrOutput {
		return v.UdpOptions
	}).(NetworkSecurityGroupSecurityRuleUdpOptionsPtrOutput)
}

type NetworkSecurityGroupSecurityRuleArrayOutput struct{ *pulumi.OutputState }

func (NetworkSecurityGroupSecurityRuleArrayOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*[]*NetworkSecurityGroupSecurityRule)(nil)).Elem()
}

func (o NetworkSecurityGroupSecurityRuleArrayOutput) ToNetworkSecurityGroupSecurityRuleArrayOutput() NetworkSecurityGroupSecurityRuleArrayOutput {
	return o
}

func (o NetworkSecurityGroupSecurityRuleArrayOutput) ToNetworkSecurityGroupSecurityRuleArrayOutputWithContext(ctx context.Context) NetworkSecurityGroupSecurityRuleArrayOutput {
	return o
}

func (o NetworkSecurityGroupSecurityRuleArrayOutput) Index(i pulumi.IntInput) NetworkSecurityGroupSecurityRuleOutput {
	return pulumi.All(o, i).ApplyT(func(vs []interface{}) *NetworkSecurityGroupSecurityRule {
		return vs[0].([]*NetworkSecurityGroupSecurityRule)[vs[1].(int)]
	}).(NetworkSecurityGroupSecurityRuleOutput)
}

type NetworkSecurityGroupSecurityRuleMapOutput struct{ *pulumi.OutputState }

func (NetworkSecurityGroupSecurityRuleMapOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*map[string]*NetworkSecurityGroupSecurityRule)(nil)).Elem()
}

func (o NetworkSecurityGroupSecurityRuleMapOutput) ToNetworkSecurityGroupSecurityRuleMapOutput() NetworkSecurityGroupSecurityRuleMapOutput {
	return o
}

func (o NetworkSecurityGroupSecurityRuleMapOutput) ToNetworkSecurityGroupSecurityRuleMapOutputWithContext(ctx context.Context) NetworkSecurityGroupSecurityRuleMapOutput {
	return o
}

func (o NetworkSecurityGroupSecurityRuleMapOutput) MapIndex(k pulumi.StringInput) NetworkSecurityGroupSecurityRuleOutput {
	return pulumi.All(o, k).ApplyT(func(vs []interface{}) *NetworkSecurityGroupSecurityRule {
		return vs[0].(map[string]*NetworkSecurityGroupSecurityRule)[vs[1].(string)]
	}).(NetworkSecurityGroupSecurityRuleOutput)
}

func init() {
	pulumi.RegisterInputType(reflect.TypeOf((*NetworkSecurityGroupSecurityRuleInput)(nil)).Elem(), &NetworkSecurityGroupSecurityRule{})
	pulumi.RegisterInputType(reflect.TypeOf((*NetworkSecurityGroupSecurityRuleArrayInput)(nil)).Elem(), NetworkSecurityGroupSecurityRuleArray{})
	pulumi.RegisterInputType(reflect.TypeOf((*NetworkSecurityGroupSecurityRuleMapInput)(nil)).Elem(), NetworkSecurityGroupSecurityRuleMap{})
	pulumi.RegisterOutputType(NetworkSecurityGroupSecurityRuleOutput{})
	pulumi.RegisterOutputType(NetworkSecurityGroupSecurityRuleArrayOutput{})
	pulumi.RegisterOutputType(NetworkSecurityGroupSecurityRuleMapOutput{})
}
