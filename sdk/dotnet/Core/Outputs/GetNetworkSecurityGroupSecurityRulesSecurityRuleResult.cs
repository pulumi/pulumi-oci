// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Core.Outputs
{

    [OutputType]
    public sealed class GetNetworkSecurityGroupSecurityRulesSecurityRuleResult
    {
        /// <summary>
        /// An optional description of your choice for the rule.
        /// </summary>
        public readonly string Description;
        /// <summary>
        /// Conceptually, this is the range of IP addresses that a packet originating from the instance can go to.
        /// </summary>
        public readonly string Destination;
        /// <summary>
        /// Type of destination for the rule. Required if `direction` = `EGRESS`.
        /// </summary>
        public readonly string DestinationType;
        /// <summary>
        /// Direction of the security rule. Set to `EGRESS` for rules that allow outbound IP packets, or `INGRESS` for rules that allow inbound IP packets.
        /// </summary>
        public readonly string Direction;
        /// <summary>
        /// Optional and valid only for ICMP and ICMPv6. Use to specify a particular ICMP type and code as defined in:
        /// * [ICMP Parameters](http://www.iana.org/assignments/icmp-parameters/icmp-parameters.xhtml)
        /// * [ICMPv6 Parameters](https://www.iana.org/assignments/icmpv6-parameters/icmpv6-parameters.xhtml)
        /// </summary>
        public readonly ImmutableArray<Outputs.GetNetworkSecurityGroupSecurityRulesSecurityRuleIcmpOptionResult> IcmpOptions;
        /// <summary>
        /// An Oracle-assigned identifier for the security rule. You specify this ID when you want to update or delete the rule.  Example: `04ABEC`
        /// </summary>
        public readonly string Id;
        /// <summary>
        /// Whether the rule is valid. The value is `True` when the rule is first created. If the rule's `source` or `destination` is a network security group, the value changes to `False` if that network security group is deleted.
        /// </summary>
        public readonly bool IsValid;
        /// <summary>
        /// The transport protocol. Specify either `all` or an IPv4 protocol number as defined in [Protocol Numbers](http://www.iana.org/assignments/protocol-numbers/protocol-numbers.xhtml). Options are supported only for ICMP ("1"), TCP ("6"), UDP ("17"), and ICMPv6 ("58").
        /// </summary>
        public readonly string Protocol;
        /// <summary>
        /// Conceptually, this is the range of IP addresses that a packet coming into the instance can come from.
        /// </summary>
        public readonly string Source;
        /// <summary>
        /// Type of source for the rule. Required if `direction` = `INGRESS`.
        /// * `CIDR_BLOCK`: If the rule's `source` is an IP address range in CIDR notation.
        /// * `SERVICE_CIDR_BLOCK`: If the rule's `source` is the `cidrBlock` value for a [Service](https://docs.cloud.oracle.com/iaas/api/#/en/iaas/latest/Service/) (the rule is for traffic coming from a particular `Service` through a service gateway).
        /// * `NETWORK_SECURITY_GROUP`: If the rule's `source` is the [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of a [NetworkSecurityGroup](https://docs.cloud.oracle.com/iaas/api/#/en/iaas/latest/NetworkSecurityGroup/).
        /// </summary>
        public readonly string SourceType;
        /// <summary>
        /// A stateless rule allows traffic in one direction. Remember to add a corresponding stateless rule in the other direction if you need to support bidirectional traffic. For example, if egress traffic allows TCP destination port 80, there should be an ingress rule to allow TCP source port 80. Defaults to false, which means the rule is stateful and a corresponding rule is not necessary for bidirectional traffic.
        /// </summary>
        public readonly bool Stateless;
        /// <summary>
        /// Optional and valid only for TCP. Use to specify particular destination ports for TCP rules. If you specify TCP as the protocol but omit this object, then all destination ports are allowed.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetNetworkSecurityGroupSecurityRulesSecurityRuleTcpOptionResult> TcpOptions;
        /// <summary>
        /// The date and time the security rule was created. Format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).
        /// </summary>
        public readonly string TimeCreated;
        /// <summary>
        /// Optional and valid only for UDP. Use to specify particular destination ports for UDP rules. If you specify UDP as the protocol but omit this object, then all destination ports are allowed.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetNetworkSecurityGroupSecurityRulesSecurityRuleUdpOptionResult> UdpOptions;

        [OutputConstructor]
        private GetNetworkSecurityGroupSecurityRulesSecurityRuleResult(
            string description,

            string destination,

            string destinationType,

            string direction,

            ImmutableArray<Outputs.GetNetworkSecurityGroupSecurityRulesSecurityRuleIcmpOptionResult> icmpOptions,

            string id,

            bool isValid,

            string protocol,

            string source,

            string sourceType,

            bool stateless,

            ImmutableArray<Outputs.GetNetworkSecurityGroupSecurityRulesSecurityRuleTcpOptionResult> tcpOptions,

            string timeCreated,

            ImmutableArray<Outputs.GetNetworkSecurityGroupSecurityRulesSecurityRuleUdpOptionResult> udpOptions)
        {
            Description = description;
            Destination = destination;
            DestinationType = destinationType;
            Direction = direction;
            IcmpOptions = icmpOptions;
            Id = id;
            IsValid = isValid;
            Protocol = protocol;
            Source = source;
            SourceType = sourceType;
            Stateless = stateless;
            TcpOptions = tcpOptions;
            TimeCreated = timeCreated;
            UdpOptions = udpOptions;
        }
    }
}
