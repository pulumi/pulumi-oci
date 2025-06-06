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
    public sealed class GetInstanceCreateVnicDetailResult
    {
        public readonly bool AssignIpv6ip;
        public readonly bool AssignPrivateDnsRecord;
        public readonly string AssignPublicIp;
        /// <summary>
        /// Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Operations.CostCenter": "42"}`
        /// </summary>
        public readonly ImmutableDictionary<string, string> DefinedTags;
        /// <summary>
        /// A user-friendly name. Does not have to be unique, and it's changeable. Avoid entering confidential information.
        /// </summary>
        public readonly string DisplayName;
        /// <summary>
        /// Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
        /// </summary>
        public readonly ImmutableDictionary<string, string> FreeformTags;
        /// <summary>
        /// The hostname for the instance VNIC's primary private IP.
        /// </summary>
        public readonly string HostnameLabel;
        public readonly ImmutableArray<Outputs.GetInstanceCreateVnicDetailIpv6addressIpv6subnetCidrPairDetailResult> Ipv6addressIpv6subnetCidrPairDetails;
        public readonly ImmutableArray<string> NsgIds;
        /// <summary>
        /// The private IP address of instance VNIC. To set the private IP address, use the `private_ip` argument in create_vnic_details.
        /// </summary>
        public readonly string PrivateIp;
        /// <summary>
        /// Security Attributes for this resource. This is unique to ZPR, and helps identify which resources are allowed to be accessed by what permission controls.  Example: `{"Oracle-DataSecurity-ZPR.MaxEgressCount.value": "42", "Oracle-DataSecurity-ZPR.MaxEgressCount.mode": "audit"}`
        /// </summary>
        public readonly ImmutableDictionary<string, string> SecurityAttributes;
        public readonly bool SkipSourceDestCheck;
        public readonly string SubnetId;
        public readonly string VlanId;

        [OutputConstructor]
        private GetInstanceCreateVnicDetailResult(
            bool assignIpv6ip,

            bool assignPrivateDnsRecord,

            string assignPublicIp,

            ImmutableDictionary<string, string> definedTags,

            string displayName,

            ImmutableDictionary<string, string> freeformTags,

            string hostnameLabel,

            ImmutableArray<Outputs.GetInstanceCreateVnicDetailIpv6addressIpv6subnetCidrPairDetailResult> ipv6addressIpv6subnetCidrPairDetails,

            ImmutableArray<string> nsgIds,

            string privateIp,

            ImmutableDictionary<string, string> securityAttributes,

            bool skipSourceDestCheck,

            string subnetId,

            string vlanId)
        {
            AssignIpv6ip = assignIpv6ip;
            AssignPrivateDnsRecord = assignPrivateDnsRecord;
            AssignPublicIp = assignPublicIp;
            DefinedTags = definedTags;
            DisplayName = displayName;
            FreeformTags = freeformTags;
            HostnameLabel = hostnameLabel;
            Ipv6addressIpv6subnetCidrPairDetails = ipv6addressIpv6subnetCidrPairDetails;
            NsgIds = nsgIds;
            PrivateIp = privateIp;
            SecurityAttributes = securityAttributes;
            SkipSourceDestCheck = skipSourceDestCheck;
            SubnetId = subnetId;
            VlanId = vlanId;
        }
    }
}
