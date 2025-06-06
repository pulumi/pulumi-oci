// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.NetworkFirewall.Outputs
{

    [OutputType]
    public sealed class GetNetworkFirewallPolicyApplicationsApplicationSummaryCollectionItemResult
    {
        /// <summary>
        /// The value of the ICMP6 message Code (subtype) field as defined by [RFC 4443](https://www.rfc-editor.org/rfc/rfc4443.html#section-2.1).
        /// </summary>
        public readonly int IcmpCode;
        /// <summary>
        /// The value of the ICMP6 message Type field as defined by [RFC 4443](https://www.rfc-editor.org/rfc/rfc4443.html#section-2.1).
        /// </summary>
        public readonly int IcmpType;
        /// <summary>
        /// Name of the application.
        /// </summary>
        public readonly string Name;
        /// <summary>
        /// Unique Network Firewall Policy identifier
        /// </summary>
        public readonly string NetworkFirewallPolicyId;
        /// <summary>
        /// OCID of the Network Firewall Policy this application belongs to.
        /// </summary>
        public readonly string ParentResourceId;
        /// <summary>
        /// Describes the type of Application.
        /// </summary>
        public readonly string Type;

        [OutputConstructor]
        private GetNetworkFirewallPolicyApplicationsApplicationSummaryCollectionItemResult(
            int icmpCode,

            int icmpType,

            string name,

            string networkFirewallPolicyId,

            string parentResourceId,

            string type)
        {
            IcmpCode = icmpCode;
            IcmpType = icmpType;
            Name = name;
            NetworkFirewallPolicyId = networkFirewallPolicyId;
            ParentResourceId = parentResourceId;
            Type = type;
        }
    }
}
