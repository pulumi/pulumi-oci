// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.NetworkFirewall.Outputs
{

    [OutputType]
    public sealed class GetNetworkFirewallPoliciesNetworkFirewallPolicySummaryCollectionItemResult
    {
        /// <summary>
        /// Map defining application lists of the policy. The value of an entry is a list of "applications", each consisting of a protocol identifier (such as TCP, UDP, or ICMP) and protocol-specific parameters (such as a port range). The associated key is the identifier by which the application list is referenced.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetNetworkFirewallPoliciesNetworkFirewallPolicySummaryCollectionItemApplicationListResult> ApplicationLists;
        /// <summary>
        /// The ID of the compartment in which to list resources.
        /// </summary>
        public readonly string CompartmentId;
        /// <summary>
        /// Map defining decryption profiles of the policy. The value of an entry is a decryption profile. The associated key is the identifier by which the decryption profile is referenced.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetNetworkFirewallPoliciesNetworkFirewallPolicySummaryCollectionItemDecryptionProfileResult> DecryptionProfiles;
        /// <summary>
        /// List of Decryption Rules defining the behavior of the policy. The first rule with a matching condition determines the action taken upon network traffic.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetNetworkFirewallPoliciesNetworkFirewallPolicySummaryCollectionItemDecryptionRuleResult> DecryptionRules;
        /// <summary>
        /// Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
        /// </summary>
        public readonly ImmutableDictionary<string, object> DefinedTags;
        /// <summary>
        /// A filter to return only resources that match the entire display name given.
        /// </summary>
        public readonly string DisplayName;
        /// <summary>
        /// Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
        /// </summary>
        public readonly ImmutableDictionary<string, object> FreeformTags;
        /// <summary>
        /// Unique Network Firewall Policy identifier
        /// </summary>
        public readonly string Id;
        /// <summary>
        /// Map defining IP address lists of the policy. The value of an entry is a list of IP addresses or prefixes in CIDR notation. The associated key is the identifier by which the IP address list is referenced.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetNetworkFirewallPoliciesNetworkFirewallPolicySummaryCollectionItemIpAddressListResult> IpAddressLists;
        /// <summary>
        /// To determine if any Network Firewall is associated with this Network Firewall Policy.
        /// </summary>
        public readonly bool IsFirewallAttached;
        /// <summary>
        /// A message describing the current state in more detail. For example, can be used to provide actionable information for a resource in Failed state.
        /// </summary>
        public readonly string LifecycleDetails;
        /// <summary>
        /// Map defining secrets of the policy. The value of an entry is a "mapped secret" consisting of a purpose and source. The associated key is the identifier by which the mapped secret is referenced.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetNetworkFirewallPoliciesNetworkFirewallPolicySummaryCollectionItemMappedSecretResult> MappedSecrets;
        /// <summary>
        /// List of Security Rules defining the behavior of the policy. The first rule with a matching condition determines the action taken upon network traffic.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetNetworkFirewallPoliciesNetworkFirewallPolicySummaryCollectionItemSecurityRuleResult> SecurityRules;
        /// <summary>
        /// A filter to return only resources with a lifecycleState matching the given value.
        /// </summary>
        public readonly string State;
        /// <summary>
        /// Usage of system tag keys. These predefined keys are scoped to namespaces. Example: `{"orcl-cloud.free-tier-retained": "true"}`
        /// </summary>
        public readonly ImmutableDictionary<string, object> SystemTags;
        /// <summary>
        /// The time instant at which the Network Firewall Policy was created in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339). Example: `2016-08-25T21:10:29.600Z`
        /// </summary>
        public readonly string TimeCreated;
        /// <summary>
        /// The time instant at which the Network Firewall Policy was updated in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339). Example: `2016-08-25T21:10:29.600Z`
        /// </summary>
        public readonly string TimeUpdated;
        /// <summary>
        /// Map defining URL pattern lists of the policy. The value of an entry is a list of URL patterns. The associated key is the identifier by which the URL pattern list is referenced.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetNetworkFirewallPoliciesNetworkFirewallPolicySummaryCollectionItemUrlListResult> UrlLists;

        [OutputConstructor]
        private GetNetworkFirewallPoliciesNetworkFirewallPolicySummaryCollectionItemResult(
            ImmutableArray<Outputs.GetNetworkFirewallPoliciesNetworkFirewallPolicySummaryCollectionItemApplicationListResult> applicationLists,

            string compartmentId,

            ImmutableArray<Outputs.GetNetworkFirewallPoliciesNetworkFirewallPolicySummaryCollectionItemDecryptionProfileResult> decryptionProfiles,

            ImmutableArray<Outputs.GetNetworkFirewallPoliciesNetworkFirewallPolicySummaryCollectionItemDecryptionRuleResult> decryptionRules,

            ImmutableDictionary<string, object> definedTags,

            string displayName,

            ImmutableDictionary<string, object> freeformTags,

            string id,

            ImmutableArray<Outputs.GetNetworkFirewallPoliciesNetworkFirewallPolicySummaryCollectionItemIpAddressListResult> ipAddressLists,

            bool isFirewallAttached,

            string lifecycleDetails,

            ImmutableArray<Outputs.GetNetworkFirewallPoliciesNetworkFirewallPolicySummaryCollectionItemMappedSecretResult> mappedSecrets,

            ImmutableArray<Outputs.GetNetworkFirewallPoliciesNetworkFirewallPolicySummaryCollectionItemSecurityRuleResult> securityRules,

            string state,

            ImmutableDictionary<string, object> systemTags,

            string timeCreated,

            string timeUpdated,

            ImmutableArray<Outputs.GetNetworkFirewallPoliciesNetworkFirewallPolicySummaryCollectionItemUrlListResult> urlLists)
        {
            ApplicationLists = applicationLists;
            CompartmentId = compartmentId;
            DecryptionProfiles = decryptionProfiles;
            DecryptionRules = decryptionRules;
            DefinedTags = definedTags;
            DisplayName = displayName;
            FreeformTags = freeformTags;
            Id = id;
            IpAddressLists = ipAddressLists;
            IsFirewallAttached = isFirewallAttached;
            LifecycleDetails = lifecycleDetails;
            MappedSecrets = mappedSecrets;
            SecurityRules = securityRules;
            State = state;
            SystemTags = systemTags;
            TimeCreated = timeCreated;
            TimeUpdated = timeUpdated;
            UrlLists = urlLists;
        }
    }
}