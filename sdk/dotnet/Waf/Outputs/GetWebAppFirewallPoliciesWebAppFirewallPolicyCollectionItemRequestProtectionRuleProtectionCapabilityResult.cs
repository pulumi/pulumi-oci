// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Waf.Outputs
{

    [OutputType]
    public sealed class GetWebAppFirewallPoliciesWebAppFirewallPolicyCollectionItemRequestProtectionRuleProtectionCapabilityResult
    {
        /// <summary>
        /// Override action to take if capability was triggered, defined in Protection Rule for this capability. Only actions of type CHECK are allowed.
        /// </summary>
        public readonly string ActionName;
        /// <summary>
        /// The minimum sum of weights of associated collaborative protection capabilities that have triggered which must be reached in order for _this_ capability to trigger. This field is ignored for non-collaborative capabilities.
        /// </summary>
        public readonly int CollaborativeActionThreshold;
        /// <summary>
        /// Explicit weight values to use for associated collaborative protection capabilities.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetWebAppFirewallPoliciesWebAppFirewallPolicyCollectionItemRequestProtectionRuleProtectionCapabilityCollaborativeWeightResult> CollaborativeWeights;
        /// <summary>
        /// Identifies specific HTTP message parameters to exclude from inspection by a protection capability.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetWebAppFirewallPoliciesWebAppFirewallPolicyCollectionItemRequestProtectionRuleProtectionCapabilityExclusionResult> Exclusions;
        /// <summary>
        /// Unique key of referenced protection capability.
        /// </summary>
        public readonly string Key;
        /// <summary>
        /// Version of referenced protection capability.
        /// </summary>
        public readonly int Version;

        [OutputConstructor]
        private GetWebAppFirewallPoliciesWebAppFirewallPolicyCollectionItemRequestProtectionRuleProtectionCapabilityResult(
            string actionName,

            int collaborativeActionThreshold,

            ImmutableArray<Outputs.GetWebAppFirewallPoliciesWebAppFirewallPolicyCollectionItemRequestProtectionRuleProtectionCapabilityCollaborativeWeightResult> collaborativeWeights,

            ImmutableArray<Outputs.GetWebAppFirewallPoliciesWebAppFirewallPolicyCollectionItemRequestProtectionRuleProtectionCapabilityExclusionResult> exclusions,

            string key,

            int version)
        {
            ActionName = actionName;
            CollaborativeActionThreshold = collaborativeActionThreshold;
            CollaborativeWeights = collaborativeWeights;
            Exclusions = exclusions;
            Key = key;
            Version = version;
        }
    }
}