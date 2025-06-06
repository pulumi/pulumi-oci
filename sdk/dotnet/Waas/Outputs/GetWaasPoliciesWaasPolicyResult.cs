// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Waas.Outputs
{

    [OutputType]
    public sealed class GetWaasPoliciesWaasPolicyResult
    {
        /// <summary>
        /// An array of additional domains for this web application.
        /// </summary>
        public readonly ImmutableArray<string> AdditionalDomains;
        /// <summary>
        /// The CNAME record to add to your DNS configuration to route traffic for the domain, and all additional domains, through the WAF.
        /// </summary>
        public readonly string Cname;
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment. This number is generated when the compartment is created.
        /// </summary>
        public readonly string CompartmentId;
        /// <summary>
        /// Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Operations.CostCenter": "42"}`
        /// </summary>
        public readonly ImmutableDictionary<string, string> DefinedTags;
        /// <summary>
        /// The user-friendly name of the WAAS policy. The name can be changed and does not need to be unique.
        /// </summary>
        public readonly string DisplayName;
        /// <summary>
        /// The domain for which the cookie is set, defaults to WAAS policy domain.
        /// </summary>
        public readonly string Domain;
        /// <summary>
        /// Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
        /// </summary>
        public readonly ImmutableDictionary<string, string> FreeformTags;
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the custom protection rule.
        /// </summary>
        public readonly string Id;
        /// <summary>
        /// The map of origin groups and their keys used to associate origins to the `wafConfig`. Origin groups allow you to apply weights to groups of origins for load balancing purposes. Origins with higher weights will receive larger proportions of client requests. To add additional origins to your WAAS policy, update the `origins` field of a `UpdateWaasPolicy` request.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetWaasPoliciesWaasPolicyOriginGroupResult> OriginGroups;
        /// <summary>
        /// A map of host servers (origins) and their keys for the web application. Origin keys are used to associate origins to specific protection rules. The key should be a user-friendly name for the host. **Examples:** `primary` or `secondary`.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetWaasPoliciesWaasPolicyOriginResult> Origins;
        /// <summary>
        /// The configuration details for the WAAS policy.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetWaasPoliciesWaasPolicyPolicyConfigResult> PolicyConfigs;
        /// <summary>
        /// The current lifecycle state of the WAAS policy.
        /// </summary>
        public readonly string State;
        /// <summary>
        /// The date and time the policy was created, expressed in RFC 3339 timestamp format.
        /// </summary>
        public readonly string TimeCreated;
        /// <summary>
        /// The Web Application Firewall configuration for the WAAS policy.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetWaasPoliciesWaasPolicyWafConfigResult> WafConfigs;

        [OutputConstructor]
        private GetWaasPoliciesWaasPolicyResult(
            ImmutableArray<string> additionalDomains,

            string cname,

            string compartmentId,

            ImmutableDictionary<string, string> definedTags,

            string displayName,

            string domain,

            ImmutableDictionary<string, string> freeformTags,

            string id,

            ImmutableArray<Outputs.GetWaasPoliciesWaasPolicyOriginGroupResult> originGroups,

            ImmutableArray<Outputs.GetWaasPoliciesWaasPolicyOriginResult> origins,

            ImmutableArray<Outputs.GetWaasPoliciesWaasPolicyPolicyConfigResult> policyConfigs,

            string state,

            string timeCreated,

            ImmutableArray<Outputs.GetWaasPoliciesWaasPolicyWafConfigResult> wafConfigs)
        {
            AdditionalDomains = additionalDomains;
            Cname = cname;
            CompartmentId = compartmentId;
            DefinedTags = definedTags;
            DisplayName = displayName;
            Domain = domain;
            FreeformTags = freeformTags;
            Id = id;
            OriginGroups = originGroups;
            Origins = origins;
            PolicyConfigs = policyConfigs;
            State = state;
            TimeCreated = timeCreated;
            WafConfigs = wafConfigs;
        }
    }
}
