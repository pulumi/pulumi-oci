// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.DataSafe.Outputs
{

    [OutputType]
    public sealed class GetSecurityPoliciesSecurityPolicyCollectionItemResult
    {
        /// <summary>
        /// A filter to return only resources that match the specified compartment OCID.
        /// </summary>
        public readonly string CompartmentId;
        /// <summary>
        /// Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm) Example: `{"Operations.CostCenter": "42"}`
        /// </summary>
        public readonly ImmutableDictionary<string, string> DefinedTags;
        /// <summary>
        /// The description of the security policy.
        /// </summary>
        public readonly string Description;
        /// <summary>
        /// A filter to return only resources that match the specified display name.
        /// </summary>
        public readonly string DisplayName;
        /// <summary>
        /// Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm)  Example: `{"Department": "Finance"}`
        /// </summary>
        public readonly ImmutableDictionary<string, string> FreeformTags;
        /// <summary>
        /// The OCID of the security policy.
        /// </summary>
        public readonly string Id;
        /// <summary>
        /// Details about the current state of the security policy in Data Safe.
        /// </summary>
        public readonly string LifecycleDetails;
        /// <summary>
        /// An optional filter to return only resources that match the specified OCID of the security policy resource.
        /// </summary>
        public readonly string SecurityPolicyId;
        /// <summary>
        /// The current state of the security policy.
        /// </summary>
        public readonly string State;
        /// <summary>
        /// System tags for this resource. Each key is predefined and scoped to a namespace. For more information, see Resource Tags. Example: `{"orcl-cloud.free-tier-retained": "true"}`
        /// </summary>
        public readonly ImmutableDictionary<string, string> SystemTags;
        /// <summary>
        /// The time that the security policy was created, in the format defined by RFC3339.
        /// </summary>
        public readonly string TimeCreated;
        /// <summary>
        /// The last date and time the security policy was updated, in the format defined by RFC3339.
        /// </summary>
        public readonly string TimeUpdated;

        [OutputConstructor]
        private GetSecurityPoliciesSecurityPolicyCollectionItemResult(
            string compartmentId,

            ImmutableDictionary<string, string> definedTags,

            string description,

            string displayName,

            ImmutableDictionary<string, string> freeformTags,

            string id,

            string lifecycleDetails,

            string securityPolicyId,

            string state,

            ImmutableDictionary<string, string> systemTags,

            string timeCreated,

            string timeUpdated)
        {
            CompartmentId = compartmentId;
            DefinedTags = definedTags;
            Description = description;
            DisplayName = displayName;
            FreeformTags = freeformTags;
            Id = id;
            LifecycleDetails = lifecycleDetails;
            SecurityPolicyId = securityPolicyId;
            State = state;
            SystemTags = systemTags;
            TimeCreated = timeCreated;
            TimeUpdated = timeUpdated;
        }
    }
}
