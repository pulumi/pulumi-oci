// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Oci.Outputs
{

    [OutputType]
    public sealed class GetWlmsWlsDomainsWlsDomainCollectionItemResult
    {
        /// <summary>
        /// The OCID of the compartment that contains the resources to list. This filter returns  only resources contained within the specified compartment.
        /// </summary>
        public readonly string CompartmentId;
        /// <summary>
        /// The WebLogic domain configuration.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetWlmsWlsDomainsWlsDomainCollectionItemConfigurationResult> Configurations;
        /// <summary>
        /// Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Operations.CostCenter": "42"}`
        /// </summary>
        public readonly ImmutableDictionary<string, string> DefinedTags;
        /// <summary>
        /// The display name.
        /// </summary>
        public readonly string DisplayName;
        /// <summary>
        /// Free-form tags for this resource. Each tag is a key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
        /// </summary>
        public readonly ImmutableDictionary<string, string> FreeformTags;
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the WebLogic domain.
        /// </summary>
        public readonly string Id;
        /// <summary>
        /// Whether or not the terms of use agreement has been accepted for the WebLogic domain.
        /// </summary>
        public readonly bool IsAcceptedTermsAndConditions;
        /// <summary>
        /// A message that describes the current state of the WebLogic domain in more detail. For example, it can be used to provide actionable information for a resource in the Failed state.
        /// </summary>
        public readonly string LifecycleDetails;
        /// <summary>
        /// A filter to return WebLogic domains based on the type of middleware of the WebLogic domain.
        /// </summary>
        public readonly string MiddlewareType;
        /// <summary>
        /// A filter to return domains based on the patch readiness status.
        /// </summary>
        public readonly string PatchReadinessStatus;
        /// <summary>
        /// A filter to return only resources that match the given lifecycle state. The state value is case-insensitive.
        /// </summary>
        public readonly string State;
        /// <summary>
        /// System tags for this resource. Each key is predefined and scoped to a namespace.  Example: `{"orcl-cloud.free-tier-retained": "true"}`
        /// </summary>
        public readonly ImmutableDictionary<string, string> SystemTags;
        /// <summary>
        /// The date and time the WebLogic domain was created (in [RFC 3339](https://tools.ietf.org/rfc/rfc3339) format).  Example: `2016-08-25T21:10:29.600Z`
        /// </summary>
        public readonly string TimeCreated;
        /// <summary>
        /// The date and time the WebLogic domain was updated (in [RFC 3339](https://tools.ietf.org/rfc/rfc3339) format).  Example: `2016-08-25T21:10:29.600Z`
        /// </summary>
        public readonly string TimeUpdated;
        /// <summary>
        /// A filter to return WebLogic domains based on the WebLogic version.
        /// </summary>
        public readonly string WeblogicVersion;

        [OutputConstructor]
        private GetWlmsWlsDomainsWlsDomainCollectionItemResult(
            string compartmentId,

            ImmutableArray<Outputs.GetWlmsWlsDomainsWlsDomainCollectionItemConfigurationResult> configurations,

            ImmutableDictionary<string, string> definedTags,

            string displayName,

            ImmutableDictionary<string, string> freeformTags,

            string id,

            bool isAcceptedTermsAndConditions,

            string lifecycleDetails,

            string middlewareType,

            string patchReadinessStatus,

            string state,

            ImmutableDictionary<string, string> systemTags,

            string timeCreated,

            string timeUpdated,

            string weblogicVersion)
        {
            CompartmentId = compartmentId;
            Configurations = configurations;
            DefinedTags = definedTags;
            DisplayName = displayName;
            FreeformTags = freeformTags;
            Id = id;
            IsAcceptedTermsAndConditions = isAcceptedTermsAndConditions;
            LifecycleDetails = lifecycleDetails;
            MiddlewareType = middlewareType;
            PatchReadinessStatus = patchReadinessStatus;
            State = state;
            SystemTags = systemTags;
            TimeCreated = timeCreated;
            TimeUpdated = timeUpdated;
            WeblogicVersion = weblogicVersion;
        }
    }
}
