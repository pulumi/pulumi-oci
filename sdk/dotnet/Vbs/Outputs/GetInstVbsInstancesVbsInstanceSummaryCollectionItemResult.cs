// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Vbs.Outputs
{

    [OutputType]
    public sealed class GetInstVbsInstancesVbsInstanceSummaryCollectionItemResult
    {
        /// <summary>
        /// The ID of the compartment in which to list resources.
        /// </summary>
        public readonly string CompartmentId;
        /// <summary>
        /// Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
        /// </summary>
        public readonly ImmutableDictionary<string, string> DefinedTags;
        /// <summary>
        /// Service instance display name
        /// </summary>
        public readonly string DisplayName;
        /// <summary>
        /// Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
        /// </summary>
        public readonly ImmutableDictionary<string, string> FreeformTags;
        /// <summary>
        /// unique VbsInstance identifier
        /// </summary>
        public readonly string Id;
        public readonly string IdcsAccessToken;
        /// <summary>
        /// Whether the VBS service instance owner explicitly approved VBS to create and use resources in the customer tenancy
        /// </summary>
        public readonly bool IsResourceUsageAgreementGranted;
        /// <summary>
        /// A message describing the current state in more detail. For example, can be used to provide actionable information for a resource in Failed state.
        /// </summary>
        public readonly string LifecyleDetails;
        /// <summary>
        /// A filter to return only resources that match the entire name given.
        /// </summary>
        public readonly string Name;
        /// <summary>
        /// Compartment where VBS may create additional resources for the service instance
        /// </summary>
        public readonly string ResourceCompartmentId;
        /// <summary>
        /// A filter to return only resources their lifecycleState matches the given lifecycleState.
        /// </summary>
        public readonly string State;
        /// <summary>
        /// Usage of system tag keys. These predefined keys are scoped to namespaces. Example: `{"orcl-cloud.free-tier-retained": "true"}`
        /// </summary>
        public readonly ImmutableDictionary<string, string> SystemTags;
        /// <summary>
        /// The time the the VbsInstance was created. An RFC3339 formatted datetime string
        /// </summary>
        public readonly string TimeCreated;
        /// <summary>
        /// The time the VbsInstance was updated. An RFC3339 formatted datetime string
        /// </summary>
        public readonly string TimeUpdated;
        /// <summary>
        /// Public web URL for accessing the VBS service instance
        /// </summary>
        public readonly string VbsAccessUrl;

        [OutputConstructor]
        private GetInstVbsInstancesVbsInstanceSummaryCollectionItemResult(
            string compartmentId,

            ImmutableDictionary<string, string> definedTags,

            string displayName,

            ImmutableDictionary<string, string> freeformTags,

            string id,

            string idcsAccessToken,

            bool isResourceUsageAgreementGranted,

            string lifecyleDetails,

            string name,

            string resourceCompartmentId,

            string state,

            ImmutableDictionary<string, string> systemTags,

            string timeCreated,

            string timeUpdated,

            string vbsAccessUrl)
        {
            CompartmentId = compartmentId;
            DefinedTags = definedTags;
            DisplayName = displayName;
            FreeformTags = freeformTags;
            Id = id;
            IdcsAccessToken = idcsAccessToken;
            IsResourceUsageAgreementGranted = isResourceUsageAgreementGranted;
            LifecyleDetails = lifecyleDetails;
            Name = name;
            ResourceCompartmentId = resourceCompartmentId;
            State = state;
            SystemTags = systemTags;
            TimeCreated = timeCreated;
            TimeUpdated = timeUpdated;
            VbsAccessUrl = vbsAccessUrl;
        }
    }
}
