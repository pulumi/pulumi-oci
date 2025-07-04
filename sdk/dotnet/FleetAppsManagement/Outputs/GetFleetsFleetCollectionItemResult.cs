// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.FleetAppsManagement.Outputs
{

    [OutputType]
    public sealed class GetFleetsFleetCollectionItemResult
    {
        /// <summary>
        /// The ID of the compartment in which to list resources. Empty only if the resource OCID query param is not specified.
        /// </summary>
        public readonly string CompartmentId;
        /// <summary>
        /// Credentials associated with the Fleet.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetFleetsFleetCollectionItemCredentialResult> Credentials;
        /// <summary>
        /// Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
        /// </summary>
        public readonly ImmutableDictionary<string, string> DefinedTags;
        /// <summary>
        /// A user-friendly description. To provide some insight about the resource. Avoid entering confidential information.
        /// </summary>
        public readonly string Description;
        /// <summary>
        /// Fleet Type
        /// </summary>
        public readonly ImmutableArray<Outputs.GetFleetsFleetCollectionItemDetailResult> Details;
        /// <summary>
        /// A filter to return only resources that match the entire display name given.
        /// </summary>
        public readonly string DisplayName;
        /// <summary>
        /// A filter to return resources that match the Environment Type given.
        /// </summary>
        public readonly string EnvironmentType;
        /// <summary>
        /// Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
        /// </summary>
        public readonly ImmutableDictionary<string, string> FreeformTags;
        /// <summary>
        /// Unique identifier or OCID for listing a single fleet by id. Either compartmentId or id must be provided.
        /// </summary>
        public readonly string Id;
        /// <summary>
        /// A value that represents if auto-confirming of the targets can be enabled. This will allow targets to be auto-confirmed in the fleet without manual intervention.
        /// </summary>
        public readonly bool IsTargetAutoConfirm;
        /// <summary>
        /// A message describing the current state in more detail. For example, can be used to provide actionable information for a resource in Failed state.
        /// </summary>
        public readonly string LifecycleDetails;
        /// <summary>
        /// Notification Preferences associated with the Fleet.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetFleetsFleetCollectionItemNotificationPreferenceResult> NotificationPreferences;
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the fleet that would be the parent for this fleet.
        /// </summary>
        public readonly string ParentFleetId;
        /// <summary>
        /// Products associated with the Fleet.
        /// </summary>
        public readonly ImmutableArray<string> Products;
        /// <summary>
        /// Properties associated with the Fleet.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetFleetsFleetCollectionItemPropertyResult> Properties;
        /// <summary>
        /// Associated region
        /// </summary>
        public readonly string ResourceRegion;
        /// <summary>
        /// Resource Selection Type
        /// </summary>
        public readonly ImmutableArray<Outputs.GetFleetsFleetCollectionItemResourceSelectionResult> ResourceSelections;
        /// <summary>
        /// Resources associated with the Fleet if resourceSelectionType is MANUAL.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetFleetsFleetCollectionItemResourceResult> Resources;
        /// <summary>
        /// A filter to return fleets whose lifecycleState matches the given lifecycleState.
        /// </summary>
        public readonly string State;
        /// <summary>
        /// System tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"orcl-cloud.free-tier-retained": "true"}`
        /// </summary>
        public readonly ImmutableDictionary<string, string> SystemTags;
        /// <summary>
        /// The time this resource was created. An RFC3339 formatted datetime string.
        /// </summary>
        public readonly string TimeCreated;
        /// <summary>
        /// The time this resource was last updated. An RFC3339 formatted datetime string.
        /// </summary>
        public readonly string TimeUpdated;

        [OutputConstructor]
        private GetFleetsFleetCollectionItemResult(
            string compartmentId,

            ImmutableArray<Outputs.GetFleetsFleetCollectionItemCredentialResult> credentials,

            ImmutableDictionary<string, string> definedTags,

            string description,

            ImmutableArray<Outputs.GetFleetsFleetCollectionItemDetailResult> details,

            string displayName,

            string environmentType,

            ImmutableDictionary<string, string> freeformTags,

            string id,

            bool isTargetAutoConfirm,

            string lifecycleDetails,

            ImmutableArray<Outputs.GetFleetsFleetCollectionItemNotificationPreferenceResult> notificationPreferences,

            string parentFleetId,

            ImmutableArray<string> products,

            ImmutableArray<Outputs.GetFleetsFleetCollectionItemPropertyResult> properties,

            string resourceRegion,

            ImmutableArray<Outputs.GetFleetsFleetCollectionItemResourceSelectionResult> resourceSelections,

            ImmutableArray<Outputs.GetFleetsFleetCollectionItemResourceResult> resources,

            string state,

            ImmutableDictionary<string, string> systemTags,

            string timeCreated,

            string timeUpdated)
        {
            CompartmentId = compartmentId;
            Credentials = credentials;
            DefinedTags = definedTags;
            Description = description;
            Details = details;
            DisplayName = displayName;
            EnvironmentType = environmentType;
            FreeformTags = freeformTags;
            Id = id;
            IsTargetAutoConfirm = isTargetAutoConfirm;
            LifecycleDetails = lifecycleDetails;
            NotificationPreferences = notificationPreferences;
            ParentFleetId = parentFleetId;
            Products = products;
            Properties = properties;
            ResourceRegion = resourceRegion;
            ResourceSelections = resourceSelections;
            Resources = resources;
            State = state;
            SystemTags = systemTags;
            TimeCreated = timeCreated;
            TimeUpdated = timeUpdated;
        }
    }
}
