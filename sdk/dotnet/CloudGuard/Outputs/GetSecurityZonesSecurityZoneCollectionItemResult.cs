// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.CloudGuard.Outputs
{

    [OutputType]
    public sealed class GetSecurityZonesSecurityZoneCollectionItemResult
    {
        /// <summary>
        /// The OCID of the compartment in which to list resources.
        /// </summary>
        public readonly string CompartmentId;
        /// <summary>
        /// Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
        /// </summary>
        public readonly ImmutableDictionary<string, string> DefinedTags;
        /// <summary>
        /// The security zone's description
        /// </summary>
        public readonly string Description;
        /// <summary>
        /// A filter to return only resources that match the entire display name given.
        /// </summary>
        public readonly string DisplayName;
        /// <summary>
        /// Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
        /// </summary>
        public readonly ImmutableDictionary<string, string> FreeformTags;
        /// <summary>
        /// The unique identifier of the security zone (`SecurityZone` resource).
        /// </summary>
        public readonly string Id;
        /// <summary>
        /// List of inherited compartments
        /// </summary>
        public readonly ImmutableArray<string> InheritedByCompartments;
        /// <summary>
        /// A message describing the current state in more detail. For example, this can be used to provide actionable information for a zone in the `Failed` state.
        /// </summary>
        public readonly string LifecycleDetails;
        /// <summary>
        /// The OCID of the recipe (`SecurityRecipe` resource) for the security zone
        /// </summary>
        public readonly string SecurityZoneRecipeId;
        /// <summary>
        /// The OCID of the target associated with the security zone
        /// </summary>
        public readonly string SecurityZoneTargetId;
        /// <summary>
        /// The field lifecycle state. Only one state can be provided. Default value for state is active. If no value is specified state is active.
        /// </summary>
        public readonly string State;
        /// <summary>
        /// The time the security zone was created. An RFC3339 formatted datetime string.
        /// </summary>
        public readonly string TimeCreated;
        /// <summary>
        /// The time the security zone was last updated. An RFC3339 formatted datetime string.
        /// </summary>
        public readonly string TimeUpdated;

        [OutputConstructor]
        private GetSecurityZonesSecurityZoneCollectionItemResult(
            string compartmentId,

            ImmutableDictionary<string, string> definedTags,

            string description,

            string displayName,

            ImmutableDictionary<string, string> freeformTags,

            string id,

            ImmutableArray<string> inheritedByCompartments,

            string lifecycleDetails,

            string securityZoneRecipeId,

            string securityZoneTargetId,

            string state,

            string timeCreated,

            string timeUpdated)
        {
            CompartmentId = compartmentId;
            DefinedTags = definedTags;
            Description = description;
            DisplayName = displayName;
            FreeformTags = freeformTags;
            Id = id;
            InheritedByCompartments = inheritedByCompartments;
            LifecycleDetails = lifecycleDetails;
            SecurityZoneRecipeId = securityZoneRecipeId;
            SecurityZoneTargetId = securityZoneTargetId;
            State = state;
            TimeCreated = timeCreated;
            TimeUpdated = timeUpdated;
        }
    }
}
