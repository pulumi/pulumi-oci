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
    public sealed class GetFleetResourcesFleetResourceCollectionItemResult
    {
        /// <summary>
        /// Resource Compartment name.
        /// </summary>
        public readonly string Compartment;
        /// <summary>
        /// OCID of the compartment to which the resource belongs to.
        /// </summary>
        public readonly string CompartmentId;
        /// <summary>
        /// Compliance State of the Resource.
        /// </summary>
        public readonly string ComplianceState;
        /// <summary>
        /// A filter to return only resources that match the entire display name given.
        /// </summary>
        public readonly string DisplayName;
        /// <summary>
        /// Environment Type associated with the Fleet when the resource type is fleet. Will only be returned for ENVIRONMENT fleets that are part of a GROUP Fleet.
        /// </summary>
        public readonly string EnvironmentType;
        /// <summary>
        /// Unique Fleet identifier.
        /// </summary>
        public readonly string FleetId;
        /// <summary>
        /// A filter to return only resources whose identifier matches the given identifier.
        /// </summary>
        public readonly string Id;
        /// <summary>
        /// A message describing the current state in more detail. For example, can be used to provide actionable information for a resource in Failed state.
        /// </summary>
        public readonly string LifecycleDetails;
        /// <summary>
        /// The compliance percentage.
        /// </summary>
        public readonly double PercentCompliant;
        /// <summary>
        /// Product associated with the resource when the resource type is fleet. Will only be returned for PRODUCT fleets that are part of a GROUP Fleet.
        /// </summary>
        public readonly string Product;
        /// <summary>
        /// Count of products within the resource.
        /// </summary>
        public readonly int ProductCount;
        /// <summary>
        /// The OCID of the resource.
        /// </summary>
        public readonly string ResourceId;
        /// <summary>
        /// Associated region
        /// </summary>
        public readonly string ResourceRegion;
        /// <summary>
        /// Type of the Resource.
        /// </summary>
        public readonly string ResourceType;
        /// <summary>
        /// A filter to return only resources whose lifecycleState matches the given lifecycleState.
        /// </summary>
        public readonly string State;
        /// <summary>
        /// System tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"orcl-cloud.free-tier-retained": "true"}`
        /// </summary>
        public readonly ImmutableDictionary<string, string> SystemTags;
        /// <summary>
        /// Count of targets within the resource.
        /// </summary>
        public readonly int TargetCount;
        /// <summary>
        /// OCID of the tenancy to which the resource belongs to.
        /// </summary>
        public readonly string TenancyId;
        /// <summary>
        /// Resource Tenancy Name.
        /// </summary>
        public readonly string TenancyName;
        /// <summary>
        /// The time this resource was created. An RFC3339 formatted datetime string.
        /// </summary>
        public readonly string TimeCreated;
        /// <summary>
        /// The time this resource was last updated. An RFC3339 formatted datetime string.
        /// </summary>
        public readonly string TimeUpdated;

        [OutputConstructor]
        private GetFleetResourcesFleetResourceCollectionItemResult(
            string compartment,

            string compartmentId,

            string complianceState,

            string displayName,

            string environmentType,

            string fleetId,

            string id,

            string lifecycleDetails,

            double percentCompliant,

            string product,

            int productCount,

            string resourceId,

            string resourceRegion,

            string resourceType,

            string state,

            ImmutableDictionary<string, string> systemTags,

            int targetCount,

            string tenancyId,

            string tenancyName,

            string timeCreated,

            string timeUpdated)
        {
            Compartment = compartment;
            CompartmentId = compartmentId;
            ComplianceState = complianceState;
            DisplayName = displayName;
            EnvironmentType = environmentType;
            FleetId = fleetId;
            Id = id;
            LifecycleDetails = lifecycleDetails;
            PercentCompliant = percentCompliant;
            Product = product;
            ProductCount = productCount;
            ResourceId = resourceId;
            ResourceRegion = resourceRegion;
            ResourceType = resourceType;
            State = state;
            SystemTags = systemTags;
            TargetCount = targetCount;
            TenancyId = tenancyId;
            TenancyName = tenancyName;
            TimeCreated = timeCreated;
            TimeUpdated = timeUpdated;
        }
    }
}
