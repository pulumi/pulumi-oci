// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.CapacityManagement.Outputs
{

    [OutputType]
    public sealed class GetOccCapacityRequestsOccCapacityRequestCollectionItemResult
    {
        /// <summary>
        /// The availability domain of the resource which is to be transferred. Note that this is only required for Capacity Request Transfer requests.
        /// </summary>
        public readonly string AvailabilityDomain;
        /// <summary>
        /// The ocid of the compartment or tenancy in which resources are to be listed. This will also be used for authorization purposes.
        /// </summary>
        public readonly string CompartmentId;
        /// <summary>
        /// The date by which the capacity requested by customers before dateFinalCustomerOrder needs to be fulfilled.
        /// </summary>
        public readonly string DateExpectedCapacityHandover;
        /// <summary>
        /// Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
        /// </summary>
        public readonly ImmutableDictionary<string, string> DefinedTags;
        /// <summary>
        /// Meaningful text about the capacity request.
        /// </summary>
        public readonly string Description;
        /// <summary>
        /// A list of resources requested as part of this request
        /// </summary>
        public readonly ImmutableArray<Outputs.GetOccCapacityRequestsOccCapacityRequestCollectionItemDetailResult> Details;
        /// <summary>
        /// A filter to return only the resources that match the entire display name. The match is not case sensitive.
        /// </summary>
        public readonly string DisplayName;
        /// <summary>
        /// Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
        /// </summary>
        public readonly ImmutableDictionary<string, string> FreeformTags;
        /// <summary>
        /// A filter to return the list of capacity requests based on the OCID of the capacity request. This is done for the users who have INSPECT permission on the resource but do not have READ permission.
        /// </summary>
        public readonly string Id;
        /// <summary>
        /// A message describing the current state in more detail. For example, can be used to provide actionable information for a resource in a Failed State.
        /// </summary>
        public readonly string LifecycleDetails;
        /// <summary>
        /// The namespace by which we would filter the list.
        /// </summary>
        public readonly string Namespace;
        /// <summary>
        /// A filter to return the list of capacity requests based on the OCID of the availability catalog against which they were created.
        /// </summary>
        public readonly string OccAvailabilityCatalogId;
        /// <summary>
        /// The OCID of the customer group to which this customer belongs to.
        /// </summary>
        public readonly string OccCustomerGroupId;
        public readonly ImmutableArray<Outputs.GetOccCapacityRequestsOccCapacityRequestCollectionItemPatchOperationResult> PatchOperations;
        /// <summary>
        /// The name of the region for which the capacity request was made.
        /// </summary>
        public readonly string Region;
        /// <summary>
        /// The different states the capacity request goes through.
        /// </summary>
        public readonly string RequestState;
        /// <summary>
        /// A filter to return only the resources that match the request type. The match is not case sensitive.
        /// </summary>
        public readonly string RequestType;
        /// <summary>
        /// The current lifecycle state of the resource.
        /// </summary>
        public readonly string State;
        /// <summary>
        /// System tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"orcl-cloud.free-tier-retained": "true"}`
        /// </summary>
        public readonly ImmutableDictionary<string, string> SystemTags;
        /// <summary>
        /// The time when the capacity request was created.
        /// </summary>
        public readonly string TimeCreated;
        /// <summary>
        /// The time when the capacity request was updated.
        /// </summary>
        public readonly string TimeUpdated;

        [OutputConstructor]
        private GetOccCapacityRequestsOccCapacityRequestCollectionItemResult(
            string availabilityDomain,

            string compartmentId,

            string dateExpectedCapacityHandover,

            ImmutableDictionary<string, string> definedTags,

            string description,

            ImmutableArray<Outputs.GetOccCapacityRequestsOccCapacityRequestCollectionItemDetailResult> details,

            string displayName,

            ImmutableDictionary<string, string> freeformTags,

            string id,

            string lifecycleDetails,

            string @namespace,

            string occAvailabilityCatalogId,

            string occCustomerGroupId,

            ImmutableArray<Outputs.GetOccCapacityRequestsOccCapacityRequestCollectionItemPatchOperationResult> patchOperations,

            string region,

            string requestState,

            string requestType,

            string state,

            ImmutableDictionary<string, string> systemTags,

            string timeCreated,

            string timeUpdated)
        {
            AvailabilityDomain = availabilityDomain;
            CompartmentId = compartmentId;
            DateExpectedCapacityHandover = dateExpectedCapacityHandover;
            DefinedTags = definedTags;
            Description = description;
            Details = details;
            DisplayName = displayName;
            FreeformTags = freeformTags;
            Id = id;
            LifecycleDetails = lifecycleDetails;
            Namespace = @namespace;
            OccAvailabilityCatalogId = occAvailabilityCatalogId;
            OccCustomerGroupId = occCustomerGroupId;
            PatchOperations = patchOperations;
            Region = region;
            RequestState = requestState;
            RequestType = requestType;
            State = state;
            SystemTags = systemTags;
            TimeCreated = timeCreated;
            TimeUpdated = timeUpdated;
        }
    }
}
