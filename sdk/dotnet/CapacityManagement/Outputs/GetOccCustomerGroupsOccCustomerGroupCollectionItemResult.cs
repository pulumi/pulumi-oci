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
    public sealed class GetOccCustomerGroupsOccCustomerGroupCollectionItemResult
    {
        /// <summary>
        /// The ocid of the compartment or tenancy in which resources are to be listed. This will also be used for authorization purposes.
        /// </summary>
        public readonly string CompartmentId;
        /// <summary>
        /// A list containing all the customers that belong to this customer group
        /// </summary>
        public readonly ImmutableArray<Outputs.GetOccCustomerGroupsOccCustomerGroupCollectionItemCustomersListResult> CustomersLists;
        /// <summary>
        /// Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
        /// </summary>
        public readonly ImmutableDictionary<string, string> DefinedTags;
        /// <summary>
        /// The description about the customer group.
        /// </summary>
        public readonly string Description;
        /// <summary>
        /// A filter to return only the resources that match the entire display name. The match is not case sensitive.
        /// </summary>
        public readonly string DisplayName;
        /// <summary>
        /// Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
        /// </summary>
        public readonly ImmutableDictionary<string, string> FreeformTags;
        /// <summary>
        /// A query filter to return the list result based on the customer group OCID. This is done for users who have INSPECT permission but do not have READ permission.
        /// </summary>
        public readonly string Id;
        /// <summary>
        /// A message describing the current state in more detail. For example, can be used to provide actionable information for a resource in a Failed State.
        /// </summary>
        public readonly string LifecycleDetails;
        /// <summary>
        /// The current lifecycle state of the resource.
        /// </summary>
        public readonly string State;
        /// <summary>
        /// A query filter to return the list result based on status.
        /// </summary>
        public readonly string Status;
        /// <summary>
        /// System tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"orcl-cloud.free-tier-retained": "true"}`
        /// </summary>
        public readonly ImmutableDictionary<string, string> SystemTags;
        /// <summary>
        /// The time when the customer group was created.
        /// </summary>
        public readonly string TimeCreated;
        /// <summary>
        /// The time when the customer group was last updated.
        /// </summary>
        public readonly string TimeUpdated;

        [OutputConstructor]
        private GetOccCustomerGroupsOccCustomerGroupCollectionItemResult(
            string compartmentId,

            ImmutableArray<Outputs.GetOccCustomerGroupsOccCustomerGroupCollectionItemCustomersListResult> customersLists,

            ImmutableDictionary<string, string> definedTags,

            string description,

            string displayName,

            ImmutableDictionary<string, string> freeformTags,

            string id,

            string lifecycleDetails,

            string state,

            string status,

            ImmutableDictionary<string, string> systemTags,

            string timeCreated,

            string timeUpdated)
        {
            CompartmentId = compartmentId;
            CustomersLists = customersLists;
            DefinedTags = definedTags;
            Description = description;
            DisplayName = displayName;
            FreeformTags = freeformTags;
            Id = id;
            LifecycleDetails = lifecycleDetails;
            State = state;
            Status = status;
            SystemTags = systemTags;
            TimeCreated = timeCreated;
            TimeUpdated = timeUpdated;
        }
    }
}
