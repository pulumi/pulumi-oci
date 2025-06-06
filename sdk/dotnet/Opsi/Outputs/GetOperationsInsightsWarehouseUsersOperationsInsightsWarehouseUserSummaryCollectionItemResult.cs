// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Opsi.Outputs
{

    [OutputType]
    public sealed class GetOperationsInsightsWarehouseUsersOperationsInsightsWarehouseUserSummaryCollectionItemResult
    {
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
        /// </summary>
        public readonly string CompartmentId;
        /// <summary>
        /// User provided connection password for the AWR Data,  Enterprise Manager Data and Ops Insights OPSI Hub.
        /// </summary>
        public readonly string ConnectionPassword;
        /// <summary>
        /// Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
        /// </summary>
        public readonly ImmutableDictionary<string, string> DefinedTags;
        /// <summary>
        /// Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
        /// </summary>
        public readonly ImmutableDictionary<string, string> FreeformTags;
        /// <summary>
        /// Unique Operations Insights Warehouse User identifier
        /// </summary>
        public readonly string Id;
        /// <summary>
        /// Indicate whether user has access to AWR data.
        /// </summary>
        public readonly bool IsAwrDataAccess;
        /// <summary>
        /// Indicate whether user has access to EM data.
        /// </summary>
        public readonly bool IsEmDataAccess;
        /// <summary>
        /// Indicate whether user has access to OPSI data.
        /// </summary>
        public readonly bool IsOpsiDataAccess;
        /// <summary>
        /// A message describing the current state in more detail. For example, can be used to provide actionable information for a resource in Failed state.
        /// </summary>
        public readonly string LifecycleDetails;
        /// <summary>
        /// Username for schema which would have access to AWR Data,  Enterprise Manager Data and Ops Insights OPSI Hub.
        /// </summary>
        public readonly string Name;
        /// <summary>
        /// Unique Operations Insights Warehouse identifier
        /// </summary>
        public readonly string OperationsInsightsWarehouseId;
        /// <summary>
        /// Lifecycle states
        /// </summary>
        public readonly string State;
        /// <summary>
        /// System tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"orcl-cloud.free-tier-retained": "true"}`
        /// </summary>
        public readonly ImmutableDictionary<string, string> SystemTags;
        /// <summary>
        /// The time at which the resource was first created. An RFC3339 formatted datetime string
        /// </summary>
        public readonly string TimeCreated;
        /// <summary>
        /// The time at which the resource was last updated. An RFC3339 formatted datetime string
        /// </summary>
        public readonly string TimeUpdated;

        [OutputConstructor]
        private GetOperationsInsightsWarehouseUsersOperationsInsightsWarehouseUserSummaryCollectionItemResult(
            string compartmentId,

            string connectionPassword,

            ImmutableDictionary<string, string> definedTags,

            ImmutableDictionary<string, string> freeformTags,

            string id,

            bool isAwrDataAccess,

            bool isEmDataAccess,

            bool isOpsiDataAccess,

            string lifecycleDetails,

            string name,

            string operationsInsightsWarehouseId,

            string state,

            ImmutableDictionary<string, string> systemTags,

            string timeCreated,

            string timeUpdated)
        {
            CompartmentId = compartmentId;
            ConnectionPassword = connectionPassword;
            DefinedTags = definedTags;
            FreeformTags = freeformTags;
            Id = id;
            IsAwrDataAccess = isAwrDataAccess;
            IsEmDataAccess = isEmDataAccess;
            IsOpsiDataAccess = isOpsiDataAccess;
            LifecycleDetails = lifecycleDetails;
            Name = name;
            OperationsInsightsWarehouseId = operationsInsightsWarehouseId;
            State = state;
            SystemTags = systemTags;
            TimeCreated = timeCreated;
            TimeUpdated = timeUpdated;
        }
    }
}
