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
    public sealed class GetAwrHubsAwrHubSummaryCollectionItemResult
    {
        /// <summary>
        /// Mailbox URL required for AWR hub and AWR source setup.
        /// </summary>
        public readonly string AwrMailboxUrl;
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
        /// </summary>
        public readonly string CompartmentId;
        /// <summary>
        /// Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
        /// </summary>
        public readonly ImmutableDictionary<string, string> DefinedTags;
        /// <summary>
        /// A filter to return only resources that match the entire display name.
        /// </summary>
        public readonly string DisplayName;
        /// <summary>
        /// Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
        /// </summary>
        public readonly ImmutableDictionary<string, string> FreeformTags;
        /// <summary>
        /// Dst Time Zone Version of the AWR Hub
        /// </summary>
        public readonly string HubDstTimezoneVersion;
        /// <summary>
        /// Unique Awr Hub identifier
        /// </summary>
        public readonly string Id;
        /// <summary>
        /// A message describing the current state in more detail. For example, can be used to provide actionable information for a resource in Failed state.
        /// </summary>
        public readonly string LifecycleDetails;
        /// <summary>
        /// Object Storage Bucket Name
        /// </summary>
        public readonly string ObjectStorageBucketName;
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
        private GetAwrHubsAwrHubSummaryCollectionItemResult(
            string awrMailboxUrl,

            string compartmentId,

            ImmutableDictionary<string, string> definedTags,

            string displayName,

            ImmutableDictionary<string, string> freeformTags,

            string hubDstTimezoneVersion,

            string id,

            string lifecycleDetails,

            string objectStorageBucketName,

            string operationsInsightsWarehouseId,

            string state,

            ImmutableDictionary<string, string> systemTags,

            string timeCreated,

            string timeUpdated)
        {
            AwrMailboxUrl = awrMailboxUrl;
            CompartmentId = compartmentId;
            DefinedTags = definedTags;
            DisplayName = displayName;
            FreeformTags = freeformTags;
            HubDstTimezoneVersion = hubDstTimezoneVersion;
            Id = id;
            LifecycleDetails = lifecycleDetails;
            ObjectStorageBucketName = objectStorageBucketName;
            OperationsInsightsWarehouseId = operationsInsightsWarehouseId;
            State = state;
            SystemTags = systemTags;
            TimeCreated = timeCreated;
            TimeUpdated = timeUpdated;
        }
    }
}
