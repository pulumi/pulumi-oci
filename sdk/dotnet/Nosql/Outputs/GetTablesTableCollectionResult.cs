// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Nosql.Outputs
{

    [OutputType]
    public sealed class GetTablesTableCollectionResult
    {
        /// <summary>
        /// The ID of a table's compartment.
        /// </summary>
        public readonly string CompartmentId;
        public readonly string DdlStatement;
        /// <summary>
        /// Defined tags for this resource. Each key is predefined and scoped to a namespace.  Example: `{"foo-namespace": {"bar-key": "value"}}`
        /// </summary>
        public readonly ImmutableDictionary<string, string> DefinedTags;
        /// <summary>
        /// Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
        /// </summary>
        public readonly ImmutableDictionary<string, string> FreeformTags;
        /// <summary>
        /// Unique identifier that is immutable.
        /// </summary>
        public readonly string Id;
        /// <summary>
        /// True if this table can be reclaimed after an idle period.
        /// </summary>
        public readonly bool IsAutoReclaimable;
        /// <summary>
        /// True if this table is currently a member of a replication set.
        /// </summary>
        public readonly bool IsMultiRegion;
        /// <summary>
        /// A message describing the current state in more detail.
        /// </summary>
        public readonly string LifecycleDetails;
        public readonly int LocalReplicaInitializationInPercent;
        /// <summary>
        /// A shell-globbing-style (*?[]) filter for names.
        /// </summary>
        public readonly string Name;
        public readonly ImmutableArray<Outputs.GetTablesTableCollectionReplicaResult> Replicas;
        /// <summary>
        /// The current state of this table's schema. Available states are MUTABLE - The schema can be changed. The table is not eligible for replication. FROZEN - The schema is immutable. The table is eligible for replication.
        /// </summary>
        public readonly string SchemaState;
        public readonly ImmutableArray<Outputs.GetTablesTableCollectionSchemaResult> Schemas;
        /// <summary>
        /// Filter list by the lifecycle state of the item.
        /// </summary>
        public readonly string State;
        /// <summary>
        /// Read-only system tag. These predefined keys are scoped to namespaces.  At present the only supported namespace is `"orcl-cloud"`; and the only key in that namespace is `"free-tier-retained"`. Example: `{"orcl-cloud"": {"free-tier-retained": "true"}}`
        /// </summary>
        public readonly ImmutableDictionary<string, string> SystemTags;
        /// <summary>
        /// Throughput and storage limits configuration of a table.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetTablesTableCollectionTableLimitResult> TableLimits;
        /// <summary>
        /// The time the the table was created. An RFC3339 formatted datetime string.
        /// </summary>
        public readonly string TimeCreated;
        /// <summary>
        /// If lifecycleState is INACTIVE, indicates when this table will be automatically removed. An RFC3339 formatted datetime string.
        /// </summary>
        public readonly string TimeOfExpiration;
        /// <summary>
        /// The time the the table's metadata was last updated. An RFC3339 formatted datetime string.
        /// </summary>
        public readonly string TimeUpdated;

        [OutputConstructor]
        private GetTablesTableCollectionResult(
            string compartmentId,

            string ddlStatement,

            ImmutableDictionary<string, string> definedTags,

            ImmutableDictionary<string, string> freeformTags,

            string id,

            bool isAutoReclaimable,

            bool isMultiRegion,

            string lifecycleDetails,

            int localReplicaInitializationInPercent,

            string name,

            ImmutableArray<Outputs.GetTablesTableCollectionReplicaResult> replicas,

            string schemaState,

            ImmutableArray<Outputs.GetTablesTableCollectionSchemaResult> schemas,

            string state,

            ImmutableDictionary<string, string> systemTags,

            ImmutableArray<Outputs.GetTablesTableCollectionTableLimitResult> tableLimits,

            string timeCreated,

            string timeOfExpiration,

            string timeUpdated)
        {
            CompartmentId = compartmentId;
            DdlStatement = ddlStatement;
            DefinedTags = definedTags;
            FreeformTags = freeformTags;
            Id = id;
            IsAutoReclaimable = isAutoReclaimable;
            IsMultiRegion = isMultiRegion;
            LifecycleDetails = lifecycleDetails;
            LocalReplicaInitializationInPercent = localReplicaInitializationInPercent;
            Name = name;
            Replicas = replicas;
            SchemaState = schemaState;
            Schemas = schemas;
            State = state;
            SystemTags = systemTags;
            TableLimits = tableLimits;
            TimeCreated = timeCreated;
            TimeOfExpiration = timeOfExpiration;
            TimeUpdated = timeUpdated;
        }
    }
}
