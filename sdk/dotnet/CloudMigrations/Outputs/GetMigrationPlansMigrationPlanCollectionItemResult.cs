// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.CloudMigrations.Outputs
{

    [OutputType]
    public sealed class GetMigrationPlansMigrationPlanCollectionItemResult
    {
        /// <summary>
        /// Limits of the resources that are needed for migration. Example: {"BlockVolume": 2, "VCN": 1}
        /// </summary>
        public readonly ImmutableDictionary<string, object> CalculatedLimits;
        /// <summary>
        /// The ID of the compartment in which to list resources.
        /// </summary>
        public readonly string CompartmentId;
        /// <summary>
        /// Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
        /// </summary>
        public readonly ImmutableDictionary<string, object> DefinedTags;
        /// <summary>
        /// A filter to return only resources that match the entire given display name.
        /// </summary>
        public readonly string DisplayName;
        /// <summary>
        /// Simple key-value pair that is applied without any predefined name, type or scope. It exists only for cross-compatibility. Example: `{"bar-key": "value"}`
        /// </summary>
        public readonly ImmutableDictionary<string, object> FreeformTags;
        /// <summary>
        /// The unique Oracle ID (OCID) that is immutable on creation.
        /// </summary>
        public readonly string Id;
        /// <summary>
        /// A message describing the current state in more detail. For example, it can be used to provide actionable information for a resource in Failed state.
        /// </summary>
        public readonly string LifecycleDetails;
        /// <summary>
        /// Unique migration identifier
        /// </summary>
        public readonly string MigrationId;
        /// <summary>
        /// Status of the migration plan.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetMigrationPlansMigrationPlanCollectionItemMigrationPlanStatResult> MigrationPlanStats;
        /// <summary>
        /// OCID of the referenced ORM job.
        /// </summary>
        public readonly string ReferenceToRmsStack;
        /// <summary>
        /// Source migraiton plan ID to be cloned.
        /// </summary>
        public readonly string SourceMigrationPlanId;
        /// <summary>
        /// The current state of the migration plan.
        /// </summary>
        public readonly string State;
        /// <summary>
        /// List of strategies for the resources to be migrated.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetMigrationPlansMigrationPlanCollectionItemStrategyResult> Strategies;
        /// <summary>
        /// Usage of system tag keys. These predefined keys are scoped to namespaces. Example: `{"orcl-cloud.free-tier-retained": "true"}`
        /// </summary>
        public readonly ImmutableDictionary<string, object> SystemTags;
        /// <summary>
        /// List of target environments.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetMigrationPlansMigrationPlanCollectionItemTargetEnvironmentResult> TargetEnvironments;
        /// <summary>
        /// The time when the migration plan was created. An RFC3339 formatted datetime string.
        /// </summary>
        public readonly string TimeCreated;
        /// <summary>
        /// The time when the migration plan was updated. An RFC3339 formatted datetime string.
        /// </summary>
        public readonly string TimeUpdated;

        [OutputConstructor]
        private GetMigrationPlansMigrationPlanCollectionItemResult(
            ImmutableDictionary<string, object> calculatedLimits,

            string compartmentId,

            ImmutableDictionary<string, object> definedTags,

            string displayName,

            ImmutableDictionary<string, object> freeformTags,

            string id,

            string lifecycleDetails,

            string migrationId,

            ImmutableArray<Outputs.GetMigrationPlansMigrationPlanCollectionItemMigrationPlanStatResult> migrationPlanStats,

            string referenceToRmsStack,

            string sourceMigrationPlanId,

            string state,

            ImmutableArray<Outputs.GetMigrationPlansMigrationPlanCollectionItemStrategyResult> strategies,

            ImmutableDictionary<string, object> systemTags,

            ImmutableArray<Outputs.GetMigrationPlansMigrationPlanCollectionItemTargetEnvironmentResult> targetEnvironments,

            string timeCreated,

            string timeUpdated)
        {
            CalculatedLimits = calculatedLimits;
            CompartmentId = compartmentId;
            DefinedTags = definedTags;
            DisplayName = displayName;
            FreeformTags = freeformTags;
            Id = id;
            LifecycleDetails = lifecycleDetails;
            MigrationId = migrationId;
            MigrationPlanStats = migrationPlanStats;
            ReferenceToRmsStack = referenceToRmsStack;
            SourceMigrationPlanId = sourceMigrationPlanId;
            State = state;
            Strategies = strategies;
            SystemTags = systemTags;
            TargetEnvironments = targetEnvironments;
            TimeCreated = timeCreated;
            TimeUpdated = timeUpdated;
        }
    }
}