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
    public sealed class GetTargetAssetsTargetAssetCollectionItemResult
    {
        /// <summary>
        /// Performance of the block volumes.
        /// </summary>
        public readonly int BlockVolumesPerformance;
        /// <summary>
        /// The OCID of the compartment.
        /// </summary>
        public readonly string CompartmentId;
        /// <summary>
        /// Messages about the compatibility issues.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetTargetAssetsTargetAssetCollectionItemCompatibilityMessageResult> CompatibilityMessages;
        /// <summary>
        /// Created resource identifier
        /// </summary>
        public readonly string CreatedResourceId;
        /// <summary>
        /// A filter to return only resources that match the entire given display name.
        /// </summary>
        public readonly string DisplayName;
        /// <summary>
        /// Cost estimation description
        /// </summary>
        public readonly ImmutableArray<Outputs.GetTargetAssetsTargetAssetCollectionItemEstimatedCostResult> EstimatedCosts;
        /// <summary>
        /// Asset ID generated by mirgration service. It is used in the mirgration service pipeline.
        /// </summary>
        public readonly string Id;
        /// <summary>
        /// A boolean indicating whether the asset should be migrated.
        /// </summary>
        public readonly bool IsExcludedFromExecution;
        /// <summary>
        /// A message describing the current state in more detail. For example, it can be used to provide actionable information for a resource in Failed state.
        /// </summary>
        public readonly string LifecycleDetails;
        /// <summary>
        /// Description of the migration asset.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetTargetAssetsTargetAssetCollectionItemMigrationAssetResult> MigrationAssets;
        /// <summary>
        /// Unique migration plan identifier
        /// </summary>
        public readonly string MigrationPlanId;
        /// <summary>
        /// Microsoft license for VM configuration.
        /// </summary>
        public readonly string MsLicense;
        /// <summary>
        /// Preferred VM shape type that you provide.
        /// </summary>
        public readonly string PreferredShapeType;
        /// <summary>
        /// Instance launch details. Use the `sourceDetails` parameter to specify whether a boot volume or an image should be used to launch a new instance.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetTargetAssetsTargetAssetCollectionItemRecommendedSpecResult> RecommendedSpecs;
        /// <summary>
        /// The current state of the target asset.
        /// </summary>
        public readonly string State;
        /// <summary>
        /// Instance launch details. Use the `sourceDetails` parameter to specify whether a boot volume or an image should be used to launch a new instance.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetTargetAssetsTargetAssetCollectionItemTestSpecResult> TestSpecs;
        /// <summary>
        /// The time when the assessment was done. An RFC3339 formatted datetime string.
        /// </summary>
        public readonly string TimeAssessed;
        /// <summary>
        /// The time when the target asset was created. An RFC3339 formatted datetime string.
        /// </summary>
        public readonly string TimeCreated;
        /// <summary>
        /// The time when the target asset was updated. An RFC3339 formatted datetime string.
        /// </summary>
        public readonly string TimeUpdated;
        /// <summary>
        /// The type of action to run when the instance is interrupted for eviction.
        /// </summary>
        public readonly string Type;
        /// <summary>
        /// Instance launch details. Use the `sourceDetails` parameter to specify whether a boot volume or an image should be used to launch a new instance.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetTargetAssetsTargetAssetCollectionItemUserSpecResult> UserSpecs;

        [OutputConstructor]
        private GetTargetAssetsTargetAssetCollectionItemResult(
            int blockVolumesPerformance,

            string compartmentId,

            ImmutableArray<Outputs.GetTargetAssetsTargetAssetCollectionItemCompatibilityMessageResult> compatibilityMessages,

            string createdResourceId,

            string displayName,

            ImmutableArray<Outputs.GetTargetAssetsTargetAssetCollectionItemEstimatedCostResult> estimatedCosts,

            string id,

            bool isExcludedFromExecution,

            string lifecycleDetails,

            ImmutableArray<Outputs.GetTargetAssetsTargetAssetCollectionItemMigrationAssetResult> migrationAssets,

            string migrationPlanId,

            string msLicense,

            string preferredShapeType,

            ImmutableArray<Outputs.GetTargetAssetsTargetAssetCollectionItemRecommendedSpecResult> recommendedSpecs,

            string state,

            ImmutableArray<Outputs.GetTargetAssetsTargetAssetCollectionItemTestSpecResult> testSpecs,

            string timeAssessed,

            string timeCreated,

            string timeUpdated,

            string type,

            ImmutableArray<Outputs.GetTargetAssetsTargetAssetCollectionItemUserSpecResult> userSpecs)
        {
            BlockVolumesPerformance = blockVolumesPerformance;
            CompartmentId = compartmentId;
            CompatibilityMessages = compatibilityMessages;
            CreatedResourceId = createdResourceId;
            DisplayName = displayName;
            EstimatedCosts = estimatedCosts;
            Id = id;
            IsExcludedFromExecution = isExcludedFromExecution;
            LifecycleDetails = lifecycleDetails;
            MigrationAssets = migrationAssets;
            MigrationPlanId = migrationPlanId;
            MsLicense = msLicense;
            PreferredShapeType = preferredShapeType;
            RecommendedSpecs = recommendedSpecs;
            State = state;
            TestSpecs = testSpecs;
            TimeAssessed = timeAssessed;
            TimeCreated = timeCreated;
            TimeUpdated = timeUpdated;
            Type = type;
            UserSpecs = userSpecs;
        }
    }
}