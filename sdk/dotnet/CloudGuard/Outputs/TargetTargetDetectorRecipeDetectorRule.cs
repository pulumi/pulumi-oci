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
    public sealed class TargetTargetDetectorRecipeDetectorRule
    {
        /// <summary>
        /// The ID of the attached data source
        /// </summary>
        public readonly string? DataSourceId;
        /// <summary>
        /// The target description.
        /// 
        /// Avoid entering confidential information.
        /// </summary>
        public readonly string? Description;
        /// <summary>
        /// (Updatable) Parameters to update detector rule configuration details in a detector recipe attached to a target.
        /// </summary>
        public readonly Outputs.TargetTargetDetectorRecipeDetectorRuleDetails Details;
        /// <summary>
        /// Detector type for the rule
        /// </summary>
        public readonly string? Detector;
        /// <summary>
        /// (Updatable) Unique identifier for the detector rule
        /// </summary>
        public readonly string DetectorRuleId;
        /// <summary>
        /// (Updatable) Display name for the target.
        /// 
        /// Avoid entering confidential information.
        /// </summary>
        public readonly string? DisplayName;
        /// <summary>
        /// Data source entities mapping for a detector rule
        /// </summary>
        public readonly ImmutableArray<Outputs.TargetTargetDetectorRecipeDetectorRuleEntitiesMapping> EntitiesMappings;
        /// <summary>
        /// A message describing the current state in more detail. For example, can be used to provide actionable information for a resource in Failed state.
        /// </summary>
        public readonly string? LifecycleDetails;
        /// <summary>
        /// List of managed list types related to this rule
        /// </summary>
        public readonly ImmutableArray<string> ManagedListTypes;
        /// <summary>
        /// Recommendation for TargetDetectorRecipeDetectorRule resource
        /// </summary>
        public readonly string? Recommendation;
        /// <summary>
        /// The type of resource which is monitored by the detector rule. For example, Instance, Database, VCN, Policy. To find the resource type for a particular rule, see [Detector Recipe Reference] (/iaas/cloud-guard/using/detect-recipes.htm#detect-recipes-reference).
        /// </summary>
        public readonly string? ResourceType;
        /// <summary>
        /// Service type of the configuration to which the rule is applied
        /// </summary>
        public readonly string? ServiceType;
        /// <summary>
        /// (Updatable) The enablement state of the detector rule
        /// </summary>
        public readonly string? State;
        /// <summary>
        /// The date and time the target was created. Format defined by RFC3339.
        /// </summary>
        public readonly string? TimeCreated;
        /// <summary>
        /// The date and time the target was last updated. Format defined by RFC3339.
        /// </summary>
        public readonly string? TimeUpdated;

        [OutputConstructor]
        private TargetTargetDetectorRecipeDetectorRule(
            string? dataSourceId,

            string? description,

            Outputs.TargetTargetDetectorRecipeDetectorRuleDetails details,

            string? detector,

            string detectorRuleId,

            string? displayName,

            ImmutableArray<Outputs.TargetTargetDetectorRecipeDetectorRuleEntitiesMapping> entitiesMappings,

            string? lifecycleDetails,

            ImmutableArray<string> managedListTypes,

            string? recommendation,

            string? resourceType,

            string? serviceType,

            string? state,

            string? timeCreated,

            string? timeUpdated)
        {
            DataSourceId = dataSourceId;
            Description = description;
            Details = details;
            Detector = detector;
            DetectorRuleId = detectorRuleId;
            DisplayName = displayName;
            EntitiesMappings = entitiesMappings;
            LifecycleDetails = lifecycleDetails;
            ManagedListTypes = managedListTypes;
            Recommendation = recommendation;
            ResourceType = resourceType;
            ServiceType = serviceType;
            State = state;
            TimeCreated = timeCreated;
            TimeUpdated = timeUpdated;
        }
    }
}
