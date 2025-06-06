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
    public sealed class DetectorRecipeEffectiveDetectorRule
    {
        /// <summary>
        /// List of responder rules that can be used to remediate this detector rule
        /// </summary>
        public readonly ImmutableArray<Outputs.DetectorRecipeEffectiveDetectorRuleCandidateResponderRule> CandidateResponderRules;
        /// <summary>
        /// The ID of the attached data source
        /// </summary>
        public readonly string? DataSourceId;
        /// <summary>
        /// (Updatable) Detector recipe description.
        /// 
        /// Avoid entering confidential information.
        /// </summary>
        public readonly string? Description;
        /// <summary>
        /// Detailed information for a detector.
        /// </summary>
        public readonly ImmutableArray<Outputs.DetectorRecipeEffectiveDetectorRuleDetail> Details;
        /// <summary>
        /// Detector for the rule
        /// </summary>
        public readonly string? Detector;
        /// <summary>
        /// The unique identifier of the detector rule.
        /// </summary>
        public readonly string? DetectorRuleId;
        /// <summary>
        /// (Updatable) Detector recipe display name.
        /// 
        /// Avoid entering confidential information.
        /// </summary>
        public readonly string? DisplayName;
        /// <summary>
        /// Data source entities mapping for the detector rule
        /// </summary>
        public readonly ImmutableArray<Outputs.DetectorRecipeEffectiveDetectorRuleEntitiesMapping> EntitiesMappings;
        /// <summary>
        /// A message describing the current state in more detail. For example, can be used to provide actionable information for a resource in Failed state.
        /// </summary>
        public readonly string? LifecycleDetails;
        /// <summary>
        /// List of managed list types related to this rule
        /// </summary>
        public readonly ImmutableArray<string> ManagedListTypes;
        /// <summary>
        /// Recommendation for DetectorRecipeDetectorRule resource
        /// </summary>
        public readonly string? Recommendation;
        /// <summary>
        /// Resource type of the configuration to which the rule is applied
        /// </summary>
        public readonly string? ResourceType;
        /// <summary>
        /// Service type of the configuration to which the rule is applied
        /// </summary>
        public readonly string? ServiceType;
        /// <summary>
        /// The current lifecycle state of the resource
        /// </summary>
        public readonly string? State;
        /// <summary>
        /// The date and time the detector recipe was created Format defined by RFC3339.
        /// </summary>
        public readonly string? TimeCreated;
        /// <summary>
        /// The date and time the detector recipe was last updated Format defined by RFC3339.
        /// </summary>
        public readonly string? TimeUpdated;

        [OutputConstructor]
        private DetectorRecipeEffectiveDetectorRule(
            ImmutableArray<Outputs.DetectorRecipeEffectiveDetectorRuleCandidateResponderRule> candidateResponderRules,

            string? dataSourceId,

            string? description,

            ImmutableArray<Outputs.DetectorRecipeEffectiveDetectorRuleDetail> details,

            string? detector,

            string? detectorRuleId,

            string? displayName,

            ImmutableArray<Outputs.DetectorRecipeEffectiveDetectorRuleEntitiesMapping> entitiesMappings,

            string? lifecycleDetails,

            ImmutableArray<string> managedListTypes,

            string? recommendation,

            string? resourceType,

            string? serviceType,

            string? state,

            string? timeCreated,

            string? timeUpdated)
        {
            CandidateResponderRules = candidateResponderRules;
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
