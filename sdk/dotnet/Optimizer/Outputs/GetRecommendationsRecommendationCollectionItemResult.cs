// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Optimizer.Outputs
{

    [OutputType]
    public sealed class GetRecommendationsRecommendationCollectionItemResult
    {
        /// <summary>
        /// The unique OCID associated with the category.
        /// </summary>
        public readonly string CategoryId;
        /// <summary>
        /// The OCID of the compartment.
        /// </summary>
        public readonly string CompartmentId;
        /// <summary>
        /// Text describing the recommendation.
        /// </summary>
        public readonly string Description;
        /// <summary>
        /// The estimated cost savings, in dollars, for the recommendation.
        /// </summary>
        public readonly double EstimatedCostSaving;
        /// <summary>
        /// Additional metadata key/value pairs for the recommendation.
        /// </summary>
        public readonly ImmutableDictionary<string, string> ExtendedMetadata;
        /// <summary>
        /// The unique OCID associated with the recommendation.
        /// </summary>
        public readonly string Id;
        /// <summary>
        /// The level of importance assigned to the recommendation.
        /// </summary>
        public readonly string Importance;
        /// <summary>
        /// Optional. A filter that returns results that match the name specified.
        /// </summary>
        public readonly string Name;
        public readonly string RecommendationId;
        /// <summary>
        /// An array of `ResourceCount` objects grouped by the status of the resource actions.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetRecommendationsRecommendationCollectionItemResourceCountResult> ResourceCounts;
        /// <summary>
        /// A filter that returns results that match the lifecycle state specified.
        /// </summary>
        public readonly string State;
        /// <summary>
        /// A filter that returns recommendations that match the status specified.
        /// </summary>
        public readonly string Status;
        /// <summary>
        /// Optional. The profile levels supported by a recommendation. For example, profile level values could be `Low`, `Medium`, and `High`. Not all recommendations support this field.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetRecommendationsRecommendationCollectionItemSupportedLevelResult> SupportedLevels;
        /// <summary>
        /// The date and time the recommendation details were created, in the format defined by RFC3339.
        /// </summary>
        public readonly string TimeCreated;
        /// <summary>
        /// The date and time that the recommendation entered its current status. The format is defined by RFC3339.
        /// </summary>
        public readonly string TimeStatusBegin;
        /// <summary>
        /// The date and time the current status will change. The format is defined by RFC3339.
        /// </summary>
        public readonly string TimeStatusEnd;
        /// <summary>
        /// The date and time the recommendation details were last updated, in the format defined by RFC3339.
        /// </summary>
        public readonly string TimeUpdated;

        [OutputConstructor]
        private GetRecommendationsRecommendationCollectionItemResult(
            string categoryId,

            string compartmentId,

            string description,

            double estimatedCostSaving,

            ImmutableDictionary<string, string> extendedMetadata,

            string id,

            string importance,

            string name,

            string recommendationId,

            ImmutableArray<Outputs.GetRecommendationsRecommendationCollectionItemResourceCountResult> resourceCounts,

            string state,

            string status,

            ImmutableArray<Outputs.GetRecommendationsRecommendationCollectionItemSupportedLevelResult> supportedLevels,

            string timeCreated,

            string timeStatusBegin,

            string timeStatusEnd,

            string timeUpdated)
        {
            CategoryId = categoryId;
            CompartmentId = compartmentId;
            Description = description;
            EstimatedCostSaving = estimatedCostSaving;
            ExtendedMetadata = extendedMetadata;
            Id = id;
            Importance = importance;
            Name = name;
            RecommendationId = recommendationId;
            ResourceCounts = resourceCounts;
            State = state;
            Status = status;
            SupportedLevels = supportedLevels;
            TimeCreated = timeCreated;
            TimeStatusBegin = timeStatusBegin;
            TimeStatusEnd = timeStatusEnd;
            TimeUpdated = timeUpdated;
        }
    }
}
