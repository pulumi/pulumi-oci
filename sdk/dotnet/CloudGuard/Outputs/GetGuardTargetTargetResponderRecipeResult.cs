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
    public sealed class GetGuardTargetTargetResponderRecipeResult
    {
        /// <summary>
        /// Compartment OCID
        /// </summary>
        public readonly string CompartmentId;
        /// <summary>
        /// Responder rule description
        /// </summary>
        public readonly string Description;
        /// <summary>
        /// Responder rule display name
        /// </summary>
        public readonly string DisplayName;
        /// <summary>
        /// List of currently enabled responder rules for the responder type for recipe after applying defaults
        /// </summary>
        public readonly ImmutableArray<Outputs.GetGuardTargetTargetResponderRecipeEffectiveResponderRuleResult> EffectiveResponderRules;
        /// <summary>
        /// Unique identifier of target responder recipe that can't be changed after creation
        /// </summary>
        public readonly string Id;
        /// <summary>
        /// Owner of target responder recipe
        /// </summary>
        public readonly string Owner;
        /// <summary>
        /// Unique identifier for the Oracle-managed responder recipe from which this recipe was cloned
        /// </summary>
        public readonly string ResponderRecipeId;
        /// <summary>
        /// List of responder rules associated with the recipe - user input
        /// </summary>
        public readonly ImmutableArray<Outputs.GetGuardTargetTargetResponderRecipeResponderRuleResult> ResponderRules;
        /// <summary>
        /// The date and time the target was created. Format defined by RFC3339.
        /// </summary>
        public readonly string TimeCreated;
        /// <summary>
        /// The date and time the target was last updated. Format defined by RFC3339.
        /// </summary>
        public readonly string TimeUpdated;

        [OutputConstructor]
        private GetGuardTargetTargetResponderRecipeResult(
            string compartmentId,

            string description,

            string displayName,

            ImmutableArray<Outputs.GetGuardTargetTargetResponderRecipeEffectiveResponderRuleResult> effectiveResponderRules,

            string id,

            string owner,

            string responderRecipeId,

            ImmutableArray<Outputs.GetGuardTargetTargetResponderRecipeResponderRuleResult> responderRules,

            string timeCreated,

            string timeUpdated)
        {
            CompartmentId = compartmentId;
            Description = description;
            DisplayName = displayName;
            EffectiveResponderRules = effectiveResponderRules;
            Id = id;
            Owner = owner;
            ResponderRecipeId = responderRecipeId;
            ResponderRules = responderRules;
            TimeCreated = timeCreated;
            TimeUpdated = timeUpdated;
        }
    }
}
