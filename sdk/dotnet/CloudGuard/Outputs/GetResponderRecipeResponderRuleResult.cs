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
    public sealed class GetResponderRecipeResponderRuleResult
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
        /// Detailed information for a responder rule
        /// </summary>
        public readonly ImmutableArray<Outputs.GetResponderRecipeResponderRuleDetailResult> Details;
        /// <summary>
        /// Responder rule display name
        /// </summary>
        public readonly string DisplayName;
        /// <summary>
        /// A message describing the current state in more detail. For example, can be used to provide actionable information for a resource in Failed state.
        /// </summary>
        public readonly string LifecycleDetails;
        /// <summary>
        /// List of policies
        /// </summary>
        public readonly ImmutableArray<string> Policies;
        /// <summary>
        /// Unique identifier for the responder rule
        /// </summary>
        public readonly string ResponderRuleId;
        /// <summary>
        /// The current lifecycle state of the example
        /// </summary>
        public readonly string State;
        /// <summary>
        /// Supported execution modes for the responder rule
        /// </summary>
        public readonly ImmutableArray<string> SupportedModes;
        /// <summary>
        /// The date and time the responder recipe was created. Format defined by RFC3339.
        /// </summary>
        public readonly string TimeCreated;
        /// <summary>
        /// The date and time the responder recipe was last updated. Format defined by RFC3339.
        /// </summary>
        public readonly string TimeUpdated;
        /// <summary>
        /// Type of responder
        /// </summary>
        public readonly string Type;

        [OutputConstructor]
        private GetResponderRecipeResponderRuleResult(
            string compartmentId,

            string description,

            ImmutableArray<Outputs.GetResponderRecipeResponderRuleDetailResult> details,

            string displayName,

            string lifecycleDetails,

            ImmutableArray<string> policies,

            string responderRuleId,

            string state,

            ImmutableArray<string> supportedModes,

            string timeCreated,

            string timeUpdated,

            string type)
        {
            CompartmentId = compartmentId;
            Description = description;
            Details = details;
            DisplayName = displayName;
            LifecycleDetails = lifecycleDetails;
            Policies = policies;
            ResponderRuleId = responderRuleId;
            State = state;
            SupportedModes = supportedModes;
            TimeCreated = timeCreated;
            TimeUpdated = timeUpdated;
            Type = type;
        }
    }
}
