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
    public sealed class ResponderRecipeEffectiveResponderRuleDetail
    {
        /// <summary>
        /// The base condition resource.
        /// </summary>
        public readonly string? Condition;
        /// <summary>
        /// List of responder rule configurations
        /// </summary>
        public readonly ImmutableArray<Outputs.ResponderRecipeEffectiveResponderRuleDetailConfiguration> Configurations;
        /// <summary>
        /// Enabled state for the responder rule
        /// </summary>
        public readonly bool? IsEnabled;
        /// <summary>
        /// Execution mode for the responder rule
        /// </summary>
        public readonly string? Mode;

        [OutputConstructor]
        private ResponderRecipeEffectiveResponderRuleDetail(
            string? condition,

            ImmutableArray<Outputs.ResponderRecipeEffectiveResponderRuleDetailConfiguration> configurations,

            bool? isEnabled,

            string? mode)
        {
            Condition = condition;
            Configurations = configurations;
            IsEnabled = isEnabled;
            Mode = mode;
        }
    }
}
