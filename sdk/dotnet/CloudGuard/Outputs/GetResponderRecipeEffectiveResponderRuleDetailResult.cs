// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.CloudGuard.Outputs
{

    [OutputType]
    public sealed class GetResponderRecipeEffectiveResponderRuleDetailResult
    {
        public readonly string Condition;
        /// <summary>
        /// ResponderRule configurations
        /// </summary>
        public readonly ImmutableArray<Outputs.GetResponderRecipeEffectiveResponderRuleDetailConfigurationResult> Configurations;
        /// <summary>
        /// Identifies state for ResponderRule
        /// </summary>
        public readonly bool IsEnabled;
        /// <summary>
        /// Execution Mode for ResponderRule
        /// </summary>
        public readonly string Mode;

        [OutputConstructor]
        private GetResponderRecipeEffectiveResponderRuleDetailResult(
            string condition,

            ImmutableArray<Outputs.GetResponderRecipeEffectiveResponderRuleDetailConfigurationResult> configurations,

            bool isEnabled,

            string mode)
        {
            Condition = condition;
            Configurations = configurations;
            IsEnabled = isEnabled;
            Mode = mode;
        }
    }
}
