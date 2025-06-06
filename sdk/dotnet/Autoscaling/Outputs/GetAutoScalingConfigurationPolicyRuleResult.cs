// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Autoscaling.Outputs
{

    [OutputType]
    public sealed class GetAutoScalingConfigurationPolicyRuleResult
    {
        /// <summary>
        /// The action to take when autoscaling is triggered.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetAutoScalingConfigurationPolicyRuleActionResult> Actions;
        /// <summary>
        /// A user-friendly name. Does not have to be unique, and it's changeable. Avoid entering confidential information.
        /// </summary>
        public readonly string DisplayName;
        /// <summary>
        /// ID of the condition that is assigned after creation.
        /// </summary>
        public readonly string Id;
        /// <summary>
        /// Metric and threshold details for triggering an autoscaling action.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetAutoScalingConfigurationPolicyRuleMetricResult> Metrics;

        [OutputConstructor]
        private GetAutoScalingConfigurationPolicyRuleResult(
            ImmutableArray<Outputs.GetAutoScalingConfigurationPolicyRuleActionResult> actions,

            string displayName,

            string id,

            ImmutableArray<Outputs.GetAutoScalingConfigurationPolicyRuleMetricResult> metrics)
        {
            Actions = actions;
            DisplayName = displayName;
            Id = id;
            Metrics = metrics;
        }
    }
}
