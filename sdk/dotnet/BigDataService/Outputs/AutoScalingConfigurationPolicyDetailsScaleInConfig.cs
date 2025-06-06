// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.BigDataService.Outputs
{

    [OutputType]
    public sealed class AutoScalingConfigurationPolicyDetailsScaleInConfig
    {
        /// <summary>
        /// (Updatable) Metric and threshold details for triggering an autoscale action.
        /// </summary>
        public readonly Outputs.AutoScalingConfigurationPolicyDetailsScaleInConfigMetric? Metric;
        /// <summary>
        /// (Updatable) This value is the minimum number of nodes the cluster can be scaled-in to.
        /// </summary>
        public readonly int? MinNodeCount;
        /// <summary>
        /// (Updatable) This value is the number of nodes to remove during a scale-in event.
        /// </summary>
        public readonly int? StepSize;

        [OutputConstructor]
        private AutoScalingConfigurationPolicyDetailsScaleInConfig(
            Outputs.AutoScalingConfigurationPolicyDetailsScaleInConfigMetric? metric,

            int? minNodeCount,

            int? stepSize)
        {
            Metric = metric;
            MinNodeCount = minNodeCount;
            StepSize = stepSize;
        }
    }
}
