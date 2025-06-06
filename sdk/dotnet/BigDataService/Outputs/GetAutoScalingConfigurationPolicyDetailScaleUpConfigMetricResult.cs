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
    public sealed class GetAutoScalingConfigurationPolicyDetailScaleUpConfigMetricResult
    {
        /// <summary>
        /// Allowed values are CPU_UTILIZATION and MEMORY_UTILIZATION.
        /// </summary>
        public readonly string MetricType;
        /// <summary>
        /// An autoscale action is triggered when a performance metric exceeds a threshold.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetAutoScalingConfigurationPolicyDetailScaleUpConfigMetricThresholdResult> Thresholds;

        [OutputConstructor]
        private GetAutoScalingConfigurationPolicyDetailScaleUpConfigMetricResult(
            string metricType,

            ImmutableArray<Outputs.GetAutoScalingConfigurationPolicyDetailScaleUpConfigMetricThresholdResult> thresholds)
        {
            MetricType = metricType;
            Thresholds = thresholds;
        }
    }
}
