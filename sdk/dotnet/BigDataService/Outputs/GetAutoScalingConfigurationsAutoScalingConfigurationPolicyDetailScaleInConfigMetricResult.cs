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
    public sealed class GetAutoScalingConfigurationsAutoScalingConfigurationPolicyDetailScaleInConfigMetricResult
    {
        public readonly string MetricType;
        public readonly ImmutableArray<Outputs.GetAutoScalingConfigurationsAutoScalingConfigurationPolicyDetailScaleInConfigMetricThresholdResult> Thresholds;

        [OutputConstructor]
        private GetAutoScalingConfigurationsAutoScalingConfigurationPolicyDetailScaleInConfigMetricResult(
            string metricType,

            ImmutableArray<Outputs.GetAutoScalingConfigurationsAutoScalingConfigurationPolicyDetailScaleInConfigMetricThresholdResult> thresholds)
        {
            MetricType = metricType;
            Thresholds = thresholds;
        }
    }
}
