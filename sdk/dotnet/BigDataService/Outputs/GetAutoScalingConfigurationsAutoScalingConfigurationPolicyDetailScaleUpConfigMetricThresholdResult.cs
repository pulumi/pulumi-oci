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
    public sealed class GetAutoScalingConfigurationsAutoScalingConfigurationPolicyDetailScaleUpConfigMetricThresholdResult
    {
        public readonly int DurationInMinutes;
        public readonly string Operator;
        public readonly int Value;

        [OutputConstructor]
        private GetAutoScalingConfigurationsAutoScalingConfigurationPolicyDetailScaleUpConfigMetricThresholdResult(
            int durationInMinutes,

            string @operator,

            int value)
        {
            DurationInMinutes = durationInMinutes;
            Operator = @operator;
            Value = value;
        }
    }
}
