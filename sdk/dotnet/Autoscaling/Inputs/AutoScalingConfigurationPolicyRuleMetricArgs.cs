// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Autoscaling.Inputs
{

    public sealed class AutoScalingConfigurationPolicyRuleMetricArgs : global::Pulumi.ResourceArgs
    {
        [Input("metricType")]
        public Input<string>? MetricType { get; set; }

        [Input("threshold")]
        public Input<Inputs.AutoScalingConfigurationPolicyRuleMetricThresholdArgs>? Threshold { get; set; }

        public AutoScalingConfigurationPolicyRuleMetricArgs()
        {
        }
        public static new AutoScalingConfigurationPolicyRuleMetricArgs Empty => new AutoScalingConfigurationPolicyRuleMetricArgs();
    }
}
