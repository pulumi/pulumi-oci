// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.BigDataService.Inputs
{

    public sealed class AutoScalingConfigurationPolicyRuleMetricArgs : global::Pulumi.ResourceArgs
    {
        /// <summary>
        /// (Updatable) Allowed value is CPU_UTILIZATION.
        /// </summary>
        [Input("metricType", required: true)]
        public Input<string> MetricType { get; set; } = null!;

        /// <summary>
        /// (Updatable) An autoscale action is triggered when a performance metric exceeds a threshold.
        /// </summary>
        [Input("threshold", required: true)]
        public Input<Inputs.AutoScalingConfigurationPolicyRuleMetricThresholdArgs> Threshold { get; set; } = null!;

        public AutoScalingConfigurationPolicyRuleMetricArgs()
        {
        }
        public static new AutoScalingConfigurationPolicyRuleMetricArgs Empty => new AutoScalingConfigurationPolicyRuleMetricArgs();
    }
}