// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.BigDataService.Inputs
{

    public sealed class AutoScalingConfigurationPolicyDetailsScaleOutConfigMetricGetArgs : global::Pulumi.ResourceArgs
    {
        /// <summary>
        /// (Updatable) Allowed value is CPU_UTILIZATION.
        /// </summary>
        [Input("metricType")]
        public Input<string>? MetricType { get; set; }

        /// <summary>
        /// (Updatable) An autoscale action is triggered when a performance metric exceeds a threshold.
        /// </summary>
        [Input("threshold")]
        public Input<Inputs.AutoScalingConfigurationPolicyDetailsScaleOutConfigMetricThresholdGetArgs>? Threshold { get; set; }

        public AutoScalingConfigurationPolicyDetailsScaleOutConfigMetricGetArgs()
        {
        }
        public static new AutoScalingConfigurationPolicyDetailsScaleOutConfigMetricGetArgs Empty => new AutoScalingConfigurationPolicyDetailsScaleOutConfigMetricGetArgs();
    }
}