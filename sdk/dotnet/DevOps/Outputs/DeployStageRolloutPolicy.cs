// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.DevOps.Outputs
{

    [OutputType]
    public sealed class DeployStageRolloutPolicy
    {
        /// <summary>
        /// (Updatable) The number that will be used to determine how many instances will be deployed concurrently.
        /// </summary>
        public readonly int? BatchCount;
        /// <summary>
        /// (Updatable) The duration of delay between batch rollout. The default delay is 1 minute.
        /// </summary>
        public readonly int? BatchDelayInSeconds;
        /// <summary>
        /// (Updatable) The percentage that will be used to determine how many instances will be deployed concurrently.
        /// </summary>
        public readonly int? BatchPercentage;
        /// <summary>
        /// (Updatable) The type of policy used for rolling out a deployment stage.
        /// </summary>
        public readonly string? PolicyType;
        /// <summary>
        /// (Updatable) Indicates the criteria to stop.
        /// </summary>
        public readonly double? RampLimitPercent;

        [OutputConstructor]
        private DeployStageRolloutPolicy(
            int? batchCount,

            int? batchDelayInSeconds,

            int? batchPercentage,

            string? policyType,

            double? rampLimitPercent)
        {
            BatchCount = batchCount;
            BatchDelayInSeconds = batchDelayInSeconds;
            BatchPercentage = batchPercentage;
            PolicyType = policyType;
            RampLimitPercent = rampLimitPercent;
        }
    }
}