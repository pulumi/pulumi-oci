// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.ApmSynthetics.Outputs
{

    [OutputType]
    public sealed class ConfigAvailabilityConfiguration
    {
        /// <summary>
        /// (Updatable) Intervals with failed runs more than this value will be classified as UNAVAILABLE.
        /// </summary>
        public readonly int? MaxAllowedFailuresPerInterval;
        /// <summary>
        /// (Updatable) Intervals with runs less than this value will be classified as UNKNOWN and excluded from the availability calculations.
        /// </summary>
        public readonly int? MinAllowedRunsPerInterval;

        [OutputConstructor]
        private ConfigAvailabilityConfiguration(
            int? maxAllowedFailuresPerInterval,

            int? minAllowedRunsPerInterval)
        {
            MaxAllowedFailuresPerInterval = maxAllowedFailuresPerInterval;
            MinAllowedRunsPerInterval = minAllowedRunsPerInterval;
        }
    }
}