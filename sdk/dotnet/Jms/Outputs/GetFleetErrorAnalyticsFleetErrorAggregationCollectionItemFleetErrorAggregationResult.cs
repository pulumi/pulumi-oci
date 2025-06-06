// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Jms.Outputs
{

    [OutputType]
    public sealed class GetFleetErrorAnalyticsFleetErrorAggregationCollectionItemFleetErrorAggregationResult
    {
        /// <summary>
        /// Number of FleetErrors encountered for the specific reason.
        /// </summary>
        public readonly int FleetErrorAnalyticCount;
        /// <summary>
        /// Enum that uniquely identifies the fleet error.
        /// </summary>
        public readonly string Reason;

        [OutputConstructor]
        private GetFleetErrorAnalyticsFleetErrorAggregationCollectionItemFleetErrorAggregationResult(
            int fleetErrorAnalyticCount,

            string reason)
        {
            FleetErrorAnalyticCount = fleetErrorAnalyticCount;
            Reason = reason;
        }
    }
}
