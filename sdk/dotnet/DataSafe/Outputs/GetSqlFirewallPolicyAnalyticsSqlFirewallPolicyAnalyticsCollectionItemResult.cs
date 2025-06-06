// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.DataSafe.Outputs
{

    [OutputType]
    public sealed class GetSqlFirewallPolicyAnalyticsSqlFirewallPolicyAnalyticsCollectionItemResult
    {
        /// <summary>
        /// The dimensions available for SQL Firewall policy analytics.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetSqlFirewallPolicyAnalyticsSqlFirewallPolicyAnalyticsCollectionItemDimensionResult> Dimensions;
        /// <summary>
        /// The total count of the aggregated metric.
        /// </summary>
        public readonly string SqlFirewallPolicyAnalyticCount;

        [OutputConstructor]
        private GetSqlFirewallPolicyAnalyticsSqlFirewallPolicyAnalyticsCollectionItemResult(
            ImmutableArray<Outputs.GetSqlFirewallPolicyAnalyticsSqlFirewallPolicyAnalyticsCollectionItemDimensionResult> dimensions,

            string sqlFirewallPolicyAnalyticCount)
        {
            Dimensions = dimensions;
            SqlFirewallPolicyAnalyticCount = sqlFirewallPolicyAnalyticCount;
        }
    }
}
