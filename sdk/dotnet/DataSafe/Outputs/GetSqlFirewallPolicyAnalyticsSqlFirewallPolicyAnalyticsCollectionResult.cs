// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.DataSafe.Outputs
{

    [OutputType]
    public sealed class GetSqlFirewallPolicyAnalyticsSqlFirewallPolicyAnalyticsCollectionResult
    {
        /// <summary>
        /// The aggregated data point items.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetSqlFirewallPolicyAnalyticsSqlFirewallPolicyAnalyticsCollectionItemResult> Items;

        [OutputConstructor]
        private GetSqlFirewallPolicyAnalyticsSqlFirewallPolicyAnalyticsCollectionResult(ImmutableArray<Outputs.GetSqlFirewallPolicyAnalyticsSqlFirewallPolicyAnalyticsCollectionItemResult> items)
        {
            Items = items;
        }
    }
}
