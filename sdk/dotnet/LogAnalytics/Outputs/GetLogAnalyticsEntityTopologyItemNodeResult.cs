// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.LogAnalytics.Outputs
{

    [OutputType]
    public sealed class GetLogAnalyticsEntityTopologyItemNodeResult
    {
        /// <summary>
        /// Array of log analytics entity summary.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetLogAnalyticsEntityTopologyItemNodeItemResult> Items;

        [OutputConstructor]
        private GetLogAnalyticsEntityTopologyItemNodeResult(ImmutableArray<Outputs.GetLogAnalyticsEntityTopologyItemNodeItemResult> items)
        {
            Items = items;
        }
    }
}
