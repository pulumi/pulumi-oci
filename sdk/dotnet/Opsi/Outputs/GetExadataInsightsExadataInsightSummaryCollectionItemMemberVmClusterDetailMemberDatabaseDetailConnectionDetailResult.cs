// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Opsi.Outputs
{

    [OutputType]
    public sealed class GetExadataInsightsExadataInsightSummaryCollectionItemMemberVmClusterDetailMemberDatabaseDetailConnectionDetailResult
    {
        public readonly ImmutableArray<Outputs.GetExadataInsightsExadataInsightSummaryCollectionItemMemberVmClusterDetailMemberDatabaseDetailConnectionDetailHostResult> Hosts;
        public readonly string Protocol;
        public readonly string ServiceName;

        [OutputConstructor]
        private GetExadataInsightsExadataInsightSummaryCollectionItemMemberVmClusterDetailMemberDatabaseDetailConnectionDetailResult(
            ImmutableArray<Outputs.GetExadataInsightsExadataInsightSummaryCollectionItemMemberVmClusterDetailMemberDatabaseDetailConnectionDetailHostResult> hosts,

            string protocol,

            string serviceName)
        {
            Hosts = hosts;
            Protocol = protocol;
            ServiceName = serviceName;
        }
    }
}