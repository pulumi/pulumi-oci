// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.DatabaseManagement.Outputs
{

    [OutputType]
    public sealed class GetJobExecutionsStatusesJobExecutionsStatusSummaryCollectionResult
    {
        /// <summary>
        /// A list of JobExecutionsSummary objects.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetJobExecutionsStatusesJobExecutionsStatusSummaryCollectionItemResult> Items;

        [OutputConstructor]
        private GetJobExecutionsStatusesJobExecutionsStatusSummaryCollectionResult(ImmutableArray<Outputs.GetJobExecutionsStatusesJobExecutionsStatusSummaryCollectionItemResult> items)
        {
            Items = items;
        }
    }
}
