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
    public sealed class GetMaskingReportsMaskingReportCollectionResult
    {
        public readonly ImmutableArray<Outputs.GetMaskingReportsMaskingReportCollectionItemResult> Items;

        [OutputConstructor]
        private GetMaskingReportsMaskingReportCollectionResult(ImmutableArray<Outputs.GetMaskingReportsMaskingReportCollectionItemResult> items)
        {
            Items = items;
        }
    }
}
