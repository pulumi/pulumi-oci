// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Oci.Outputs
{

    [OutputType]
    public sealed class GetWlmsWlsDomainScanResultsScanResultCollectionResult
    {
        /// <summary>
        /// List of scan results.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetWlmsWlsDomainScanResultsScanResultCollectionItemResult> Items;

        [OutputConstructor]
        private GetWlmsWlsDomainScanResultsScanResultCollectionResult(ImmutableArray<Outputs.GetWlmsWlsDomainScanResultsScanResultCollectionItemResult> items)
        {
            Items = items;
        }
    }
}
