// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Blockchain.Outputs
{

    [OutputType]
    public sealed class GetBlockchainPlatformPatchesBlockchainPlatformPatchCollectionItemResult
    {
        /// <summary>
        /// Collection of PatchSummary
        /// </summary>
        public readonly ImmutableArray<Outputs.GetBlockchainPlatformPatchesBlockchainPlatformPatchCollectionItemItemResult> Items;

        [OutputConstructor]
        private GetBlockchainPlatformPatchesBlockchainPlatformPatchCollectionItemResult(ImmutableArray<Outputs.GetBlockchainPlatformPatchesBlockchainPlatformPatchCollectionItemItemResult> items)
        {
            Items = items;
        }
    }
}
