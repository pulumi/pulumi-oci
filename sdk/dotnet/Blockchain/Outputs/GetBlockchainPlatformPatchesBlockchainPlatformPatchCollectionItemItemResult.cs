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
    public sealed class GetBlockchainPlatformPatchesBlockchainPlatformPatchCollectionItemItemResult
    {
        /// <summary>
        /// patch id
        /// </summary>
        public readonly string Id;
        /// <summary>
        /// A URL for the patch specific documentation
        /// </summary>
        public readonly string PatchInfoUrl;
        /// <summary>
        /// patch service version
        /// </summary>
        public readonly string ServiceVersion;
        /// <summary>
        /// patch due date for customer initiated patching
        /// </summary>
        public readonly string TimePatchDue;

        [OutputConstructor]
        private GetBlockchainPlatformPatchesBlockchainPlatformPatchCollectionItemItemResult(
            string id,

            string patchInfoUrl,

            string serviceVersion,

            string timePatchDue)
        {
            Id = id;
            PatchInfoUrl = patchInfoUrl;
            ServiceVersion = serviceVersion;
            TimePatchDue = timePatchDue;
        }
    }
}
