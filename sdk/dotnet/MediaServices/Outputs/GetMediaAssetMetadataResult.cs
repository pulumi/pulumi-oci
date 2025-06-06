// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.MediaServices.Outputs
{

    [OutputType]
    public sealed class GetMediaAssetMetadataResult
    {
        /// <summary>
        /// JSON string containing the technial metadata for the media asset.
        /// </summary>
        public readonly string Metadata;

        [OutputConstructor]
        private GetMediaAssetMetadataResult(string metadata)
        {
            Metadata = metadata;
        }
    }
}
