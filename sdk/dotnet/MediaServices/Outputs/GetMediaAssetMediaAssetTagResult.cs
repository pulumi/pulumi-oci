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
    public sealed class GetMediaAssetMediaAssetTagResult
    {
        /// <summary>
        /// The type of the media asset.
        /// </summary>
        public readonly string Type;
        /// <summary>
        /// Tag of the MediaAsset.
        /// </summary>
        public readonly string Value;

        [OutputConstructor]
        private GetMediaAssetMediaAssetTagResult(
            string type,

            string value)
        {
            Type = type;
            Value = value;
        }
    }
}
