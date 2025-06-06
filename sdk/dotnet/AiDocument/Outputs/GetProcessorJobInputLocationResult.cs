// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.AiDocument.Outputs
{

    [OutputType]
    public sealed class GetProcessorJobInputLocationResult
    {
        /// <summary>
        /// Raw document data with Base64 encoding.
        /// </summary>
        public readonly string Data;
        /// <summary>
        /// The list of ObjectLocations.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetProcessorJobInputLocationObjectLocationResult> ObjectLocations;
        /// <summary>
        /// The type of input location. The allowed values are:
        /// * `OBJECT_STORAGE_LOCATIONS`: A list of object locations in Object Storage.
        /// * `INLINE_DOCUMENT_CONTENT`: The content of an inline document.
        /// </summary>
        public readonly string SourceType;

        [OutputConstructor]
        private GetProcessorJobInputLocationResult(
            string data,

            ImmutableArray<Outputs.GetProcessorJobInputLocationObjectLocationResult> objectLocations,

            string sourceType)
        {
            Data = data;
            ObjectLocations = objectLocations;
            SourceType = sourceType;
        }
    }
}
