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
    public sealed class GetCompatibleFormatsForSensitiveTypeFormatsForSensitiveTypeResult
    {
        /// <summary>
        /// An array of the library masking formats compatible with the sensitive type.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetCompatibleFormatsForSensitiveTypeFormatsForSensitiveTypeMaskingFormatResult> MaskingFormats;
        /// <summary>
        /// The OCID of the sensitive type.
        /// </summary>
        public readonly string SensitiveTypeId;

        [OutputConstructor]
        private GetCompatibleFormatsForSensitiveTypeFormatsForSensitiveTypeResult(
            ImmutableArray<Outputs.GetCompatibleFormatsForSensitiveTypeFormatsForSensitiveTypeMaskingFormatResult> maskingFormats,

            string sensitiveTypeId)
        {
            MaskingFormats = maskingFormats;
            SensitiveTypeId = sensitiveTypeId;
        }
    }
}
