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
    public sealed class GetLibraryMaskingFormatsLibraryMaskingFormatCollectionResult
    {
        public readonly ImmutableArray<Outputs.GetLibraryMaskingFormatsLibraryMaskingFormatCollectionItemResult> Items;

        [OutputConstructor]
        private GetLibraryMaskingFormatsLibraryMaskingFormatCollectionResult(ImmutableArray<Outputs.GetLibraryMaskingFormatsLibraryMaskingFormatCollectionItemResult> items)
        {
            Items = items;
        }
    }
}
