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
    public sealed class GetApiaccesscontrolApiMetadataByEntityTypesApiMetadataByEntityTypeCollectionResult
    {
        /// <summary>
        /// List of apiMetadataByEntityTypeSummary.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetApiaccesscontrolApiMetadataByEntityTypesApiMetadataByEntityTypeCollectionItemResult> Items;

        [OutputConstructor]
        private GetApiaccesscontrolApiMetadataByEntityTypesApiMetadataByEntityTypeCollectionResult(ImmutableArray<Outputs.GetApiaccesscontrolApiMetadataByEntityTypesApiMetadataByEntityTypeCollectionItemResult> items)
        {
            Items = items;
        }
    }
}
