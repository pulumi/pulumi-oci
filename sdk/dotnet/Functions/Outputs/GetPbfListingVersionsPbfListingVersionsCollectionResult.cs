// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Functions.Outputs
{

    [OutputType]
    public sealed class GetPbfListingVersionsPbfListingVersionsCollectionResult
    {
        /// <summary>
        /// List of PbfListingVersionSummary.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetPbfListingVersionsPbfListingVersionsCollectionItemResult> Items;

        [OutputConstructor]
        private GetPbfListingVersionsPbfListingVersionsCollectionResult(ImmutableArray<Outputs.GetPbfListingVersionsPbfListingVersionsCollectionItemResult> items)
        {
            Items = items;
        }
    }
}