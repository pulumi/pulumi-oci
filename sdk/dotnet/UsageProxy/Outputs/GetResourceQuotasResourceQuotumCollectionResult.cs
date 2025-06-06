// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.UsageProxy.Outputs
{

    [OutputType]
    public sealed class GetResourceQuotasResourceQuotumCollectionResult
    {
        /// <summary>
        /// Used to indicate if further quota consumption isAllowed.
        /// </summary>
        public readonly bool IsAllowed;
        /// <summary>
        /// The list of resource quota details.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetResourceQuotasResourceQuotumCollectionItemResult> Items;

        [OutputConstructor]
        private GetResourceQuotasResourceQuotumCollectionResult(
            bool isAllowed,

            ImmutableArray<Outputs.GetResourceQuotasResourceQuotumCollectionItemResult> items)
        {
            IsAllowed = isAllowed;
            Items = items;
        }
    }
}
