// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.CapacityManagement.Outputs
{

    [OutputType]
    public sealed class GetInternalOccmDemandSignalCatalogResourcesInternalOccmDemandSignalCatalogResourceCollectionItemResourcePropertyResult
    {
        /// <summary>
        /// An array of items containing detailed information about a resource's property dependecies.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetInternalOccmDemandSignalCatalogResourcesInternalOccmDemandSignalCatalogResourceCollectionItemResourcePropertyItemResult> Items;

        [OutputConstructor]
        private GetInternalOccmDemandSignalCatalogResourcesInternalOccmDemandSignalCatalogResourceCollectionItemResourcePropertyResult(ImmutableArray<Outputs.GetInternalOccmDemandSignalCatalogResourcesInternalOccmDemandSignalCatalogResourceCollectionItemResourcePropertyItemResult> items)
        {
            Items = items;
        }
    }
}
