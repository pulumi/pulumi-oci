// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.FleetAppsManagement.Outputs
{

    [OutputType]
    public sealed class GetFleetProductsFleetProductCollectionResult
    {
        /// <summary>
        /// List of fleetProducts.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetFleetProductsFleetProductCollectionItemResult> Items;

        [OutputConstructor]
        private GetFleetProductsFleetProductCollectionResult(ImmutableArray<Outputs.GetFleetProductsFleetProductCollectionItemResult> items)
        {
            Items = items;
        }
    }
}
