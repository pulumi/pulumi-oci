// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.CapacityManagement.Outputs
{

    [OutputType]
    public sealed class GetOccAvailabilityCatalogOccAvailabilitiesOccAvailabilityCollectionResult
    {
        /// <summary>
        /// An array of capacity constraints.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetOccAvailabilityCatalogOccAvailabilitiesOccAvailabilityCollectionItemResult> Items;

        [OutputConstructor]
        private GetOccAvailabilityCatalogOccAvailabilitiesOccAvailabilityCollectionResult(ImmutableArray<Outputs.GetOccAvailabilityCatalogOccAvailabilitiesOccAvailabilityCollectionItemResult> items)
        {
            Items = items;
        }
    }
}
