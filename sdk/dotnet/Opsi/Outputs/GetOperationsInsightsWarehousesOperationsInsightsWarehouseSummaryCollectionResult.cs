// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Opsi.Outputs
{

    [OutputType]
    public sealed class GetOperationsInsightsWarehousesOperationsInsightsWarehouseSummaryCollectionResult
    {
        public readonly ImmutableArray<Outputs.GetOperationsInsightsWarehousesOperationsInsightsWarehouseSummaryCollectionItemResult> Items;

        [OutputConstructor]
        private GetOperationsInsightsWarehousesOperationsInsightsWarehouseSummaryCollectionResult(ImmutableArray<Outputs.GetOperationsInsightsWarehousesOperationsInsightsWarehouseSummaryCollectionItemResult> items)
        {
            Items = items;
        }
    }
}