// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.UsageProxy.Outputs
{

    [OutputType]
    public sealed class GetResourcesResourcesCollectionResult
    {
        /// <summary>
        /// The list of resource details for a service.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetResourcesResourcesCollectionItemResult> Items;

        [OutputConstructor]
        private GetResourcesResourcesCollectionResult(ImmutableArray<Outputs.GetResourcesResourcesCollectionItemResult> items)
        {
            Items = items;
        }
    }
}