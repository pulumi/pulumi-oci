// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Tenantmanagercontrolplane.Outputs
{

    [OutputType]
    public sealed class GetSubscriptionMappingsSubscriptionMappingCollectionResult
    {
        public readonly ImmutableArray<Outputs.GetSubscriptionMappingsSubscriptionMappingCollectionItemResult> Items;

        [OutputConstructor]
        private GetSubscriptionMappingsSubscriptionMappingCollectionResult(ImmutableArray<Outputs.GetSubscriptionMappingsSubscriptionMappingCollectionItemResult> items)
        {
            Items = items;
        }
    }
}
