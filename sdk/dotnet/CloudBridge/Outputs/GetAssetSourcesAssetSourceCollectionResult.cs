// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.CloudBridge.Outputs
{

    [OutputType]
    public sealed class GetAssetSourcesAssetSourceCollectionResult
    {
        public readonly ImmutableArray<Outputs.GetAssetSourcesAssetSourceCollectionItemResult> Items;

        [OutputConstructor]
        private GetAssetSourcesAssetSourceCollectionResult(ImmutableArray<Outputs.GetAssetSourcesAssetSourceCollectionItemResult> items)
        {
            Items = items;
        }
    }
}