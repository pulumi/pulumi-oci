// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Opa.Outputs
{

    [OutputType]
    public sealed class GetOpaInstancesOpaInstanceCollectionResult
    {
        public readonly ImmutableArray<Outputs.GetOpaInstancesOpaInstanceCollectionItemResult> Items;

        [OutputConstructor]
        private GetOpaInstancesOpaInstanceCollectionResult(ImmutableArray<Outputs.GetOpaInstancesOpaInstanceCollectionItemResult> items)
        {
            Items = items;
        }
    }
}