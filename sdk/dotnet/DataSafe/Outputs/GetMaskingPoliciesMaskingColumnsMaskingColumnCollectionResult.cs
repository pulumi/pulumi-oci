// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.DataSafe.Outputs
{

    [OutputType]
    public sealed class GetMaskingPoliciesMaskingColumnsMaskingColumnCollectionResult
    {
        public readonly ImmutableArray<Outputs.GetMaskingPoliciesMaskingColumnsMaskingColumnCollectionItemResult> Items;

        [OutputConstructor]
        private GetMaskingPoliciesMaskingColumnsMaskingColumnCollectionResult(ImmutableArray<Outputs.GetMaskingPoliciesMaskingColumnsMaskingColumnCollectionItemResult> items)
        {
            Items = items;
        }
    }
}