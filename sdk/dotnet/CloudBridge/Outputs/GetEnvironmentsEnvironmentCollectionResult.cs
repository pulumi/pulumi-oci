// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.CloudBridge.Outputs
{

    [OutputType]
    public sealed class GetEnvironmentsEnvironmentCollectionResult
    {
        public readonly ImmutableArray<Outputs.GetEnvironmentsEnvironmentCollectionItemResult> Items;

        [OutputConstructor]
        private GetEnvironmentsEnvironmentCollectionResult(ImmutableArray<Outputs.GetEnvironmentsEnvironmentCollectionItemResult> items)
        {
            Items = items;
        }
    }
}
