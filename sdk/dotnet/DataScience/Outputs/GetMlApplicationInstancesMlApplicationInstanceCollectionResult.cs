// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.DataScience.Outputs
{

    [OutputType]
    public sealed class GetMlApplicationInstancesMlApplicationInstanceCollectionResult
    {
        public readonly ImmutableArray<Outputs.GetMlApplicationInstancesMlApplicationInstanceCollectionItemResult> Items;

        [OutputConstructor]
        private GetMlApplicationInstancesMlApplicationInstanceCollectionResult(ImmutableArray<Outputs.GetMlApplicationInstancesMlApplicationInstanceCollectionItemResult> items)
        {
            Items = items;
        }
    }
}
