// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.OsManagementHub.Outputs
{

    [OutputType]
    public sealed class GetProfilesProfileCollectionResult
    {
        public readonly ImmutableArray<Outputs.GetProfilesProfileCollectionItemResult> Items;

        [OutputConstructor]
        private GetProfilesProfileCollectionResult(ImmutableArray<Outputs.GetProfilesProfileCollectionItemResult> items)
        {
            Items = items;
        }
    }
}
