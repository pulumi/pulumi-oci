// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.DataSafe.Outputs
{

    [OutputType]
    public sealed class GetAuditProfilesAuditProfileCollectionResult
    {
        public readonly ImmutableArray<Outputs.GetAuditProfilesAuditProfileCollectionItemResult> Items;

        [OutputConstructor]
        private GetAuditProfilesAuditProfileCollectionResult(ImmutableArray<Outputs.GetAuditProfilesAuditProfileCollectionItemResult> items)
        {
            Items = items;
        }
    }
}
