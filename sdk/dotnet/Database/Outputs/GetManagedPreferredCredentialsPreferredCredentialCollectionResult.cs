// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Database.Outputs
{

    [OutputType]
    public sealed class GetManagedPreferredCredentialsPreferredCredentialCollectionResult
    {
        public readonly ImmutableArray<Outputs.GetManagedPreferredCredentialsPreferredCredentialCollectionItemResult> Items;

        [OutputConstructor]
        private GetManagedPreferredCredentialsPreferredCredentialCollectionResult(ImmutableArray<Outputs.GetManagedPreferredCredentialsPreferredCredentialCollectionItemResult> items)
        {
            Items = items;
        }
    }
}