// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Waf.Outputs
{

    [OutputType]
    public sealed class GetProtectionCapabilitiesProtectionCapabilityCollectionResult
    {
        /// <summary>
        /// List of protection capabilities.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetProtectionCapabilitiesProtectionCapabilityCollectionItemResult> Items;

        [OutputConstructor]
        private GetProtectionCapabilitiesProtectionCapabilityCollectionResult(ImmutableArray<Outputs.GetProtectionCapabilitiesProtectionCapabilityCollectionItemResult> items)
        {
            Items = items;
        }
    }
}
