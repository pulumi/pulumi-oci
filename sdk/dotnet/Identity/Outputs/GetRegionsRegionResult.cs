// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Identity.Outputs
{

    [OutputType]
    public sealed class GetRegionsRegionResult
    {
        /// <summary>
        /// The key of the region. See [Regions and Availability Domains](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/regions.htm) for the full list of supported 3-letter region codes.  Example: `PHX`
        /// </summary>
        public readonly string Key;
        /// <summary>
        /// The name of the region. See [Regions and Availability Domains](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/regions.htm) for the full list of supported region names.  Example: `us-phoenix-1`
        /// </summary>
        public readonly string Name;

        [OutputConstructor]
        private GetRegionsRegionResult(
            string key,

            string name)
        {
            Key = key;
            Name = name;
        }
    }
}
