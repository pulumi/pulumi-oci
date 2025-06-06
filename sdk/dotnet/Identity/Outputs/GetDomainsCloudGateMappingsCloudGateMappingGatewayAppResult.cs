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
    public sealed class GetDomainsCloudGateMappingsCloudGateMappingGatewayAppResult
    {
        /// <summary>
        /// The name (Client ID) of the gateway application protected by this Cloud Gate.
        /// </summary>
        public readonly string Name;
        /// <summary>
        /// The URI to the upstream block entry
        /// </summary>
        public readonly string Ref;
        /// <summary>
        /// The id of the upstream block entry.
        /// </summary>
        public readonly string Value;

        [OutputConstructor]
        private GetDomainsCloudGateMappingsCloudGateMappingGatewayAppResult(
            string name,

            string @ref,

            string value)
        {
            Name = name;
            Ref = @ref;
            Value = value;
        }
    }
}
