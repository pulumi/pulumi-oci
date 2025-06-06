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
    public sealed class GetDomainsMyAppsMyAppOwnerResult
    {
        /// <summary>
        /// User display name
        /// </summary>
        public readonly string Display;
        /// <summary>
        /// UserWalletArtifact URI
        /// </summary>
        public readonly string Ref;
        /// <summary>
        /// UserWalletArtifact identifier
        /// </summary>
        public readonly string Value;

        [OutputConstructor]
        private GetDomainsMyAppsMyAppOwnerResult(
            string display,

            string @ref,

            string value)
        {
            Display = display;
            Ref = @ref;
            Value = value;
        }
    }
}
