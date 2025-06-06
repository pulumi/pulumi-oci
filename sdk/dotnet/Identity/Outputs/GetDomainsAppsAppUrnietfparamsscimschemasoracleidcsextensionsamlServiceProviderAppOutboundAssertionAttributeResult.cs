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
    public sealed class GetDomainsAppsAppUrnietfparamsscimschemasoracleidcsextensionsamlServiceProviderAppOutboundAssertionAttributeResult
    {
        /// <summary>
        /// Mapped Attribute Direction
        /// </summary>
        public readonly string Direction;
        /// <summary>
        /// URI of the AppRole.
        /// </summary>
        public readonly string Ref;
        /// <summary>
        /// ID of the AppRole.
        /// </summary>
        public readonly string Value;

        [OutputConstructor]
        private GetDomainsAppsAppUrnietfparamsscimschemasoracleidcsextensionsamlServiceProviderAppOutboundAssertionAttributeResult(
            string direction,

            string @ref,

            string value)
        {
            Direction = direction;
            Ref = @ref;
            Value = value;
        }
    }
}
