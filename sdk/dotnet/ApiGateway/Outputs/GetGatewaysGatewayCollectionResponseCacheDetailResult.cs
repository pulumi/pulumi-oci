// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.ApiGateway.Outputs
{

    [OutputType]
    public sealed class GetGatewaysGatewayCollectionResponseCacheDetailResult
    {
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Oracle Vault Service secret resource.
        /// </summary>
        public readonly string AuthenticationSecretId;
        /// <summary>
        /// The version number of the authentication secret to use.
        /// </summary>
        public readonly string AuthenticationSecretVersionNumber;
        /// <summary>
        /// Defines the timeout for establishing a connection with the Response Cache.
        /// </summary>
        public readonly int ConnectTimeoutInMs;
        /// <summary>
        /// Defines if the connection should be over SSL.
        /// </summary>
        public readonly bool IsSslEnabled;
        /// <summary>
        /// Defines whether or not to uphold SSL verification.
        /// </summary>
        public readonly bool IsSslVerifyDisabled;
        /// <summary>
        /// Defines the timeout for reading data from the Response Cache.
        /// </summary>
        public readonly int ReadTimeoutInMs;
        /// <summary>
        /// Defines the timeout for transmitting data to the Response Cache.
        /// </summary>
        public readonly int SendTimeoutInMs;
        /// <summary>
        /// The set of cache store members to connect to. At present only a single server is supported.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetGatewaysGatewayCollectionResponseCacheDetailServerResult> Servers;
        /// <summary>
        /// Type of the Response Cache.
        /// </summary>
        public readonly string Type;

        [OutputConstructor]
        private GetGatewaysGatewayCollectionResponseCacheDetailResult(
            string authenticationSecretId,

            string authenticationSecretVersionNumber,

            int connectTimeoutInMs,

            bool isSslEnabled,

            bool isSslVerifyDisabled,

            int readTimeoutInMs,

            int sendTimeoutInMs,

            ImmutableArray<Outputs.GetGatewaysGatewayCollectionResponseCacheDetailServerResult> servers,

            string type)
        {
            AuthenticationSecretId = authenticationSecretId;
            AuthenticationSecretVersionNumber = authenticationSecretVersionNumber;
            ConnectTimeoutInMs = connectTimeoutInMs;
            IsSslEnabled = isSslEnabled;
            IsSslVerifyDisabled = isSslVerifyDisabled;
            ReadTimeoutInMs = readTimeoutInMs;
            SendTimeoutInMs = sendTimeoutInMs;
            Servers = servers;
            Type = type;
        }
    }
}
