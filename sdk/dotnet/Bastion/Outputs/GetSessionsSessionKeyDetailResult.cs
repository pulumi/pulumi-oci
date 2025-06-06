// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Bastion.Outputs
{

    [OutputType]
    public sealed class GetSessionsSessionKeyDetailResult
    {
        /// <summary>
        /// The public key in OpenSSH format of the SSH key pair for the session. When you connect to the session, you must provide the private key of the same SSH key pair.
        /// </summary>
        public readonly string PublicKeyContent;

        [OutputConstructor]
        private GetSessionsSessionKeyDetailResult(string publicKeyContent)
        {
            PublicKeyContent = publicKeyContent;
        }
    }
}
