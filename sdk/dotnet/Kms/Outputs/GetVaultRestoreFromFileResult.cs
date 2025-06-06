// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Kms.Outputs
{

    [OutputType]
    public sealed class GetVaultRestoreFromFileResult
    {
        /// <summary>
        /// content length of vault's backup binary file
        /// </summary>
        public readonly string ContentLength;
        /// <summary>
        /// content md5 hashed value of vault's backup file
        /// </summary>
        public readonly string ContentMd5;
        /// <summary>
        /// Vault backup file content
        /// </summary>
        public readonly string RestoreVaultFromFileDetails;

        [OutputConstructor]
        private GetVaultRestoreFromFileResult(
            string contentLength,

            string contentMd5,

            string restoreVaultFromFileDetails)
        {
            ContentLength = contentLength;
            ContentMd5 = contentMd5;
            RestoreVaultFromFileDetails = restoreVaultFromFileDetails;
        }
    }
}
