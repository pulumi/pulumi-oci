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
    public sealed class TargetDatabaseTlsConfig
    {
        /// <summary>
        /// (Updatable) The format of the certificate store.
        /// </summary>
        public readonly string? CertificateStoreType;
        /// <summary>
        /// (Updatable) Base64 encoded string of key store file content.
        /// </summary>
        public readonly string? KeyStoreContent;
        /// <summary>
        /// (Updatable) Status to represent whether the database connection is TLS enabled or not.
        /// </summary>
        public readonly string Status;
        /// <summary>
        /// (Updatable) The password to read the trust store and key store files, if they are password protected.
        /// </summary>
        public readonly string? StorePassword;
        /// <summary>
        /// (Updatable) Base64 encoded string of trust store file content.
        /// 
        /// 
        /// ** IMPORTANT **
        /// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
        /// </summary>
        public readonly string? TrustStoreContent;

        [OutputConstructor]
        private TargetDatabaseTlsConfig(
            string? certificateStoreType,

            string? keyStoreContent,

            string status,

            string? storePassword,

            string? trustStoreContent)
        {
            CertificateStoreType = certificateStoreType;
            KeyStoreContent = keyStoreContent;
            Status = status;
            StorePassword = storePassword;
            TrustStoreContent = trustStoreContent;
        }
    }
}
