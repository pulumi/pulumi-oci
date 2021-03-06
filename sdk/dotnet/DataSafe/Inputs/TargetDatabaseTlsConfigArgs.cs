// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.DataSafe.Inputs
{

    public sealed class TargetDatabaseTlsConfigArgs : Pulumi.ResourceArgs
    {
        /// <summary>
        /// (Updatable) The format of the certificate store.
        /// </summary>
        [Input("certificateStoreType")]
        public Input<string>? CertificateStoreType { get; set; }

        /// <summary>
        /// (Updatable) Base64 encoded string of key store file content.
        /// </summary>
        [Input("keyStoreContent")]
        public Input<string>? KeyStoreContent { get; set; }

        /// <summary>
        /// (Updatable) Status to represent whether the database connection is TLS enabled or not.
        /// </summary>
        [Input("status", required: true)]
        public Input<string> Status { get; set; } = null!;

        /// <summary>
        /// (Updatable) The password to read the trust store and key store files, if they are password protected.
        /// </summary>
        [Input("storePassword")]
        public Input<string>? StorePassword { get; set; }

        /// <summary>
        /// (Updatable) Base64 encoded string of trust store file content.
        /// </summary>
        [Input("trustStoreContent")]
        public Input<string>? TrustStoreContent { get; set; }

        public TargetDatabaseTlsConfigArgs()
        {
        }
    }
}
