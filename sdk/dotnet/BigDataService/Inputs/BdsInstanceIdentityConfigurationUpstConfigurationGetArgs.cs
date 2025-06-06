// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.BigDataService.Inputs
{

    public sealed class BdsInstanceIdentityConfigurationUpstConfigurationGetArgs : global::Pulumi.ResourceArgs
    {
        /// <summary>
        /// The kerberos keytab content used for creating identity propagation trust config, in base64 format
        /// </summary>
        [Input("keytabContent")]
        public Input<string>? KeytabContent { get; set; }

        /// <summary>
        /// Master Encryption key used for encrypting token exchange keytab.
        /// </summary>
        [Input("masterEncryptionKeyId")]
        public Input<string>? MasterEncryptionKeyId { get; set; }

        /// <summary>
        /// Secret ID for token exchange keytab
        /// </summary>
        [Input("secretId")]
        public Input<string>? SecretId { get; set; }

        /// <summary>
        /// Lifecycle state of the UPST config
        /// </summary>
        [Input("state")]
        public Input<string>? State { get; set; }

        /// <summary>
        /// Time when this UPST config was created, shown as an RFC 3339 formatted datetime string.
        /// </summary>
        [Input("timeCreated")]
        public Input<string>? TimeCreated { get; set; }

        /// <summary>
        /// Time when the keytab for token exchange principal is last refreshed, shown as an RFC 3339 formatted datetime string.
        /// </summary>
        [Input("timeTokenExchangeKeytabLastRefreshed")]
        public Input<string>? TimeTokenExchangeKeytabLastRefreshed { get; set; }

        /// <summary>
        /// Time when this UPST config was updated, shown as an RFC 3339 formatted datetime string.
        /// </summary>
        [Input("timeUpdated")]
        public Input<string>? TimeUpdated { get; set; }

        /// <summary>
        /// Token exchange kerberos Principal name in cluster
        /// </summary>
        [Input("tokenExchangePrincipalName")]
        public Input<string>? TokenExchangePrincipalName { get; set; }

        /// <summary>
        /// The instance OCID of the node, which is the resource from which the node backup was acquired.
        /// </summary>
        [Input("vaultId")]
        public Input<string>? VaultId { get; set; }

        public BdsInstanceIdentityConfigurationUpstConfigurationGetArgs()
        {
        }
        public static new BdsInstanceIdentityConfigurationUpstConfigurationGetArgs Empty => new BdsInstanceIdentityConfigurationUpstConfigurationGetArgs();
    }
}
