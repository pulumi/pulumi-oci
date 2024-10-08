// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Opsi.Inputs
{

    public sealed class DatabaseInsightConnectionCredentialDetailsGetArgs : global::Pulumi.ResourceArgs
    {
        /// <summary>
        /// Credential source name that had been added in Management Agent wallet. This is supplied in the External Database Service.
        /// </summary>
        [Input("credentialSourceName")]
        public Input<string>? CredentialSourceName { get; set; }

        /// <summary>
        /// Credential type.
        /// </summary>
        [Input("credentialType")]
        public Input<string>? CredentialType { get; set; }

        /// <summary>
        /// The secret [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) mapping to the database credentials.
        /// </summary>
        [Input("passwordSecretId")]
        public Input<string>? PasswordSecretId { get; set; }

        /// <summary>
        /// database user role.
        /// </summary>
        [Input("role")]
        public Input<string>? Role { get; set; }

        /// <summary>
        /// database user name.
        /// </summary>
        [Input("userName")]
        public Input<string>? UserName { get; set; }

        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Secret where the database keystore contents are stored. This is used for TCPS support in BM/VM/ExaCS cases.
        /// </summary>
        [Input("walletSecretId")]
        public Input<string>? WalletSecretId { get; set; }

        public DatabaseInsightConnectionCredentialDetailsGetArgs()
        {
        }
        public static new DatabaseInsightConnectionCredentialDetailsGetArgs Empty => new DatabaseInsightConnectionCredentialDetailsGetArgs();
    }
}
