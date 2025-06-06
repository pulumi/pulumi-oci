// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Core.Outputs
{

    [OutputType]
    public sealed class CrossConnectGroupMacsecPropertiesPrimaryKey
    {
        /// <summary>
        /// (Updatable) Secret [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) containing the Connectivity Association Key (CAK) of this MACsec key.
        /// </summary>
        public readonly string ConnectivityAssociationKeySecretId;
        /// <summary>
        /// (Updatable) The secret version of the `connectivity_association_key_secret_id` secret in Vault.
        /// 
        /// NOTE: Only the latest secret version will be used.
        /// </summary>
        public readonly string? ConnectivityAssociationKeySecretVersion;
        /// <summary>
        /// (Updatable) Secret [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) containing the Connectivity association Key Name (CKN) of this MACsec key.
        /// </summary>
        public readonly string ConnectivityAssociationNameSecretId;
        /// <summary>
        /// (Updatable) The secret version of the `connectivity_association_name_secret_id` secret in Vault.
        /// 
        /// NOTE: Only the latest secret version will be used.
        /// </summary>
        public readonly string? ConnectivityAssociationNameSecretVersion;

        [OutputConstructor]
        private CrossConnectGroupMacsecPropertiesPrimaryKey(
            string connectivityAssociationKeySecretId,

            string? connectivityAssociationKeySecretVersion,

            string connectivityAssociationNameSecretId,

            string? connectivityAssociationNameSecretVersion)
        {
            ConnectivityAssociationKeySecretId = connectivityAssociationKeySecretId;
            ConnectivityAssociationKeySecretVersion = connectivityAssociationKeySecretVersion;
            ConnectivityAssociationNameSecretId = connectivityAssociationNameSecretId;
            ConnectivityAssociationNameSecretVersion = connectivityAssociationNameSecretVersion;
        }
    }
}
