// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Database.Inputs
{

    public sealed class DatabaseUpgradeDbBackupConfigBackupDestinationDetailGetArgs : global::Pulumi.ResourceArgs
    {
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the DBRS policy used for backup.
        /// </summary>
        [Input("dbrsPolicyId")]
        public Input<string>? DbrsPolicyId { get; set; }

        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the database.
        /// </summary>
        [Input("id")]
        public Input<string>? Id { get; set; }

        /// <summary>
        /// Proxy URL to connect to object store.
        /// </summary>
        [Input("internetProxy")]
        public Input<string>? InternetProxy { get; set; }

        /// <summary>
        /// Indicates whether the backup destination is cross-region or local region.
        /// </summary>
        [Input("isRemote")]
        public Input<bool>? IsRemote { get; set; }

        /// <summary>
        /// The name of the remote region where the remote automatic incremental backups will be stored.
        /// </summary>
        [Input("remoteRegion")]
        public Input<string>? RemoteRegion { get; set; }

        /// <summary>
        /// Type of the database backup destination.
        /// </summary>
        [Input("type")]
        public Input<string>? Type { get; set; }

        /// <summary>
        /// For a RECOVERY_APPLIANCE backup destination, the password for the VPC user that is used to access the Recovery Appliance.
        /// </summary>
        [Input("vpcPassword")]
        public Input<string>? VpcPassword { get; set; }

        /// <summary>
        /// For a RECOVERY_APPLIANCE backup destination, the Virtual Private Catalog (VPC) user that is used to access the Recovery Appliance.
        /// </summary>
        [Input("vpcUser")]
        public Input<string>? VpcUser { get; set; }

        public DatabaseUpgradeDbBackupConfigBackupDestinationDetailGetArgs()
        {
        }
        public static new DatabaseUpgradeDbBackupConfigBackupDestinationDetailGetArgs Empty => new DatabaseUpgradeDbBackupConfigBackupDestinationDetailGetArgs();
    }
}
