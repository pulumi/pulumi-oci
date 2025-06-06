// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Mysql.Inputs
{

    public sealed class MysqlBackupDbSystemSnapshotDataStorageArgs : global::Pulumi.ResourceArgs
    {
        /// <summary>
        /// The actual allocated storage size for the DB System. This may be higher than dataStorageSizeInGBs if an automatic storage expansion has occurred.
        /// </summary>
        [Input("allocatedStorageSizeInGbs")]
        public Input<int>? AllocatedStorageSizeInGbs { get; set; }

        /// <summary>
        /// DEPRECATED: User specified size of the data volume. May be less than current allocatedStorageSizeInGBs. Replaced by dataStorage.dataStorageSizeInGBs.
        /// </summary>
        [Input("dataStorageSizeInGb")]
        public Input<int>? DataStorageSizeInGb { get; set; }

        /// <summary>
        /// The absolute limit the DB System's storage size may ever expand to, either manually or automatically. This limit is based based on the initial dataStorageSizeInGBs when the DB System was first created. Both dataStorageSizeInGBs and maxDataStorageSizeInGBs can not exceed this value.
        /// </summary>
        [Input("dataStorageSizeLimitInGbs")]
        public Input<int>? DataStorageSizeLimitInGbs { get; set; }

        /// <summary>
        /// Enable/disable automatic storage expansion. When set to true, the DB System will automatically add storage incrementally up to the value specified in maxStorageSizeInGBs.
        /// </summary>
        [Input("isAutoExpandStorageEnabled")]
        public Input<bool>? IsAutoExpandStorageEnabled { get; set; }

        /// <summary>
        /// Maximum storage size this DB System can expand to. When isAutoExpandStorageEnabled is set to true, the DB System will add storage incrementally up to this value.
        /// </summary>
        [Input("maxStorageSizeInGbs")]
        public Input<int>? MaxStorageSizeInGbs { get; set; }

        public MysqlBackupDbSystemSnapshotDataStorageArgs()
        {
        }
        public static new MysqlBackupDbSystemSnapshotDataStorageArgs Empty => new MysqlBackupDbSystemSnapshotDataStorageArgs();
    }
}
