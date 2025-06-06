// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Mysql.Inputs
{

    public sealed class MysqlDbSystemBackupPolicyCopyPolicyArgs : global::Pulumi.ResourceArgs
    {
        /// <summary>
        /// (Updatable) Number of days to retain the copied DB system backup.
        /// </summary>
        [Input("backupCopyRetentionInDays")]
        public Input<int>? BackupCopyRetentionInDays { get; set; }

        /// <summary>
        /// (Updatable) The destination region name to which the DB system backup will be copied.
        /// </summary>
        [Input("copyToRegion", required: true)]
        public Input<string> CopyToRegion { get; set; } = null!;

        public MysqlDbSystemBackupPolicyCopyPolicyArgs()
        {
        }
        public static new MysqlDbSystemBackupPolicyCopyPolicyArgs Empty => new MysqlDbSystemBackupPolicyCopyPolicyArgs();
    }
}
