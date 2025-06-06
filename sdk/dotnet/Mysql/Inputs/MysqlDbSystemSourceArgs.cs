// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Mysql.Inputs
{

    public sealed class MysqlDbSystemSourceArgs : global::Pulumi.ResourceArgs
    {
        /// <summary>
        /// The OCID of the backup to be used as the source for the new DB System.
        /// </summary>
        [Input("backupId")]
        public Input<string>? BackupId { get; set; }

        /// <summary>
        /// The OCID of the DB System from which a backup shall be selected to be restored when creating the new DB System. Use this together with recovery point to perform a point in time recovery operation.
        /// </summary>
        [Input("dbSystemId")]
        public Input<string>? DbSystemId { get; set; }

        /// <summary>
        /// The date and time, as per RFC 3339, of the change up to which the new DB System shall be restored to, using a backup and logs from the original DB System. In case no point in time is specified, then this new DB System shall be restored up to the latest change recorded for the original DB System.
        /// </summary>
        [Input("recoveryPoint")]
        public Input<string>? RecoveryPoint { get; set; }

        /// <summary>
        /// The specific source identifier. Use `BACKUP` for creating a new database by restoring from a backup. Use `IMPORTURL` for creating a new database from a URL Object Storage PAR.
        /// </summary>
        [Input("sourceType", required: true)]
        public Input<string> SourceType { get; set; } = null!;

        [Input("sourceUrl")]
        private Input<string>? _sourceUrl;

        /// <summary>
        /// The Pre-Authenticated Request (PAR) of a bucket/prefix or PAR of a @.manifest.json object from the Object Storage. Check [Using Pre-Authenticated Requests](https://docs.oracle.com/en-us/iaas/Content/Object/Tasks/usingpreauthenticatedrequests.htm) for information related to PAR creation. Please create PAR with "Permit object reads" access type and "Enable Object Listing" permission when using a bucket/prefix PAR. Please create PAR with "Permit object reads" access type when using a @.manifest.json object PAR.
        /// </summary>
        public Input<string>? SourceUrl
        {
            get => _sourceUrl;
            set
            {
                var emptySecret = Output.CreateSecret(0);
                _sourceUrl = Output.Tuple<Input<string>?, int>(value, emptySecret).Apply(t => t.Item1);
            }
        }

        public MysqlDbSystemSourceArgs()
        {
        }
        public static new MysqlDbSystemSourceArgs Empty => new MysqlDbSystemSourceArgs();
    }
}
