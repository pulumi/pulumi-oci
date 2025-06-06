// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Database.Inputs
{

    public sealed class BackupDestinationAssociatedDatabaseArgs : global::Pulumi.ResourceArgs
    {
        /// <summary>
        /// The display name of the database that is associated with the backup destination.
        /// </summary>
        [Input("dbName")]
        public Input<string>? DbName { get; set; }

        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the backup destination.
        /// </summary>
        [Input("id")]
        public Input<string>? Id { get; set; }

        public BackupDestinationAssociatedDatabaseArgs()
        {
        }
        public static new BackupDestinationAssociatedDatabaseArgs Empty => new BackupDestinationAssociatedDatabaseArgs();
    }
}
