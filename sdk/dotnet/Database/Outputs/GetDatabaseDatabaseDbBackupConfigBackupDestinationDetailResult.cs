// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Database.Outputs
{

    [OutputType]
    public sealed class GetDatabaseDatabaseDbBackupConfigBackupDestinationDetailResult
    {
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the database.
        /// </summary>
        public readonly string Id;
        /// <summary>
        /// Type of the database backup destination.
        /// </summary>
        public readonly string Type;
        public readonly string VpcUser;

        [OutputConstructor]
        private GetDatabaseDatabaseDbBackupConfigBackupDestinationDetailResult(
            string id,

            string type,

            string vpcUser)
        {
            Id = id;
            Type = type;
            VpcUser = vpcUser;
        }
    }
}