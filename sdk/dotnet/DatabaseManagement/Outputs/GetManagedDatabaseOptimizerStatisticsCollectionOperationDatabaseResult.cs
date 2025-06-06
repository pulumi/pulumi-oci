// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.DatabaseManagement.Outputs
{

    [OutputType]
    public sealed class GetManagedDatabaseOptimizerStatisticsCollectionOperationDatabaseResult
    {
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment in which the Managed Database resides.
        /// </summary>
        public readonly string CompartmentId;
        /// <summary>
        /// The infrastructure used to deploy the Oracle Database.
        /// </summary>
        public readonly string DbDeploymentType;
        /// <summary>
        /// The subtype of the Oracle Database. Indicates whether the database is a Container Database, Pluggable Database, Non-container Database, Autonomous Database, or Autonomous Container Database.
        /// </summary>
        public readonly string DbSubType;
        /// <summary>
        /// The type of Oracle Database installation.
        /// </summary>
        public readonly string DbType;
        /// <summary>
        /// The version of the Oracle Database.
        /// </summary>
        public readonly string DbVersion;
        /// <summary>
        /// The ID of the operation.
        /// </summary>
        public readonly string Id;
        /// <summary>
        /// The name of the Managed Database.
        /// </summary>
        public readonly string Name;

        [OutputConstructor]
        private GetManagedDatabaseOptimizerStatisticsCollectionOperationDatabaseResult(
            string compartmentId,

            string dbDeploymentType,

            string dbSubType,

            string dbType,

            string dbVersion,

            string id,

            string name)
        {
            CompartmentId = compartmentId;
            DbDeploymentType = dbDeploymentType;
            DbSubType = dbSubType;
            DbType = dbType;
            DbVersion = dbVersion;
            Id = id;
            Name = name;
        }
    }
}
