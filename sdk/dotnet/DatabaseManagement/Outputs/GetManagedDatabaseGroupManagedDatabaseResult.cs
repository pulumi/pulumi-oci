// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.DatabaseManagement.Outputs
{

    [OutputType]
    public sealed class GetManagedDatabaseGroupManagedDatabaseResult
    {
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment in which the Managed Database resides.
        /// </summary>
        public readonly string CompartmentId;
        /// <summary>
        /// The subtype of the Oracle Database. Indicates whether the database is a Container Database, Pluggable Database, Non-container Database, Autonomous Database, or Autonomous Container Database.
        /// </summary>
        public readonly string DatabaseSubType;
        /// <summary>
        /// The type of Oracle Database installation.
        /// </summary>
        public readonly string DatabaseType;
        /// <summary>
        /// The infrastructure used to deploy the Oracle Database.
        /// </summary>
        public readonly string DeploymentType;
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Managed Database.
        /// </summary>
        public readonly string Id;
        /// <summary>
        /// The name of the Managed Database Group.
        /// </summary>
        public readonly string Name;
        /// <summary>
        /// The date and time the Managed Database was added to the group.
        /// </summary>
        public readonly string TimeAdded;
        /// <summary>
        /// The workload type of the Autonomous Database.
        /// </summary>
        public readonly string WorkloadType;

        [OutputConstructor]
        private GetManagedDatabaseGroupManagedDatabaseResult(
            string compartmentId,

            string databaseSubType,

            string databaseType,

            string deploymentType,

            string id,

            string name,

            string timeAdded,

            string workloadType)
        {
            CompartmentId = compartmentId;
            DatabaseSubType = databaseSubType;
            DatabaseType = databaseType;
            DeploymentType = deploymentType;
            Id = id;
            Name = name;
            TimeAdded = timeAdded;
            WorkloadType = workloadType;
        }
    }
}
