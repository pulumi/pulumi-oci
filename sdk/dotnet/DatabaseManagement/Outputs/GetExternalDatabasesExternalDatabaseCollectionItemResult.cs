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
    public sealed class GetExternalDatabasesExternalDatabaseCollectionItemResult
    {
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
        /// </summary>
        public readonly string CompartmentId;
        /// <summary>
        /// The subtype of Oracle Database. Indicates whether the database is a Container Database, Pluggable Database, or Non-container Database.
        /// </summary>
        public readonly string DatabaseSubType;
        /// <summary>
        /// The type of Oracle Database installation.
        /// </summary>
        public readonly string DatabaseType;
        /// <summary>
        /// The configuration of the Database Management service.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetExternalDatabasesExternalDatabaseCollectionItemDbManagementConfigResult> DbManagementConfigs;
        /// <summary>
        /// The basic information about an external DB system.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetExternalDatabasesExternalDatabaseCollectionItemDbSystemInfoResult> DbSystemInfos;
        /// <summary>
        /// The `DB_UNIQUE_NAME` of the external database.
        /// </summary>
        public readonly string DbUniqueName;
        /// <summary>
        /// A filter to only return the resources that match the entire display name.
        /// </summary>
        public readonly string DisplayName;
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the parent Container Database (CDB) if this is a Pluggable Database (PDB).
        /// </summary>
        public readonly string ExternalContainerDatabaseId;
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the external DB home.
        /// </summary>
        public readonly string ExternalDbHomeId;
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the external DB system.
        /// </summary>
        public readonly string Id;
        /// <summary>
        /// The list of database instances if the database is a RAC database.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetExternalDatabasesExternalDatabaseCollectionItemInstanceDetailResult> InstanceDetails;
        /// <summary>
        /// The current lifecycle state of the external database resource.
        /// </summary>
        public readonly string State;
        /// <summary>
        /// The date and time the external DB system was created.
        /// </summary>
        public readonly string TimeCreated;

        [OutputConstructor]
        private GetExternalDatabasesExternalDatabaseCollectionItemResult(
            string compartmentId,

            string databaseSubType,

            string databaseType,

            ImmutableArray<Outputs.GetExternalDatabasesExternalDatabaseCollectionItemDbManagementConfigResult> dbManagementConfigs,

            ImmutableArray<Outputs.GetExternalDatabasesExternalDatabaseCollectionItemDbSystemInfoResult> dbSystemInfos,

            string dbUniqueName,

            string displayName,

            string externalContainerDatabaseId,

            string externalDbHomeId,

            string id,

            ImmutableArray<Outputs.GetExternalDatabasesExternalDatabaseCollectionItemInstanceDetailResult> instanceDetails,

            string state,

            string timeCreated)
        {
            CompartmentId = compartmentId;
            DatabaseSubType = databaseSubType;
            DatabaseType = databaseType;
            DbManagementConfigs = dbManagementConfigs;
            DbSystemInfos = dbSystemInfos;
            DbUniqueName = dbUniqueName;
            DisplayName = displayName;
            ExternalContainerDatabaseId = externalContainerDatabaseId;
            ExternalDbHomeId = externalDbHomeId;
            Id = id;
            InstanceDetails = instanceDetails;
            State = state;
            TimeCreated = timeCreated;
        }
    }
}