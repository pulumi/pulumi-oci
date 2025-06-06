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
    public sealed class GetManagedDatabasesManagedDatabaseCollectionItemResult
    {
        /// <summary>
        /// The additional details specific to a type of database defined in `{"key": "value"}` format. Example: `{"bar-key": "value"}`
        /// </summary>
        public readonly ImmutableDictionary<string, string> AdditionalDetails;
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
        /// </summary>
        public readonly string CompartmentId;
        /// <summary>
        /// The operating system of database.
        /// </summary>
        public readonly string DatabasePlatformName;
        /// <summary>
        /// The status of the Oracle Database. Indicates whether the status of the database is UP, DOWN, or UNKNOWN at the current time.
        /// </summary>
        public readonly string DatabaseStatus;
        /// <summary>
        /// The subtype of the Oracle Database. Indicates whether the database is a Container Database, Pluggable Database, Non-container Database, Autonomous Database, or Autonomous Container Database.
        /// </summary>
        public readonly string DatabaseSubType;
        /// <summary>
        /// The type of Oracle Database installation.
        /// </summary>
        public readonly string DatabaseType;
        /// <summary>
        /// The Oracle Database version.
        /// </summary>
        public readonly string DatabaseVersion;
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the DB system that this Managed Database is part of.
        /// </summary>
        public readonly string DbSystemId;
        /// <summary>
        /// The list of feature configurations
        /// </summary>
        public readonly ImmutableArray<Outputs.GetManagedDatabasesManagedDatabaseCollectionItemDbmgmtFeatureConfigResult> DbmgmtFeatureConfigs;
        /// <summary>
        /// Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Operations.CostCenter": "42"}`
        /// </summary>
        public readonly ImmutableDictionary<string, string> DefinedTags;
        /// <summary>
        /// A filter to return Managed Databases of the specified deployment type.
        /// </summary>
        public readonly string DeploymentType;
        /// <summary>
        /// Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Department": "Finance"}`
        /// </summary>
        public readonly ImmutableDictionary<string, string> FreeformTags;
        /// <summary>
        /// The identifier of the resource.
        /// </summary>
        public readonly string Id;
        /// <summary>
        /// Indicates whether the Oracle Database is part of a cluster.
        /// </summary>
        public readonly bool IsCluster;
        /// <summary>
        /// A list of Managed Database Groups that the Managed Database belongs to.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetManagedDatabasesManagedDatabaseCollectionItemManagedDatabaseGroupResult> ManagedDatabaseGroups;
        /// <summary>
        /// A filter to return Managed Databases with the specified management option.
        /// </summary>
        public readonly string ManagementOption;
        /// <summary>
        /// A filter to return only resources that match the entire name.
        /// </summary>
        public readonly string Name;
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the parent Container Database if Managed Database is a Pluggable Database.
        /// </summary>
        public readonly string ParentContainerId;
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the storage DB system.
        /// </summary>
        public readonly string StorageSystemId;
        /// <summary>
        /// System tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). System tags can be viewed by users, but can only be created by the system.  Example: `{"orcl-cloud.free-tier-retained": "true"}`
        /// </summary>
        public readonly ImmutableDictionary<string, string> SystemTags;
        /// <summary>
        /// The date and time the Managed Database was created.
        /// </summary>
        public readonly string TimeCreated;
        /// <summary>
        /// The workload type of the Autonomous Database.
        /// </summary>
        public readonly string WorkloadType;

        [OutputConstructor]
        private GetManagedDatabasesManagedDatabaseCollectionItemResult(
            ImmutableDictionary<string, string> additionalDetails,

            string compartmentId,

            string databasePlatformName,

            string databaseStatus,

            string databaseSubType,

            string databaseType,

            string databaseVersion,

            string dbSystemId,

            ImmutableArray<Outputs.GetManagedDatabasesManagedDatabaseCollectionItemDbmgmtFeatureConfigResult> dbmgmtFeatureConfigs,

            ImmutableDictionary<string, string> definedTags,

            string deploymentType,

            ImmutableDictionary<string, string> freeformTags,

            string id,

            bool isCluster,

            ImmutableArray<Outputs.GetManagedDatabasesManagedDatabaseCollectionItemManagedDatabaseGroupResult> managedDatabaseGroups,

            string managementOption,

            string name,

            string parentContainerId,

            string storageSystemId,

            ImmutableDictionary<string, string> systemTags,

            string timeCreated,

            string workloadType)
        {
            AdditionalDetails = additionalDetails;
            CompartmentId = compartmentId;
            DatabasePlatformName = databasePlatformName;
            DatabaseStatus = databaseStatus;
            DatabaseSubType = databaseSubType;
            DatabaseType = databaseType;
            DatabaseVersion = databaseVersion;
            DbSystemId = dbSystemId;
            DbmgmtFeatureConfigs = dbmgmtFeatureConfigs;
            DefinedTags = definedTags;
            DeploymentType = deploymentType;
            FreeformTags = freeformTags;
            Id = id;
            IsCluster = isCluster;
            ManagedDatabaseGroups = managedDatabaseGroups;
            ManagementOption = managementOption;
            Name = name;
            ParentContainerId = parentContainerId;
            StorageSystemId = storageSystemId;
            SystemTags = systemTags;
            TimeCreated = timeCreated;
            WorkloadType = workloadType;
        }
    }
}
