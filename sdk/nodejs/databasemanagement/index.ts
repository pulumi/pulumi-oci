// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import * as utilities from "../utilities";

// Export members:
export * from "./dbManagementPrivateEndpoint";
export * from "./getDbManagementPrivateEndpoint";
export * from "./getDbManagementPrivateEndpointAssociatedDatabase";
export * from "./getDbManagementPrivateEndpointAssociatedDatabases";
export * from "./getDbManagementPrivateEndpoints";
export * from "./getJobExecutionsStatus";
export * from "./getJobExecutionsStatuses";
export * from "./getManagedDatabase";
export * from "./getManagedDatabaseAddmTask";
export * from "./getManagedDatabaseAddmTasks";
export * from "./getManagedDatabaseAlertLogCount";
export * from "./getManagedDatabaseAlertLogCounts";
export * from "./getManagedDatabaseAttentionLogCount";
export * from "./getManagedDatabaseAttentionLogCounts";
export * from "./getManagedDatabaseGroup";
export * from "./getManagedDatabaseGroups";
export * from "./getManagedDatabaseOptimizerStatisticsAdvisorExecution";
export * from "./getManagedDatabaseOptimizerStatisticsAdvisorExecutionScript";
export * from "./getManagedDatabaseOptimizerStatisticsAdvisorExecutions";
export * from "./getManagedDatabaseOptimizerStatisticsCollectionAggregations";
export * from "./getManagedDatabaseOptimizerStatisticsCollectionOperation";
export * from "./getManagedDatabaseOptimizerStatisticsCollectionOperations";
export * from "./getManagedDatabaseSqlTuningAdvisorTask";
export * from "./getManagedDatabaseSqlTuningAdvisorTasks";
export * from "./getManagedDatabaseSqlTuningAdvisorTasksExecutionPlanStatsComparison";
export * from "./getManagedDatabaseSqlTuningAdvisorTasksFinding";
export * from "./getManagedDatabaseSqlTuningAdvisorTasksFindings";
export * from "./getManagedDatabaseSqlTuningAdvisorTasksRecommendation";
export * from "./getManagedDatabaseSqlTuningAdvisorTasksRecommendations";
export * from "./getManagedDatabaseSqlTuningAdvisorTasksSqlExecutionPlan";
export * from "./getManagedDatabaseSqlTuningAdvisorTasksSummaryReport";
export * from "./getManagedDatabaseSqlTuningSet";
export * from "./getManagedDatabaseSqlTuningSets";
export * from "./getManagedDatabaseTableStatistics";
export * from "./getManagedDatabaseUser";
export * from "./getManagedDatabaseUserConsumerGroupPrivilege";
export * from "./getManagedDatabaseUserConsumerGroupPrivileges";
export * from "./getManagedDatabaseUserDataAccessContainer";
export * from "./getManagedDatabaseUserDataAccessContainers";
export * from "./getManagedDatabaseUserObjectPrivilege";
export * from "./getManagedDatabaseUserObjectPrivileges";
export * from "./getManagedDatabaseUserProxiedForUser";
export * from "./getManagedDatabaseUserProxiedForUsers";
export * from "./getManagedDatabaseUserRole";
export * from "./getManagedDatabaseUserRoles";
export * from "./getManagedDatabaseUsers";
export * from "./getManagedDatabases";
export * from "./getManagedDatabasesAsmProperties";
export * from "./getManagedDatabasesAsmProperty";
export * from "./getManagedDatabasesDatabaseParameter";
export * from "./getManagedDatabasesDatabaseParameters";
export * from "./getManagedDatabasesUserProxyUser";
export * from "./getManagedDatabasesUserProxyUsers";
export * from "./getManagedDatabasesUserSystemPrivilege";
export * from "./getManagedDatabasesUserSystemPrivileges";
export * from "./managedDatabaseGroup";
export * from "./managedDatabasesChangeDatabaseParameter";
export * from "./managedDatabasesResetDatabaseParameter";

// Import resources to register:
import { DbManagementPrivateEndpoint } from "./dbManagementPrivateEndpoint";
import { ManagedDatabaseGroup } from "./managedDatabaseGroup";
import { ManagedDatabasesChangeDatabaseParameter } from "./managedDatabasesChangeDatabaseParameter";
import { ManagedDatabasesResetDatabaseParameter } from "./managedDatabasesResetDatabaseParameter";

const _module = {
    version: utilities.getVersion(),
    construct: (name: string, type: string, urn: string): pulumi.Resource => {
        switch (type) {
            case "oci:DatabaseManagement/dbManagementPrivateEndpoint:DbManagementPrivateEndpoint":
                return new DbManagementPrivateEndpoint(name, <any>undefined, { urn })
            case "oci:DatabaseManagement/managedDatabaseGroup:ManagedDatabaseGroup":
                return new ManagedDatabaseGroup(name, <any>undefined, { urn })
            case "oci:DatabaseManagement/managedDatabasesChangeDatabaseParameter:ManagedDatabasesChangeDatabaseParameter":
                return new ManagedDatabasesChangeDatabaseParameter(name, <any>undefined, { urn })
            case "oci:DatabaseManagement/managedDatabasesResetDatabaseParameter:ManagedDatabasesResetDatabaseParameter":
                return new ManagedDatabasesResetDatabaseParameter(name, <any>undefined, { urn })
            default:
                throw new Error(`unknown resource type ${type}`);
        }
    },
};
pulumi.runtime.registerResourceModule("oci", "DatabaseManagement/dbManagementPrivateEndpoint", _module)
pulumi.runtime.registerResourceModule("oci", "DatabaseManagement/managedDatabaseGroup", _module)
pulumi.runtime.registerResourceModule("oci", "DatabaseManagement/managedDatabasesChangeDatabaseParameter", _module)
pulumi.runtime.registerResourceModule("oci", "DatabaseManagement/managedDatabasesResetDatabaseParameter", _module)