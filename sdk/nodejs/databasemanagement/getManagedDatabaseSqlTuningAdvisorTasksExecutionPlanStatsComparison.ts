// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import { input as inputs, output as outputs } from "../types";
import * as utilities from "../utilities";

/**
 * This data source provides details about a specific Managed Database Sql Tuning Advisor Tasks Execution Plan Stats Comparision resource in Oracle Cloud Infrastructure Database Management service.
 *
 * Retrieves a comparison of the existing SQL execution plan and a new plan.
 * A SQL tuning task may suggest a new execution plan for a SQL,
 * and this API retrieves the comparison report of the statistics of the two plans.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testManagedDatabaseSqlTuningAdvisorTasksExecutionPlanStatsComparision = oci.DatabaseManagement.getManagedDatabaseSqlTuningAdvisorTasksExecutionPlanStatsComparison({
 *     executionId: oci_database_management_execution.test_execution.id,
 *     managedDatabaseId: oci_database_management_managed_database.test_managed_database.id,
 *     sqlObjectId: oci_objectstorage_object.test_object.id,
 *     sqlTuningAdvisorTaskId: oci_database_management_sql_tuning_advisor_task.test_sql_tuning_advisor_task.id,
 * });
 * ```
 */
export function getManagedDatabaseSqlTuningAdvisorTasksExecutionPlanStatsComparison(args: GetManagedDatabaseSqlTuningAdvisorTasksExecutionPlanStatsComparisonArgs, opts?: pulumi.InvokeOptions): Promise<GetManagedDatabaseSqlTuningAdvisorTasksExecutionPlanStatsComparisonResult> {
    if (!opts) {
        opts = {}
    }

    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts);
    return pulumi.runtime.invoke("oci:DatabaseManagement/getManagedDatabaseSqlTuningAdvisorTasksExecutionPlanStatsComparison:getManagedDatabaseSqlTuningAdvisorTasksExecutionPlanStatsComparison", {
        "executionId": args.executionId,
        "managedDatabaseId": args.managedDatabaseId,
        "sqlObjectId": args.sqlObjectId,
        "sqlTuningAdvisorTaskId": args.sqlTuningAdvisorTaskId,
    }, opts);
}

/**
 * A collection of arguments for invoking getManagedDatabaseSqlTuningAdvisorTasksExecutionPlanStatsComparison.
 */
export interface GetManagedDatabaseSqlTuningAdvisorTasksExecutionPlanStatsComparisonArgs {
    /**
     * The execution ID for an execution of a SQL tuning task. This is not the [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
     */
    executionId: string;
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Managed Database.
     */
    managedDatabaseId: string;
    /**
     * The SQL object ID for the SQL tuning task. This is not the [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
     */
    sqlObjectId: string;
    /**
     * The SQL tuning task identifier. This is not the [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
     */
    sqlTuningAdvisorTaskId: string;
}

/**
 * A collection of values returned by getManagedDatabaseSqlTuningAdvisorTasksExecutionPlanStatsComparison.
 */
export interface GetManagedDatabaseSqlTuningAdvisorTasksExecutionPlanStatsComparisonResult {
    readonly executionId: string;
    /**
     * The provider-assigned unique ID for this managed resource.
     */
    readonly id: string;
    readonly managedDatabaseId: string;
    /**
     * The statistics of a SQL execution plan.
     */
    readonly modifieds: outputs.DatabaseManagement.GetManagedDatabaseSqlTuningAdvisorTasksExecutionPlanStatsComparisonModified[];
    /**
     * The statistics of a SQL execution plan.
     */
    readonly originals: outputs.DatabaseManagement.GetManagedDatabaseSqlTuningAdvisorTasksExecutionPlanStatsComparisonOriginal[];
    readonly sqlObjectId: string;
    readonly sqlTuningAdvisorTaskId: string;
}

export function getManagedDatabaseSqlTuningAdvisorTasksExecutionPlanStatsComparisonOutput(args: GetManagedDatabaseSqlTuningAdvisorTasksExecutionPlanStatsComparisonOutputArgs, opts?: pulumi.InvokeOptions): pulumi.Output<GetManagedDatabaseSqlTuningAdvisorTasksExecutionPlanStatsComparisonResult> {
    return pulumi.output(args).apply(a => getManagedDatabaseSqlTuningAdvisorTasksExecutionPlanStatsComparison(a, opts))
}

/**
 * A collection of arguments for invoking getManagedDatabaseSqlTuningAdvisorTasksExecutionPlanStatsComparison.
 */
export interface GetManagedDatabaseSqlTuningAdvisorTasksExecutionPlanStatsComparisonOutputArgs {
    /**
     * The execution ID for an execution of a SQL tuning task. This is not the [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
     */
    executionId: pulumi.Input<string>;
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Managed Database.
     */
    managedDatabaseId: pulumi.Input<string>;
    /**
     * The SQL object ID for the SQL tuning task. This is not the [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
     */
    sqlObjectId: pulumi.Input<string>;
    /**
     * The SQL tuning task identifier. This is not the [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
     */
    sqlTuningAdvisorTaskId: pulumi.Input<string>;
}