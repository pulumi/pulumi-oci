// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import { input as inputs, output as outputs } from "../types";
import * as utilities from "../utilities";

/**
 * This data source provides details about a specific Managed Database Sql Tuning Advisor Tasks Finding resource in Oracle Cloud Infrastructure Database Management service.
 *
 * Gets an array of the details of the findings that match specific filters.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testManagedDatabaseSqlTuningAdvisorTasksFinding = oci.DatabaseManagement.getManagedDatabaseSqlTuningAdvisorTasksFinding({
 *     managedDatabaseId: oci_database_management_managed_database.test_managed_database.id,
 *     sqlTuningAdvisorTaskId: oci_database_management_sql_tuning_advisor_task.test_sql_tuning_advisor_task.id,
 *     beginExecId: oci_database_management_begin_exec.test_begin_exec.id,
 *     endExecId: oci_database_management_end_exec.test_end_exec.id,
 *     findingFilter: _var.managed_database_sql_tuning_advisor_tasks_finding_finding_filter,
 *     indexHashFilter: _var.managed_database_sql_tuning_advisor_tasks_finding_index_hash_filter,
 *     searchPeriod: _var.managed_database_sql_tuning_advisor_tasks_finding_search_period,
 *     statsHashFilter: _var.managed_database_sql_tuning_advisor_tasks_finding_stats_hash_filter,
 * });
 * ```
 */
export function getManagedDatabaseSqlTuningAdvisorTasksFinding(args: GetManagedDatabaseSqlTuningAdvisorTasksFindingArgs, opts?: pulumi.InvokeOptions): Promise<GetManagedDatabaseSqlTuningAdvisorTasksFindingResult> {
    if (!opts) {
        opts = {}
    }

    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts);
    return pulumi.runtime.invoke("oci:DatabaseManagement/getManagedDatabaseSqlTuningAdvisorTasksFinding:getManagedDatabaseSqlTuningAdvisorTasksFinding", {
        "beginExecId": args.beginExecId,
        "endExecId": args.endExecId,
        "findingFilter": args.findingFilter,
        "indexHashFilter": args.indexHashFilter,
        "managedDatabaseId": args.managedDatabaseId,
        "searchPeriod": args.searchPeriod,
        "sqlTuningAdvisorTaskId": args.sqlTuningAdvisorTaskId,
        "statsHashFilter": args.statsHashFilter,
    }, opts);
}

/**
 * A collection of arguments for invoking getManagedDatabaseSqlTuningAdvisorTasksFinding.
 */
export interface GetManagedDatabaseSqlTuningAdvisorTasksFindingArgs {
    /**
     * The optional greater than or equal to filter on the execution ID related to a specific SQL Tuning Advisor task.
     */
    beginExecId?: string;
    /**
     * The optional less than or equal to query parameter to filter on the execution ID related to a specific SQL Tuning Advisor task.
     */
    endExecId?: string;
    /**
     * The filter used to display specific findings in the report.
     */
    findingFilter?: string;
    /**
     * The hash value of the index table name.
     */
    indexHashFilter?: string;
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Managed Database.
     */
    managedDatabaseId: string;
    /**
     * The search period during which the API will search for begin and end exec id, if not supplied. Unused if beginExecId and endExecId optional query params are both supplied.
     */
    searchPeriod?: string;
    /**
     * The SQL tuning task identifier. This is not the [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
     */
    sqlTuningAdvisorTaskId: string;
    /**
     * The hash value of the object for the statistic finding search.
     */
    statsHashFilter?: string;
}

/**
 * A collection of values returned by getManagedDatabaseSqlTuningAdvisorTasksFinding.
 */
export interface GetManagedDatabaseSqlTuningAdvisorTasksFindingResult {
    readonly beginExecId?: string;
    readonly endExecId?: string;
    readonly findingFilter?: string;
    /**
     * The provider-assigned unique ID for this managed resource.
     */
    readonly id: string;
    readonly indexHashFilter?: string;
    /**
     * An array of the findings for a tuning task.
     */
    readonly items: outputs.DatabaseManagement.GetManagedDatabaseSqlTuningAdvisorTasksFindingItem[];
    readonly managedDatabaseId: string;
    readonly searchPeriod?: string;
    /**
     * The unique identifier of the SQL Tuning Advisor task. This is not the [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
     */
    readonly sqlTuningAdvisorTaskId: string;
    readonly statsHashFilter?: string;
}

export function getManagedDatabaseSqlTuningAdvisorTasksFindingOutput(args: GetManagedDatabaseSqlTuningAdvisorTasksFindingOutputArgs, opts?: pulumi.InvokeOptions): pulumi.Output<GetManagedDatabaseSqlTuningAdvisorTasksFindingResult> {
    return pulumi.output(args).apply(a => getManagedDatabaseSqlTuningAdvisorTasksFinding(a, opts))
}

/**
 * A collection of arguments for invoking getManagedDatabaseSqlTuningAdvisorTasksFinding.
 */
export interface GetManagedDatabaseSqlTuningAdvisorTasksFindingOutputArgs {
    /**
     * The optional greater than or equal to filter on the execution ID related to a specific SQL Tuning Advisor task.
     */
    beginExecId?: pulumi.Input<string>;
    /**
     * The optional less than or equal to query parameter to filter on the execution ID related to a specific SQL Tuning Advisor task.
     */
    endExecId?: pulumi.Input<string>;
    /**
     * The filter used to display specific findings in the report.
     */
    findingFilter?: pulumi.Input<string>;
    /**
     * The hash value of the index table name.
     */
    indexHashFilter?: pulumi.Input<string>;
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Managed Database.
     */
    managedDatabaseId: pulumi.Input<string>;
    /**
     * The search period during which the API will search for begin and end exec id, if not supplied. Unused if beginExecId and endExecId optional query params are both supplied.
     */
    searchPeriod?: pulumi.Input<string>;
    /**
     * The SQL tuning task identifier. This is not the [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
     */
    sqlTuningAdvisorTaskId: pulumi.Input<string>;
    /**
     * The hash value of the object for the statistic finding search.
     */
    statsHashFilter?: pulumi.Input<string>;
}
