// *** WARNING: this file was generated by pulumi-language-nodejs. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import * as inputs from "../types/input";
import * as outputs from "../types/output";
import * as utilities from "../utilities";

/**
 * This data source provides details about a specific Managed Database Sql Tuning Advisor Tasks Summary Report resource in Oracle Cloud Infrastructure Database Management service.
 *
 * Gets the summary report for the specified SQL Tuning Advisor task.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testManagedDatabaseSqlTuningAdvisorTasksSummaryReport = oci.DatabaseManagement.getManagedDatabaseSqlTuningAdvisorTasksSummaryReport({
 *     managedDatabaseId: testManagedDatabase.id,
 *     sqlTuningAdvisorTaskId: testSqlTuningAdvisorTask.id,
 *     beginExecIdGreaterThanOrEqualTo: managedDatabaseSqlTuningAdvisorTasksSummaryReportBeginExecIdGreaterThanOrEqualTo,
 *     endExecIdLessThanOrEqualTo: managedDatabaseSqlTuningAdvisorTasksSummaryReportEndExecIdLessThanOrEqualTo,
 *     opcNamedCredentialId: managedDatabaseSqlTuningAdvisorTasksSummaryReportOpcNamedCredentialId,
 *     searchPeriod: managedDatabaseSqlTuningAdvisorTasksSummaryReportSearchPeriod,
 *     timeGreaterThanOrEqualTo: managedDatabaseSqlTuningAdvisorTasksSummaryReportTimeGreaterThanOrEqualTo,
 *     timeLessThanOrEqualTo: managedDatabaseSqlTuningAdvisorTasksSummaryReportTimeLessThanOrEqualTo,
 * });
 * ```
 */
export function getManagedDatabaseSqlTuningAdvisorTasksSummaryReport(args: GetManagedDatabaseSqlTuningAdvisorTasksSummaryReportArgs, opts?: pulumi.InvokeOptions): Promise<GetManagedDatabaseSqlTuningAdvisorTasksSummaryReportResult> {
    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts || {});
    return pulumi.runtime.invoke("oci:DatabaseManagement/getManagedDatabaseSqlTuningAdvisorTasksSummaryReport:getManagedDatabaseSqlTuningAdvisorTasksSummaryReport", {
        "beginExecIdGreaterThanOrEqualTo": args.beginExecIdGreaterThanOrEqualTo,
        "endExecIdLessThanOrEqualTo": args.endExecIdLessThanOrEqualTo,
        "managedDatabaseId": args.managedDatabaseId,
        "opcNamedCredentialId": args.opcNamedCredentialId,
        "searchPeriod": args.searchPeriod,
        "sqlTuningAdvisorTaskId": args.sqlTuningAdvisorTaskId,
        "timeGreaterThanOrEqualTo": args.timeGreaterThanOrEqualTo,
        "timeLessThanOrEqualTo": args.timeLessThanOrEqualTo,
    }, opts);
}

/**
 * A collection of arguments for invoking getManagedDatabaseSqlTuningAdvisorTasksSummaryReport.
 */
export interface GetManagedDatabaseSqlTuningAdvisorTasksSummaryReportArgs {
    /**
     * The optional greater than or equal to filter on the execution ID related to a specific SQL Tuning Advisor task. This is applicable only for Auto SQL Tuning tasks.
     */
    beginExecIdGreaterThanOrEqualTo?: string;
    /**
     * The optional less than or equal to query parameter to filter on the execution ID related to a specific SQL Tuning Advisor task. This is applicable only for Auto SQL Tuning tasks.
     */
    endExecIdLessThanOrEqualTo?: string;
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Managed Database.
     */
    managedDatabaseId: string;
    /**
     * The OCID of the Named Credential.
     */
    opcNamedCredentialId?: string;
    /**
     * How far back the API will search for begin and end exec id. Unused if neither exec ids nor time filter query params are supplied. This is applicable only for Auto SQL Tuning tasks.
     */
    searchPeriod?: string;
    /**
     * The SQL tuning task identifier. This is not the [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
     */
    sqlTuningAdvisorTaskId: string;
    /**
     * The optional greater than or equal to query parameter to filter the timestamp. This is applicable only for Auto SQL Tuning tasks.
     */
    timeGreaterThanOrEqualTo?: string;
    /**
     * The optional less than or equal to query parameter to filter the timestamp. This is applicable only for Auto SQL Tuning tasks.
     */
    timeLessThanOrEqualTo?: string;
}

/**
 * A collection of values returned by getManagedDatabaseSqlTuningAdvisorTasksSummaryReport.
 */
export interface GetManagedDatabaseSqlTuningAdvisorTasksSummaryReportResult {
    readonly beginExecIdGreaterThanOrEqualTo?: string;
    readonly endExecIdLessThanOrEqualTo?: string;
    /**
     * The provider-assigned unique ID for this managed resource.
     */
    readonly id: string;
    /**
     * The list of object findings related to indexes.
     */
    readonly indexFindings: outputs.DatabaseManagement.GetManagedDatabaseSqlTuningAdvisorTasksSummaryReportIndexFinding[];
    readonly managedDatabaseId: string;
    /**
     * The list of object findings related to statistics.
     */
    readonly objectStatFindings: outputs.DatabaseManagement.GetManagedDatabaseSqlTuningAdvisorTasksSummaryReportObjectStatFinding[];
    readonly opcNamedCredentialId?: string;
    readonly searchPeriod?: string;
    readonly sqlTuningAdvisorTaskId: string;
    /**
     * The number of distinct SQL statements with stale or missing optimizer statistics recommendations.
     */
    readonly statistics: outputs.DatabaseManagement.GetManagedDatabaseSqlTuningAdvisorTasksSummaryReportStatistic[];
    /**
     * The general information regarding the SQL Tuning Advisor task.
     */
    readonly taskInfos: outputs.DatabaseManagement.GetManagedDatabaseSqlTuningAdvisorTasksSummaryReportTaskInfo[];
    readonly timeGreaterThanOrEqualTo?: string;
    readonly timeLessThanOrEqualTo?: string;
}
/**
 * This data source provides details about a specific Managed Database Sql Tuning Advisor Tasks Summary Report resource in Oracle Cloud Infrastructure Database Management service.
 *
 * Gets the summary report for the specified SQL Tuning Advisor task.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testManagedDatabaseSqlTuningAdvisorTasksSummaryReport = oci.DatabaseManagement.getManagedDatabaseSqlTuningAdvisorTasksSummaryReport({
 *     managedDatabaseId: testManagedDatabase.id,
 *     sqlTuningAdvisorTaskId: testSqlTuningAdvisorTask.id,
 *     beginExecIdGreaterThanOrEqualTo: managedDatabaseSqlTuningAdvisorTasksSummaryReportBeginExecIdGreaterThanOrEqualTo,
 *     endExecIdLessThanOrEqualTo: managedDatabaseSqlTuningAdvisorTasksSummaryReportEndExecIdLessThanOrEqualTo,
 *     opcNamedCredentialId: managedDatabaseSqlTuningAdvisorTasksSummaryReportOpcNamedCredentialId,
 *     searchPeriod: managedDatabaseSqlTuningAdvisorTasksSummaryReportSearchPeriod,
 *     timeGreaterThanOrEqualTo: managedDatabaseSqlTuningAdvisorTasksSummaryReportTimeGreaterThanOrEqualTo,
 *     timeLessThanOrEqualTo: managedDatabaseSqlTuningAdvisorTasksSummaryReportTimeLessThanOrEqualTo,
 * });
 * ```
 */
export function getManagedDatabaseSqlTuningAdvisorTasksSummaryReportOutput(args: GetManagedDatabaseSqlTuningAdvisorTasksSummaryReportOutputArgs, opts?: pulumi.InvokeOutputOptions): pulumi.Output<GetManagedDatabaseSqlTuningAdvisorTasksSummaryReportResult> {
    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts || {});
    return pulumi.runtime.invokeOutput("oci:DatabaseManagement/getManagedDatabaseSqlTuningAdvisorTasksSummaryReport:getManagedDatabaseSqlTuningAdvisorTasksSummaryReport", {
        "beginExecIdGreaterThanOrEqualTo": args.beginExecIdGreaterThanOrEqualTo,
        "endExecIdLessThanOrEqualTo": args.endExecIdLessThanOrEqualTo,
        "managedDatabaseId": args.managedDatabaseId,
        "opcNamedCredentialId": args.opcNamedCredentialId,
        "searchPeriod": args.searchPeriod,
        "sqlTuningAdvisorTaskId": args.sqlTuningAdvisorTaskId,
        "timeGreaterThanOrEqualTo": args.timeGreaterThanOrEqualTo,
        "timeLessThanOrEqualTo": args.timeLessThanOrEqualTo,
    }, opts);
}

/**
 * A collection of arguments for invoking getManagedDatabaseSqlTuningAdvisorTasksSummaryReport.
 */
export interface GetManagedDatabaseSqlTuningAdvisorTasksSummaryReportOutputArgs {
    /**
     * The optional greater than or equal to filter on the execution ID related to a specific SQL Tuning Advisor task. This is applicable only for Auto SQL Tuning tasks.
     */
    beginExecIdGreaterThanOrEqualTo?: pulumi.Input<string>;
    /**
     * The optional less than or equal to query parameter to filter on the execution ID related to a specific SQL Tuning Advisor task. This is applicable only for Auto SQL Tuning tasks.
     */
    endExecIdLessThanOrEqualTo?: pulumi.Input<string>;
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Managed Database.
     */
    managedDatabaseId: pulumi.Input<string>;
    /**
     * The OCID of the Named Credential.
     */
    opcNamedCredentialId?: pulumi.Input<string>;
    /**
     * How far back the API will search for begin and end exec id. Unused if neither exec ids nor time filter query params are supplied. This is applicable only for Auto SQL Tuning tasks.
     */
    searchPeriod?: pulumi.Input<string>;
    /**
     * The SQL tuning task identifier. This is not the [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
     */
    sqlTuningAdvisorTaskId: pulumi.Input<string>;
    /**
     * The optional greater than or equal to query parameter to filter the timestamp. This is applicable only for Auto SQL Tuning tasks.
     */
    timeGreaterThanOrEqualTo?: pulumi.Input<string>;
    /**
     * The optional less than or equal to query parameter to filter the timestamp. This is applicable only for Auto SQL Tuning tasks.
     */
    timeLessThanOrEqualTo?: pulumi.Input<string>;
}
