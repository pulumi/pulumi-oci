// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import * as utilities from "../utilities";

/**
 * This data source provides details about a specific Managed Database Sql Plan Baseline resource in Oracle Cloud Infrastructure Database Management service.
 *
 * Gets the SQL plan baseline details for the specified planName.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testManagedDatabaseSqlPlanBaseline = oci.DatabaseManagement.getManagedDatabaseSqlPlanBaseline({
 *     managedDatabaseId: oci_database_management_managed_database.test_managed_database.id,
 *     planName: _var.managed_database_sql_plan_baseline_plan_name,
 * });
 * ```
 */
export function getManagedDatabaseSqlPlanBaseline(args: GetManagedDatabaseSqlPlanBaselineArgs, opts?: pulumi.InvokeOptions): Promise<GetManagedDatabaseSqlPlanBaselineResult> {

    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts || {});
    return pulumi.runtime.invoke("oci:DatabaseManagement/getManagedDatabaseSqlPlanBaseline:getManagedDatabaseSqlPlanBaseline", {
        "managedDatabaseId": args.managedDatabaseId,
        "planName": args.planName,
    }, opts);
}

/**
 * A collection of arguments for invoking getManagedDatabaseSqlPlanBaseline.
 */
export interface GetManagedDatabaseSqlPlanBaselineArgs {
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Managed Database.
     */
    managedDatabaseId: string;
    /**
     * The plan name of the SQL plan baseline.
     */
    planName: string;
}

/**
 * A collection of values returned by getManagedDatabaseSqlPlanBaseline.
 */
export interface GetManagedDatabaseSqlPlanBaselineResult {
    /**
     * Indicates whether the plan baseline is accepted (`YES`) or not (`NO`).
     */
    readonly accepted: string;
    /**
     * The application action.
     */
    readonly action: string;
    /**
     * Indicates whether a plan that is automatically captured by SQL plan management is marked adaptive or not.
     */
    readonly adaptive: string;
    /**
     * Indicates whether the plan baseline is auto-purged (`YES`) or not (`NO`).
     */
    readonly autoPurge: string;
    /**
     * Indicates whether the plan baseline is enabled (`YES`) or disabled (`NO`).
     */
    readonly enabled: string;
    /**
     * The execution plan for the SQL statement.
     */
    readonly executionPlan: string;
    /**
     * Indicates whether the plan baseline is fixed (`YES`) or not (`NO`).
     */
    readonly fixed: string;
    /**
     * The provider-assigned unique ID for this managed resource.
     */
    readonly id: string;
    readonly managedDatabaseId: string;
    /**
     * The application module name.
     */
    readonly module: string;
    /**
     * The origin of the SQL plan baseline.
     */
    readonly origin: string;
    /**
     * The unique plan identifier.
     */
    readonly planName: string;
    /**
     * Indicates whether the optimizer was able to reproduce the plan (`YES`) or not (`NO`). The value is set to `YES` when a plan is initially added to the plan baseline.
     */
    readonly reproduced: string;
    /**
     * The unique SQL identifier.
     */
    readonly sqlHandle: string;
    /**
     * The SQL text.
     */
    readonly sqlText: string;
    /**
     * The date and time when the plan baseline was created.
     */
    readonly timeCreated: string;
    /**
     * The date and time when the plan baseline was last executed.
     */
    readonly timeLastExecuted: string;
    /**
     * The date and time when the plan baseline was last modified.
     */
    readonly timeLastModified: string;
}
/**
 * This data source provides details about a specific Managed Database Sql Plan Baseline resource in Oracle Cloud Infrastructure Database Management service.
 *
 * Gets the SQL plan baseline details for the specified planName.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testManagedDatabaseSqlPlanBaseline = oci.DatabaseManagement.getManagedDatabaseSqlPlanBaseline({
 *     managedDatabaseId: oci_database_management_managed_database.test_managed_database.id,
 *     planName: _var.managed_database_sql_plan_baseline_plan_name,
 * });
 * ```
 */
export function getManagedDatabaseSqlPlanBaselineOutput(args: GetManagedDatabaseSqlPlanBaselineOutputArgs, opts?: pulumi.InvokeOptions): pulumi.Output<GetManagedDatabaseSqlPlanBaselineResult> {
    return pulumi.output(args).apply((a: any) => getManagedDatabaseSqlPlanBaseline(a, opts))
}

/**
 * A collection of arguments for invoking getManagedDatabaseSqlPlanBaseline.
 */
export interface GetManagedDatabaseSqlPlanBaselineOutputArgs {
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Managed Database.
     */
    managedDatabaseId: pulumi.Input<string>;
    /**
     * The plan name of the SQL plan baseline.
     */
    planName: pulumi.Input<string>;
}