// *** WARNING: this file was generated by pulumi-language-nodejs. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import * as inputs from "../types/input";
import * as outputs from "../types/output";
import * as utilities from "../utilities";

/**
 * This data source provides details about a specific Managed Database Optimizer Statistics Advisor Execution resource in Oracle Cloud Infrastructure Database Management service.
 *
 * Gets a comprehensive report of the Optimizer Statistics Advisor execution, which includes details of the
 * Managed Database, findings, recommendations, rationale, and examples.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testManagedDatabaseOptimizerStatisticsAdvisorExecution = oci.DatabaseManagement.getManagedDatabaseOptimizerStatisticsAdvisorExecution({
 *     executionName: managedDatabaseOptimizerStatisticsAdvisorExecutionExecutionName,
 *     managedDatabaseId: testManagedDatabase.id,
 *     taskName: managedDatabaseOptimizerStatisticsAdvisorExecutionTaskName,
 * });
 * ```
 */
export function getManagedDatabaseOptimizerStatisticsAdvisorExecution(args: GetManagedDatabaseOptimizerStatisticsAdvisorExecutionArgs, opts?: pulumi.InvokeOptions): Promise<GetManagedDatabaseOptimizerStatisticsAdvisorExecutionResult> {
    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts || {});
    return pulumi.runtime.invoke("oci:DatabaseManagement/getManagedDatabaseOptimizerStatisticsAdvisorExecution:getManagedDatabaseOptimizerStatisticsAdvisorExecution", {
        "executionName": args.executionName,
        "managedDatabaseId": args.managedDatabaseId,
        "taskName": args.taskName,
    }, opts);
}

/**
 * A collection of arguments for invoking getManagedDatabaseOptimizerStatisticsAdvisorExecution.
 */
export interface GetManagedDatabaseOptimizerStatisticsAdvisorExecutionArgs {
    /**
     * The name of the Optimizer Statistics Advisor execution.
     */
    executionName: string;
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Managed Database.
     */
    managedDatabaseId: string;
    /**
     * The name of the optimizer statistics collection execution task.
     */
    taskName: string;
}

/**
 * A collection of values returned by getManagedDatabaseOptimizerStatisticsAdvisorExecution.
 */
export interface GetManagedDatabaseOptimizerStatisticsAdvisorExecutionResult {
    /**
     * The summary of the Managed Database resource.
     */
    readonly databases: outputs.DatabaseManagement.GetManagedDatabaseOptimizerStatisticsAdvisorExecutionDatabase[];
    /**
     * The errors in the Optimizer Statistics Advisor execution, if any.
     */
    readonly errorMessage: string;
    /**
     * The name of the Optimizer Statistics Advisor execution.
     */
    readonly executionName: string;
    /**
     * The list of findings for the rule.
     */
    readonly findings: number;
    /**
     * The provider-assigned unique ID for this managed resource.
     */
    readonly id: string;
    readonly managedDatabaseId: string;
    /**
     * A report that includes the rules, findings, recommendations, and actions discovered during the execution of the Optimizer Statistics Advisor.
     */
    readonly reports: outputs.DatabaseManagement.GetManagedDatabaseOptimizerStatisticsAdvisorExecutionReport[];
    /**
     * The status of the Optimizer Statistics Advisor execution.
     */
    readonly status: string;
    /**
     * The Optimizer Statistics Advisor execution status message, if any.
     */
    readonly statusMessage: string;
    /**
     * The name of the Optimizer Statistics Advisor task.
     */
    readonly taskName: string;
    /**
     * The end time of the time range to retrieve the Optimizer Statistics Advisor execution of a Managed Database in UTC in ISO-8601 format, which is "yyyy-MM-dd'T'hh:mm:ss.sss'Z'".
     */
    readonly timeEnd: string;
    /**
     * The start time of the time range to retrieve the Optimizer Statistics Advisor execution of a Managed Database in UTC in ISO-8601 format, which is "yyyy-MM-dd'T'hh:mm:ss.sss'Z'".
     */
    readonly timeStart: string;
}
/**
 * This data source provides details about a specific Managed Database Optimizer Statistics Advisor Execution resource in Oracle Cloud Infrastructure Database Management service.
 *
 * Gets a comprehensive report of the Optimizer Statistics Advisor execution, which includes details of the
 * Managed Database, findings, recommendations, rationale, and examples.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testManagedDatabaseOptimizerStatisticsAdvisorExecution = oci.DatabaseManagement.getManagedDatabaseOptimizerStatisticsAdvisorExecution({
 *     executionName: managedDatabaseOptimizerStatisticsAdvisorExecutionExecutionName,
 *     managedDatabaseId: testManagedDatabase.id,
 *     taskName: managedDatabaseOptimizerStatisticsAdvisorExecutionTaskName,
 * });
 * ```
 */
export function getManagedDatabaseOptimizerStatisticsAdvisorExecutionOutput(args: GetManagedDatabaseOptimizerStatisticsAdvisorExecutionOutputArgs, opts?: pulumi.InvokeOutputOptions): pulumi.Output<GetManagedDatabaseOptimizerStatisticsAdvisorExecutionResult> {
    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts || {});
    return pulumi.runtime.invokeOutput("oci:DatabaseManagement/getManagedDatabaseOptimizerStatisticsAdvisorExecution:getManagedDatabaseOptimizerStatisticsAdvisorExecution", {
        "executionName": args.executionName,
        "managedDatabaseId": args.managedDatabaseId,
        "taskName": args.taskName,
    }, opts);
}

/**
 * A collection of arguments for invoking getManagedDatabaseOptimizerStatisticsAdvisorExecution.
 */
export interface GetManagedDatabaseOptimizerStatisticsAdvisorExecutionOutputArgs {
    /**
     * The name of the Optimizer Statistics Advisor execution.
     */
    executionName: pulumi.Input<string>;
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Managed Database.
     */
    managedDatabaseId: pulumi.Input<string>;
    /**
     * The name of the optimizer statistics collection execution task.
     */
    taskName: pulumi.Input<string>;
}
