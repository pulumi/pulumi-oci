// *** WARNING: this file was generated by pulumi-language-nodejs. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import * as inputs from "../types/input";
import * as outputs from "../types/output";
import * as utilities from "../utilities";

/**
 * This data source provides details about a specific Run Statement resource in Oracle Cloud Infrastructure Data Flow service.
 *
 * Retrieves the statement corresponding to the `statementId` for a Session run specified by `runId`.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testRunStatement = oci.DataFlow.getRunStatement({
 *     runId: testRun.id,
 *     statementId: testStatement.id,
 * });
 * ```
 */
export function getRunStatement(args: GetRunStatementArgs, opts?: pulumi.InvokeOptions): Promise<GetRunStatementResult> {
    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts || {});
    return pulumi.runtime.invoke("oci:DataFlow/getRunStatement:getRunStatement", {
        "runId": args.runId,
        "statementId": args.statementId,
    }, opts);
}

/**
 * A collection of arguments for invoking getRunStatement.
 */
export interface GetRunStatementArgs {
    /**
     * The unique ID for the run
     */
    runId: string;
    /**
     * The unique ID for the statement.
     */
    statementId: string;
}

/**
 * A collection of values returned by getRunStatement.
 */
export interface GetRunStatementResult {
    /**
     * The statement code to execute. Example: `println(sc.version)`
     */
    readonly code: string;
    /**
     * The statement ID.
     */
    readonly id: string;
    /**
     * The execution output of a statement.
     */
    readonly outputs: outputs.DataFlow.GetRunStatementOutput[];
    /**
     * The execution progress.
     */
    readonly progress: number;
    /**
     * The ID of a run.
     */
    readonly runId: string;
    /**
     * The current state of this statement.
     */
    readonly state: string;
    readonly statementId: string;
    /**
     * The date and time a statement execution was completed, expressed in [RFC 3339](https://tools.ietf.org/html/rfc3339) timestamp format. Example: `2022-05-31T21:10:29.600Z`
     */
    readonly timeCompleted: string;
    /**
     * The date and time the resource was created, expressed in [RFC 3339](https://tools.ietf.org/html/rfc3339) timestamp format. Example: `2018-04-03T21:10:29.600Z`
     */
    readonly timeCreated: string;
}
/**
 * This data source provides details about a specific Run Statement resource in Oracle Cloud Infrastructure Data Flow service.
 *
 * Retrieves the statement corresponding to the `statementId` for a Session run specified by `runId`.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testRunStatement = oci.DataFlow.getRunStatement({
 *     runId: testRun.id,
 *     statementId: testStatement.id,
 * });
 * ```
 */
export function getRunStatementOutput(args: GetRunStatementOutputArgs, opts?: pulumi.InvokeOutputOptions): pulumi.Output<GetRunStatementResult> {
    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts || {});
    return pulumi.runtime.invokeOutput("oci:DataFlow/getRunStatement:getRunStatement", {
        "runId": args.runId,
        "statementId": args.statementId,
    }, opts);
}

/**
 * A collection of arguments for invoking getRunStatement.
 */
export interface GetRunStatementOutputArgs {
    /**
     * The unique ID for the run
     */
    runId: pulumi.Input<string>;
    /**
     * The unique ID for the statement.
     */
    statementId: pulumi.Input<string>;
}
