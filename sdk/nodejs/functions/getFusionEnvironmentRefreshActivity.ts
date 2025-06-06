// *** WARNING: this file was generated by pulumi-language-nodejs. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import * as inputs from "../types/input";
import * as outputs from "../types/output";
import * as utilities from "../utilities";

/**
 * This data source provides details about a specific Fusion Environment Refresh Activity resource in Oracle Cloud Infrastructure Fusion Apps service.
 *
 * Gets a RefreshActivity by identifier
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testFusionEnvironmentRefreshActivity = oci.Functions.getFusionEnvironmentRefreshActivity({
 *     fusionEnvironmentId: testFusionEnvironment.id,
 *     refreshActivityId: testRefreshActivity.id,
 * });
 * ```
 */
export function getFusionEnvironmentRefreshActivity(args: GetFusionEnvironmentRefreshActivityArgs, opts?: pulumi.InvokeOptions): Promise<GetFusionEnvironmentRefreshActivityResult> {
    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts || {});
    return pulumi.runtime.invoke("oci:Functions/getFusionEnvironmentRefreshActivity:getFusionEnvironmentRefreshActivity", {
        "fusionEnvironmentId": args.fusionEnvironmentId,
        "refreshActivityId": args.refreshActivityId,
    }, opts);
}

/**
 * A collection of arguments for invoking getFusionEnvironmentRefreshActivity.
 */
export interface GetFusionEnvironmentRefreshActivityArgs {
    /**
     * unique FusionEnvironment identifier
     */
    fusionEnvironmentId: string;
    /**
     * The unique identifier (OCID) of the Refresh activity.
     */
    refreshActivityId: string;
}

/**
 * A collection of values returned by getFusionEnvironmentRefreshActivity.
 */
export interface GetFusionEnvironmentRefreshActivityResult {
    /**
     * A friendly name for the refresh activity. Can be changed later.
     */
    readonly displayName: string;
    readonly fusionEnvironmentId: string;
    /**
     * The unique identifier (OCID) of the refresh activity. Can't be changed after creation.
     */
    readonly id: string;
    /**
     * Represents if the customer opted for Data Masking or not during refreshActivity.
     */
    readonly isDataMaskingOpted: boolean;
    /**
     * A message describing the current state in more detail. For example, can be used to provide actionable information for a resource in Failed state.
     */
    readonly lifecycleDetails: string;
    readonly refreshActivityId: string;
    /**
     * Details of refresh investigation information, each item represents a different issue.
     */
    readonly refreshIssueDetailsLists: outputs.Functions.GetFusionEnvironmentRefreshActivityRefreshIssueDetailsList[];
    /**
     * Service availability / impact during refresh activity execution up down
     */
    readonly serviceAvailability: string;
    /**
     * The OCID of the Fusion environment that is the source environment for the refresh.
     */
    readonly sourceFusionEnvironmentId: string;
    /**
     * The current state of the refreshActivity.
     */
    readonly state: string;
    /**
     * The time the refresh activity record was created. An RFC3339 formatted datetime string.
     */
    readonly timeAccepted: string;
    /**
     * The time the refresh activity is scheduled to end. An RFC3339 formatted datetime string.
     */
    readonly timeExpectedFinish: string;
    /**
     * The time the refresh activity actually completed / cancelled / failed. An RFC3339 formatted datetime string.
     */
    readonly timeFinished: string;
    /**
     * The date and time of the most recent source environment backup used for the environment refresh.
     */
    readonly timeOfRestorationPoint: string;
    /**
     * The time the refresh activity record was updated. An RFC3339 formatted datetime string.
     */
    readonly timeUpdated: string;
}
/**
 * This data source provides details about a specific Fusion Environment Refresh Activity resource in Oracle Cloud Infrastructure Fusion Apps service.
 *
 * Gets a RefreshActivity by identifier
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testFusionEnvironmentRefreshActivity = oci.Functions.getFusionEnvironmentRefreshActivity({
 *     fusionEnvironmentId: testFusionEnvironment.id,
 *     refreshActivityId: testRefreshActivity.id,
 * });
 * ```
 */
export function getFusionEnvironmentRefreshActivityOutput(args: GetFusionEnvironmentRefreshActivityOutputArgs, opts?: pulumi.InvokeOutputOptions): pulumi.Output<GetFusionEnvironmentRefreshActivityResult> {
    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts || {});
    return pulumi.runtime.invokeOutput("oci:Functions/getFusionEnvironmentRefreshActivity:getFusionEnvironmentRefreshActivity", {
        "fusionEnvironmentId": args.fusionEnvironmentId,
        "refreshActivityId": args.refreshActivityId,
    }, opts);
}

/**
 * A collection of arguments for invoking getFusionEnvironmentRefreshActivity.
 */
export interface GetFusionEnvironmentRefreshActivityOutputArgs {
    /**
     * unique FusionEnvironment identifier
     */
    fusionEnvironmentId: pulumi.Input<string>;
    /**
     * The unique identifier (OCID) of the Refresh activity.
     */
    refreshActivityId: pulumi.Input<string>;
}
