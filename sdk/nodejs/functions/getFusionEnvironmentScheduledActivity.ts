// *** WARNING: this file was generated by pulumi-language-nodejs. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import * as inputs from "../types/input";
import * as outputs from "../types/output";
import * as utilities from "../utilities";

/**
 * This data source provides details about a specific Fusion Environment Scheduled Activity resource in Oracle Cloud Infrastructure Fusion Apps service.
 *
 * Gets a ScheduledActivity by identifier
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testFusionEnvironmentScheduledActivity = oci.Functions.getFusionEnvironmentScheduledActivity({
 *     fusionEnvironmentId: testFusionEnvironment.id,
 *     scheduledActivityId: testScheduledActivity.id,
 * });
 * ```
 */
export function getFusionEnvironmentScheduledActivity(args: GetFusionEnvironmentScheduledActivityArgs, opts?: pulumi.InvokeOptions): Promise<GetFusionEnvironmentScheduledActivityResult> {
    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts || {});
    return pulumi.runtime.invoke("oci:Functions/getFusionEnvironmentScheduledActivity:getFusionEnvironmentScheduledActivity", {
        "fusionEnvironmentId": args.fusionEnvironmentId,
        "scheduledActivityId": args.scheduledActivityId,
    }, opts);
}

/**
 * A collection of arguments for invoking getFusionEnvironmentScheduledActivity.
 */
export interface GetFusionEnvironmentScheduledActivityArgs {
    /**
     * unique FusionEnvironment identifier
     */
    fusionEnvironmentId: string;
    /**
     * Unique ScheduledActivity identifier.
     */
    scheduledActivityId: string;
}

/**
 * A collection of values returned by getFusionEnvironmentScheduledActivity.
 */
export interface GetFusionEnvironmentScheduledActivityResult {
    /**
     * List of actions
     */
    readonly actions: outputs.Functions.GetFusionEnvironmentScheduledActivityAction[];
    /**
     * Cumulative delay hours
     */
    readonly delayInHours: number;
    /**
     * scheduled activity display name, can be renamed.
     */
    readonly displayName: string;
    /**
     * FAaaS Environment Identifier.
     */
    readonly fusionEnvironmentId: string;
    /**
     * The provider-assigned unique ID for this managed resource.
     */
    readonly id: string;
    /**
     * A message describing the current state in more detail. For example, can be used to provide actionable information for a resource in Failed state.
     */
    readonly lifecycleDetails: string;
    /**
     * run cadence.
     */
    readonly runCycle: string;
    readonly scheduledActivityId: string;
    /**
     * Service availability / impact during scheduled activity execution up down
     */
    readonly serviceAvailability: string;
    /**
     * The current state of the scheduledActivity.
     */
    readonly state: string;
    /**
     * The time the scheduled activity record was created. An RFC3339 formatted datetime string.
     */
    readonly timeCreated: string;
    /**
     * Current time the scheduled activity is scheduled to end. An RFC3339 formatted datetime string.
     */
    readonly timeExpectedFinish: string;
    /**
     * The time the scheduled activity actually completed / cancelled / failed. An RFC3339 formatted datetime string.
     */
    readonly timeFinished: string;
    /**
     * Current time the scheduled activity is scheduled to start. An RFC3339 formatted datetime string.
     */
    readonly timeScheduledStart: string;
    /**
     * The time the scheduled activity record was updated. An RFC3339 formatted datetime string.
     */
    readonly timeUpdated: string;
}
/**
 * This data source provides details about a specific Fusion Environment Scheduled Activity resource in Oracle Cloud Infrastructure Fusion Apps service.
 *
 * Gets a ScheduledActivity by identifier
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testFusionEnvironmentScheduledActivity = oci.Functions.getFusionEnvironmentScheduledActivity({
 *     fusionEnvironmentId: testFusionEnvironment.id,
 *     scheduledActivityId: testScheduledActivity.id,
 * });
 * ```
 */
export function getFusionEnvironmentScheduledActivityOutput(args: GetFusionEnvironmentScheduledActivityOutputArgs, opts?: pulumi.InvokeOutputOptions): pulumi.Output<GetFusionEnvironmentScheduledActivityResult> {
    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts || {});
    return pulumi.runtime.invokeOutput("oci:Functions/getFusionEnvironmentScheduledActivity:getFusionEnvironmentScheduledActivity", {
        "fusionEnvironmentId": args.fusionEnvironmentId,
        "scheduledActivityId": args.scheduledActivityId,
    }, opts);
}

/**
 * A collection of arguments for invoking getFusionEnvironmentScheduledActivity.
 */
export interface GetFusionEnvironmentScheduledActivityOutputArgs {
    /**
     * unique FusionEnvironment identifier
     */
    fusionEnvironmentId: pulumi.Input<string>;
    /**
     * Unique ScheduledActivity identifier.
     */
    scheduledActivityId: pulumi.Input<string>;
}
