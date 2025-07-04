// *** WARNING: this file was generated by pulumi-language-nodejs. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import * as inputs from "../types/input";
import * as outputs from "../types/output";
import * as utilities from "../utilities";

/**
 * This data source provides details about a specific Scheduler Definition resource in Oracle Cloud Infrastructure Fleet Apps Management service.
 *
 * Get the details of a SchedulerDefinition that performs lifecycle management operations.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testSchedulerDefinition = oci.FleetAppsManagement.getSchedulerDefinition({
 *     schedulerDefinitionId: testSchedulerDefinitionOciFleetAppsManagementSchedulerDefinition.id,
 * });
 * ```
 */
export function getSchedulerDefinition(args: GetSchedulerDefinitionArgs, opts?: pulumi.InvokeOptions): Promise<GetSchedulerDefinitionResult> {
    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts || {});
    return pulumi.runtime.invoke("oci:FleetAppsManagement/getSchedulerDefinition:getSchedulerDefinition", {
        "schedulerDefinitionId": args.schedulerDefinitionId,
    }, opts);
}

/**
 * A collection of arguments for invoking getSchedulerDefinition.
 */
export interface GetSchedulerDefinitionArgs {
    /**
     * unique SchedulerDefinition identifier
     */
    schedulerDefinitionId: string;
}

/**
 * A collection of values returned by getSchedulerDefinition.
 */
export interface GetSchedulerDefinitionResult {
    /**
     * Action Groups associated with the Schedule.
     */
    readonly actionGroups: outputs.FleetAppsManagement.GetSchedulerDefinitionActionGroup[];
    /**
     * Compartment OCID
     */
    readonly compartmentId: string;
    /**
     * Count of Action Groups affected by the Schedule.
     */
    readonly countOfAffectedActionGroups: number;
    /**
     * Count of Resources affected by the Schedule.
     */
    readonly countOfAffectedResources: number;
    /**
     * Count of Targets affected by the Schedule.
     */
    readonly countOfAffectedTargets: number;
    /**
     * Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
     */
    readonly definedTags: {[key: string]: string};
    /**
     * A user-friendly description. To provide some insight about the resource. Avoid entering confidential information.
     */
    readonly description: string;
    /**
     * A user-friendly name. Does not have to be unique, and it's changeable. Avoid entering confidential information.  Example: `My new resource`
     */
    readonly displayName: string;
    /**
     * Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
     */
    readonly freeformTags: {[key: string]: string};
    /**
     * The OCID of the resource.
     */
    readonly id: string;
    /**
     * A message describing the current state in more detail. For example, can be used to provide actionable information for a resource in Failed state.
     */
    readonly lifecycleDetails: string;
    /**
     * All LifeCycle Operations that are part of the schedule.
     */
    readonly lifecycleOperations: string[];
    /**
     * All products that are part of the schedule for PRODUCT ActionGroup Type.
     */
    readonly products: string[];
    /**
     * Associated region
     */
    readonly resourceRegion: string;
    /**
     * Runbooks.
     */
    readonly runBooks: outputs.FleetAppsManagement.GetSchedulerDefinitionRunBook[];
    readonly schedulerDefinitionId: string;
    /**
     * Schedule Information.
     */
    readonly schedules: outputs.FleetAppsManagement.GetSchedulerDefinitionSchedule[];
    /**
     * The current state of the SchedulerDefinition.
     */
    readonly state: string;
    /**
     * System tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"orcl-cloud.free-tier-retained": "true"}`
     */
    readonly systemTags: {[key: string]: string};
    /**
     * The time this resource was created. An RFC3339 formatted datetime string.
     */
    readonly timeCreated: string;
    /**
     * The scheduled date for the next run of the Job.
     */
    readonly timeOfNextRun: string;
    /**
     * The time this resource was last updated. An RFC3339 formatted datetime string.
     */
    readonly timeUpdated: string;
}
/**
 * This data source provides details about a specific Scheduler Definition resource in Oracle Cloud Infrastructure Fleet Apps Management service.
 *
 * Get the details of a SchedulerDefinition that performs lifecycle management operations.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testSchedulerDefinition = oci.FleetAppsManagement.getSchedulerDefinition({
 *     schedulerDefinitionId: testSchedulerDefinitionOciFleetAppsManagementSchedulerDefinition.id,
 * });
 * ```
 */
export function getSchedulerDefinitionOutput(args: GetSchedulerDefinitionOutputArgs, opts?: pulumi.InvokeOutputOptions): pulumi.Output<GetSchedulerDefinitionResult> {
    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts || {});
    return pulumi.runtime.invokeOutput("oci:FleetAppsManagement/getSchedulerDefinition:getSchedulerDefinition", {
        "schedulerDefinitionId": args.schedulerDefinitionId,
    }, opts);
}

/**
 * A collection of arguments for invoking getSchedulerDefinition.
 */
export interface GetSchedulerDefinitionOutputArgs {
    /**
     * unique SchedulerDefinition identifier
     */
    schedulerDefinitionId: pulumi.Input<string>;
}
