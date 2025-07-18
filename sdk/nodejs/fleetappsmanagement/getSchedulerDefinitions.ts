// *** WARNING: this file was generated by pulumi-language-nodejs. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import * as inputs from "../types/input";
import * as outputs from "../types/output";
import * as utilities from "../utilities";

/**
 * This data source provides the list of Scheduler Definitions in Oracle Cloud Infrastructure Fleet Apps Management service.
 *
 * Returns a list of all the Schedule Definitions in the specified compartment.
 * The query parameter `compartmentId` is required unless the query parameter `id` is specified.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testSchedulerDefinitions = oci.FleetAppsManagement.getSchedulerDefinitions({
 *     compartmentId: compartmentId,
 *     displayName: schedulerDefinitionDisplayName,
 *     fleetId: testFleet.id,
 *     id: schedulerDefinitionId,
 *     maintenanceWindowId: testMaintenanceWindow.id,
 *     product: schedulerDefinitionProduct,
 *     runbookId: testRunbook.id,
 *     runbookVersionName: testRunbookVersion.name,
 *     state: schedulerDefinitionState,
 *     timeScheduledGreaterThanOrEqualTo: schedulerDefinitionTimeScheduledGreaterThanOrEqualTo,
 *     timeScheduledLessThan: schedulerDefinitionTimeScheduledLessThan,
 * });
 * ```
 */
export function getSchedulerDefinitions(args?: GetSchedulerDefinitionsArgs, opts?: pulumi.InvokeOptions): Promise<GetSchedulerDefinitionsResult> {
    args = args || {};
    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts || {});
    return pulumi.runtime.invoke("oci:FleetAppsManagement/getSchedulerDefinitions:getSchedulerDefinitions", {
        "compartmentId": args.compartmentId,
        "displayName": args.displayName,
        "filters": args.filters,
        "fleetId": args.fleetId,
        "id": args.id,
        "maintenanceWindowId": args.maintenanceWindowId,
        "product": args.product,
        "runbookId": args.runbookId,
        "runbookVersionName": args.runbookVersionName,
        "state": args.state,
        "timeScheduledGreaterThanOrEqualTo": args.timeScheduledGreaterThanOrEqualTo,
        "timeScheduledLessThan": args.timeScheduledLessThan,
    }, opts);
}

/**
 * A collection of arguments for invoking getSchedulerDefinitions.
 */
export interface GetSchedulerDefinitionsArgs {
    /**
     * The ID of the compartment in which to list resources. Empty only if the resource OCID query param is not specified.
     */
    compartmentId?: string;
    /**
     * A filter to return only resources that match the entire display name given.
     */
    displayName?: string;
    filters?: inputs.FleetAppsManagement.GetSchedulerDefinitionsFilter[];
    /**
     * unique Fleet identifier
     */
    fleetId?: string;
    /**
     * Unique identifier or OCID for listing a single Schedule Definition by id. Either compartmentId or id must be provided.
     */
    id?: string;
    /**
     * A filter to return only schedule definitions whose associated maintenanceWindowId matches the given maintenanceWindowId.
     */
    maintenanceWindowId?: string;
    /**
     * A filter to return only dchedule definitions whose assocaited product matches the given product
     */
    product?: string;
    /**
     * A filter to return only schedule definitions whose associated runbookId matches the given runbookId.
     */
    runbookId?: string;
    /**
     * RunbookVersion Name filter
     */
    runbookVersionName?: string;
    /**
     * A filter to return only scheduleDefinitions whose lifecycleState matches the given lifecycleState.
     */
    state?: string;
    /**
     * Scheduled Time
     */
    timeScheduledGreaterThanOrEqualTo?: string;
    /**
     * Scheduled Time
     */
    timeScheduledLessThan?: string;
}

/**
 * A collection of values returned by getSchedulerDefinitions.
 */
export interface GetSchedulerDefinitionsResult {
    /**
     * Compartment OCID
     */
    readonly compartmentId?: string;
    /**
     * A user-friendly name. Does not have to be unique, and it's changeable. Avoid entering confidential information.  Example: `My new resource`
     */
    readonly displayName?: string;
    readonly filters?: outputs.FleetAppsManagement.GetSchedulerDefinitionsFilter[];
    /**
     * ID of the fleet
     */
    readonly fleetId?: string;
    /**
     * The OCID of the resource.
     */
    readonly id?: string;
    /**
     * Provide MaintenanceWindowId
     */
    readonly maintenanceWindowId?: string;
    readonly product?: string;
    /**
     * The ID of the Runbook
     */
    readonly runbookId?: string;
    /**
     * The runbook version name
     */
    readonly runbookVersionName?: string;
    /**
     * The list of scheduler_definition_collection.
     */
    readonly schedulerDefinitionCollections: outputs.FleetAppsManagement.GetSchedulerDefinitionsSchedulerDefinitionCollection[];
    /**
     * The current state of the SchedulerDefinition.
     */
    readonly state?: string;
    readonly timeScheduledGreaterThanOrEqualTo?: string;
    readonly timeScheduledLessThan?: string;
}
/**
 * This data source provides the list of Scheduler Definitions in Oracle Cloud Infrastructure Fleet Apps Management service.
 *
 * Returns a list of all the Schedule Definitions in the specified compartment.
 * The query parameter `compartmentId` is required unless the query parameter `id` is specified.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testSchedulerDefinitions = oci.FleetAppsManagement.getSchedulerDefinitions({
 *     compartmentId: compartmentId,
 *     displayName: schedulerDefinitionDisplayName,
 *     fleetId: testFleet.id,
 *     id: schedulerDefinitionId,
 *     maintenanceWindowId: testMaintenanceWindow.id,
 *     product: schedulerDefinitionProduct,
 *     runbookId: testRunbook.id,
 *     runbookVersionName: testRunbookVersion.name,
 *     state: schedulerDefinitionState,
 *     timeScheduledGreaterThanOrEqualTo: schedulerDefinitionTimeScheduledGreaterThanOrEqualTo,
 *     timeScheduledLessThan: schedulerDefinitionTimeScheduledLessThan,
 * });
 * ```
 */
export function getSchedulerDefinitionsOutput(args?: GetSchedulerDefinitionsOutputArgs, opts?: pulumi.InvokeOutputOptions): pulumi.Output<GetSchedulerDefinitionsResult> {
    args = args || {};
    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts || {});
    return pulumi.runtime.invokeOutput("oci:FleetAppsManagement/getSchedulerDefinitions:getSchedulerDefinitions", {
        "compartmentId": args.compartmentId,
        "displayName": args.displayName,
        "filters": args.filters,
        "fleetId": args.fleetId,
        "id": args.id,
        "maintenanceWindowId": args.maintenanceWindowId,
        "product": args.product,
        "runbookId": args.runbookId,
        "runbookVersionName": args.runbookVersionName,
        "state": args.state,
        "timeScheduledGreaterThanOrEqualTo": args.timeScheduledGreaterThanOrEqualTo,
        "timeScheduledLessThan": args.timeScheduledLessThan,
    }, opts);
}

/**
 * A collection of arguments for invoking getSchedulerDefinitions.
 */
export interface GetSchedulerDefinitionsOutputArgs {
    /**
     * The ID of the compartment in which to list resources. Empty only if the resource OCID query param is not specified.
     */
    compartmentId?: pulumi.Input<string>;
    /**
     * A filter to return only resources that match the entire display name given.
     */
    displayName?: pulumi.Input<string>;
    filters?: pulumi.Input<pulumi.Input<inputs.FleetAppsManagement.GetSchedulerDefinitionsFilterArgs>[]>;
    /**
     * unique Fleet identifier
     */
    fleetId?: pulumi.Input<string>;
    /**
     * Unique identifier or OCID for listing a single Schedule Definition by id. Either compartmentId or id must be provided.
     */
    id?: pulumi.Input<string>;
    /**
     * A filter to return only schedule definitions whose associated maintenanceWindowId matches the given maintenanceWindowId.
     */
    maintenanceWindowId?: pulumi.Input<string>;
    /**
     * A filter to return only dchedule definitions whose assocaited product matches the given product
     */
    product?: pulumi.Input<string>;
    /**
     * A filter to return only schedule definitions whose associated runbookId matches the given runbookId.
     */
    runbookId?: pulumi.Input<string>;
    /**
     * RunbookVersion Name filter
     */
    runbookVersionName?: pulumi.Input<string>;
    /**
     * A filter to return only scheduleDefinitions whose lifecycleState matches the given lifecycleState.
     */
    state?: pulumi.Input<string>;
    /**
     * Scheduled Time
     */
    timeScheduledGreaterThanOrEqualTo?: pulumi.Input<string>;
    /**
     * Scheduled Time
     */
    timeScheduledLessThan?: pulumi.Input<string>;
}
