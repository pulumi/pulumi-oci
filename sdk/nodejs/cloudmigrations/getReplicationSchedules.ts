// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import * as inputs from "../types/input";
import * as outputs from "../types/output";
import * as utilities from "../utilities";

/**
 * This data source provides the list of Replication Schedules in Oracle Cloud Infrastructure Cloud Migrations service.
 *
 * Returns a list of replication schedules.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testReplicationSchedules = oci.CloudMigrations.getReplicationSchedules({
 *     compartmentId: _var.compartment_id,
 *     displayName: _var.replication_schedule_display_name,
 *     replicationScheduleId: oci_cloud_migrations_replication_schedule.test_replication_schedule.id,
 *     state: _var.replication_schedule_state,
 * });
 * ```
 */
export function getReplicationSchedules(args?: GetReplicationSchedulesArgs, opts?: pulumi.InvokeOptions): Promise<GetReplicationSchedulesResult> {
    args = args || {};

    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts || {});
    return pulumi.runtime.invoke("oci:CloudMigrations/getReplicationSchedules:getReplicationSchedules", {
        "compartmentId": args.compartmentId,
        "displayName": args.displayName,
        "filters": args.filters,
        "replicationScheduleId": args.replicationScheduleId,
        "state": args.state,
    }, opts);
}

/**
 * A collection of arguments for invoking getReplicationSchedules.
 */
export interface GetReplicationSchedulesArgs {
    /**
     * The ID of the compartment in which to list resources.
     */
    compartmentId?: string;
    /**
     * A filter to return only resources that match the entire given display name.
     */
    displayName?: string;
    filters?: inputs.CloudMigrations.GetReplicationSchedulesFilter[];
    /**
     * Unique replication schedule identifier in query
     */
    replicationScheduleId?: string;
    /**
     * The current state of the replication schedule.
     */
    state?: string;
}

/**
 * A collection of values returned by getReplicationSchedules.
 */
export interface GetReplicationSchedulesResult {
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment in which the replication schedule exists.
     */
    readonly compartmentId?: string;
    /**
     * A name of the replication schedule.
     */
    readonly displayName?: string;
    readonly filters?: outputs.CloudMigrations.GetReplicationSchedulesFilter[];
    /**
     * The provider-assigned unique ID for this managed resource.
     */
    readonly id: string;
    /**
     * The list of replication_schedule_collection.
     */
    readonly replicationScheduleCollections: outputs.CloudMigrations.GetReplicationSchedulesReplicationScheduleCollection[];
    readonly replicationScheduleId?: string;
    /**
     * Current state of the replication schedule.
     */
    readonly state?: string;
}
/**
 * This data source provides the list of Replication Schedules in Oracle Cloud Infrastructure Cloud Migrations service.
 *
 * Returns a list of replication schedules.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testReplicationSchedules = oci.CloudMigrations.getReplicationSchedules({
 *     compartmentId: _var.compartment_id,
 *     displayName: _var.replication_schedule_display_name,
 *     replicationScheduleId: oci_cloud_migrations_replication_schedule.test_replication_schedule.id,
 *     state: _var.replication_schedule_state,
 * });
 * ```
 */
export function getReplicationSchedulesOutput(args?: GetReplicationSchedulesOutputArgs, opts?: pulumi.InvokeOptions): pulumi.Output<GetReplicationSchedulesResult> {
    return pulumi.output(args).apply((a: any) => getReplicationSchedules(a, opts))
}

/**
 * A collection of arguments for invoking getReplicationSchedules.
 */
export interface GetReplicationSchedulesOutputArgs {
    /**
     * The ID of the compartment in which to list resources.
     */
    compartmentId?: pulumi.Input<string>;
    /**
     * A filter to return only resources that match the entire given display name.
     */
    displayName?: pulumi.Input<string>;
    filters?: pulumi.Input<pulumi.Input<inputs.CloudMigrations.GetReplicationSchedulesFilterArgs>[]>;
    /**
     * Unique replication schedule identifier in query
     */
    replicationScheduleId?: pulumi.Input<string>;
    /**
     * The current state of the replication schedule.
     */
    state?: pulumi.Input<string>;
}