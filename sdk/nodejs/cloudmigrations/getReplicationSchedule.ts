// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import * as utilities from "../utilities";

/**
 * This data source provides details about a specific Replication Schedule resource in Oracle Cloud Infrastructure Cloud Migrations service.
 *
 * Gets a replication schedule by identifier.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testReplicationSchedule = oci.CloudMigrations.getReplicationSchedule({
 *     replicationScheduleId: oci_cloud_migrations_replication_schedule.test_replication_schedule.id,
 * });
 * ```
 */
export function getReplicationSchedule(args: GetReplicationScheduleArgs, opts?: pulumi.InvokeOptions): Promise<GetReplicationScheduleResult> {

    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts || {});
    return pulumi.runtime.invoke("oci:CloudMigrations/getReplicationSchedule:getReplicationSchedule", {
        "replicationScheduleId": args.replicationScheduleId,
    }, opts);
}

/**
 * A collection of arguments for invoking getReplicationSchedule.
 */
export interface GetReplicationScheduleArgs {
    /**
     * Unique replication schedule identifier in path
     */
    replicationScheduleId: string;
}

/**
 * A collection of values returned by getReplicationSchedule.
 */
export interface GetReplicationScheduleResult {
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment in which the replication schedule exists.
     */
    readonly compartmentId: string;
    /**
     * Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
     */
    readonly definedTags: {[key: string]: any};
    /**
     * A name of the replication schedule.
     */
    readonly displayName: string;
    /**
     * Recurrence specification for the replication schedule execution.
     */
    readonly executionRecurrences: string;
    /**
     * Simple key-value pair that is applied without any predefined name, type or scope. It exists only for cross-compatibility. Example: `{"bar-key": "value"}`
     */
    readonly freeformTags: {[key: string]: any};
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the replication schedule.
     */
    readonly id: string;
    /**
     * The detailed state of the replication schedule.
     */
    readonly lifecycleDetails: string;
    readonly replicationScheduleId: string;
    /**
     * Current state of the replication schedule.
     */
    readonly state: string;
    /**
     * Usage of system tag keys. These predefined keys are scoped to namespaces. Example: `{"orcl-cloud.free-tier-retained": "true"}`
     */
    readonly systemTags: {[key: string]: any};
    /**
     * The time when the replication schedule was created in RFC3339 format.
     */
    readonly timeCreated: string;
    /**
     * The time when the replication schedule was last updated in RFC3339 format.
     */
    readonly timeUpdated: string;
}
/**
 * This data source provides details about a specific Replication Schedule resource in Oracle Cloud Infrastructure Cloud Migrations service.
 *
 * Gets a replication schedule by identifier.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testReplicationSchedule = oci.CloudMigrations.getReplicationSchedule({
 *     replicationScheduleId: oci_cloud_migrations_replication_schedule.test_replication_schedule.id,
 * });
 * ```
 */
export function getReplicationScheduleOutput(args: GetReplicationScheduleOutputArgs, opts?: pulumi.InvokeOptions): pulumi.Output<GetReplicationScheduleResult> {
    return pulumi.output(args).apply((a: any) => getReplicationSchedule(a, opts))
}

/**
 * A collection of arguments for invoking getReplicationSchedule.
 */
export interface GetReplicationScheduleOutputArgs {
    /**
     * Unique replication schedule identifier in path
     */
    replicationScheduleId: pulumi.Input<string>;
}