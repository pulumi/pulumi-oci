// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import * as inputs from "../types/input";
import * as outputs from "../types/output";
import * as utilities from "../utilities";

/**
 * This data source provides the list of Task Records in Oracle Cloud Infrastructure Fleet Apps Management service.
 *
 * Returns a list of TaskRecords.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testTaskRecords = oci.FleetAppsManagement.getTaskRecords({
 *     compartmentId: compartmentId,
 *     displayName: taskRecordDisplayName,
 *     id: taskRecordId,
 *     platform: taskRecordPlatform,
 *     state: taskRecordState,
 *     type: taskRecordType,
 * });
 * ```
 */
export function getTaskRecords(args?: GetTaskRecordsArgs, opts?: pulumi.InvokeOptions): Promise<GetTaskRecordsResult> {
    args = args || {};
    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts || {});
    return pulumi.runtime.invoke("oci:FleetAppsManagement/getTaskRecords:getTaskRecords", {
        "compartmentId": args.compartmentId,
        "displayName": args.displayName,
        "filters": args.filters,
        "id": args.id,
        "platform": args.platform,
        "state": args.state,
        "type": args.type,
    }, opts);
}

/**
 * A collection of arguments for invoking getTaskRecords.
 */
export interface GetTaskRecordsArgs {
    /**
     * The ID of the compartment in which to list resources.
     */
    compartmentId?: string;
    /**
     * A filter to return only resources that match the entire display name given.
     */
    displayName?: string;
    filters?: inputs.FleetAppsManagement.GetTaskRecordsFilter[];
    /**
     * unique TaskDetail identifier
     */
    id?: string;
    /**
     * The platform for the Task.
     */
    platform?: string;
    /**
     * The current state of the Task.
     */
    state?: string;
    /**
     * The type of the Task.
     */
    type?: string;
}

/**
 * A collection of values returned by getTaskRecords.
 */
export interface GetTaskRecordsResult {
    readonly compartmentId?: string;
    /**
     * A user-friendly name. Does not have to be unique, and it's changeable. Avoid entering confidential information.  Example: `My new resource`
     */
    readonly displayName?: string;
    readonly filters?: outputs.FleetAppsManagement.GetTaskRecordsFilter[];
    /**
     * The OCID of the resource.
     */
    readonly id?: string;
    /**
     * The platform of the runbook.
     */
    readonly platform?: string;
    /**
     * The current state of the TaskRecord.
     */
    readonly state?: string;
    /**
     * The list of task_record_collection.
     */
    readonly taskRecordCollections: outputs.FleetAppsManagement.GetTaskRecordsTaskRecordCollection[];
    /**
     * Task type.
     */
    readonly type?: string;
}
/**
 * This data source provides the list of Task Records in Oracle Cloud Infrastructure Fleet Apps Management service.
 *
 * Returns a list of TaskRecords.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testTaskRecords = oci.FleetAppsManagement.getTaskRecords({
 *     compartmentId: compartmentId,
 *     displayName: taskRecordDisplayName,
 *     id: taskRecordId,
 *     platform: taskRecordPlatform,
 *     state: taskRecordState,
 *     type: taskRecordType,
 * });
 * ```
 */
export function getTaskRecordsOutput(args?: GetTaskRecordsOutputArgs, opts?: pulumi.InvokeOutputOptions): pulumi.Output<GetTaskRecordsResult> {
    args = args || {};
    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts || {});
    return pulumi.runtime.invokeOutput("oci:FleetAppsManagement/getTaskRecords:getTaskRecords", {
        "compartmentId": args.compartmentId,
        "displayName": args.displayName,
        "filters": args.filters,
        "id": args.id,
        "platform": args.platform,
        "state": args.state,
        "type": args.type,
    }, opts);
}

/**
 * A collection of arguments for invoking getTaskRecords.
 */
export interface GetTaskRecordsOutputArgs {
    /**
     * The ID of the compartment in which to list resources.
     */
    compartmentId?: pulumi.Input<string>;
    /**
     * A filter to return only resources that match the entire display name given.
     */
    displayName?: pulumi.Input<string>;
    filters?: pulumi.Input<pulumi.Input<inputs.FleetAppsManagement.GetTaskRecordsFilterArgs>[]>;
    /**
     * unique TaskDetail identifier
     */
    id?: pulumi.Input<string>;
    /**
     * The platform for the Task.
     */
    platform?: pulumi.Input<string>;
    /**
     * The current state of the Task.
     */
    state?: pulumi.Input<string>;
    /**
     * The type of the Task.
     */
    type?: pulumi.Input<string>;
}
