// *** WARNING: this file was generated by pulumi-language-nodejs. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import * as inputs from "../types/input";
import * as outputs from "../types/output";
import * as utilities from "../utilities";

/**
 * This data source provides details about a specific Namespace Scheduled Task resource in Oracle Cloud Infrastructure Log Analytics service.
 *
 * Get the scheduled task for the specified task identifier.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testNamespaceScheduledTask = oci.LogAnalytics.getNamespaceScheduledTask({
 *     namespace: namespaceScheduledTaskNamespace,
 *     scheduledTaskId: testScheduledTask.id,
 * });
 * ```
 */
export function getNamespaceScheduledTask(args: GetNamespaceScheduledTaskArgs, opts?: pulumi.InvokeOptions): Promise<GetNamespaceScheduledTaskResult> {
    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts || {});
    return pulumi.runtime.invoke("oci:LogAnalytics/getNamespaceScheduledTask:getNamespaceScheduledTask", {
        "namespace": args.namespace,
        "scheduledTaskId": args.scheduledTaskId,
    }, opts);
}

/**
 * A collection of arguments for invoking getNamespaceScheduledTask.
 */
export interface GetNamespaceScheduledTaskArgs {
    /**
     * The Logging Analytics namespace used for the request.
     */
    namespace: string;
    /**
     * Unique scheduledTask id returned from task create. If invalid will lead to a 404 not found.
     */
    scheduledTaskId: string;
}

/**
 * A collection of values returned by getNamespaceScheduledTask.
 */
export interface GetNamespaceScheduledTaskResult {
    /**
     * Action for scheduled task.
     */
    readonly actions: outputs.LogAnalytics.GetNamespaceScheduledTaskAction[];
    /**
     * Compartment Identifier [OCID] (https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
     */
    readonly compartmentId: string;
    /**
     * Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
     */
    readonly definedTags: {[key: string]: string};
    /**
     * A user-friendly name that is changeable and that does not have to be unique. Format: a leading alphanumeric, followed by zero or more alphanumerics, underscores, spaces, backslashes, or hyphens in any order). No trailing spaces allowed.
     */
    readonly displayName: string;
    /**
     * Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
     */
    readonly freeformTags: {[key: string]: string};
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the data plane resource.
     */
    readonly id: string;
    /**
     * Discriminator.
     */
    readonly kind: string;
    /**
     * The namespace of the extracted metric. A valid value starts with an alphabetical character and includes only alphanumeric characters and underscores (_).
     */
    readonly namespace: string;
    /**
     * Number of execution occurrences.
     */
    readonly numOccurrences: string;
    /**
     * The ManagementSavedSearch id [OCID] utilized in the action.
     */
    readonly savedSearchId: string;
    readonly scheduledTaskId: string;
    /**
     * Schedules.
     */
    readonly schedules: outputs.LogAnalytics.GetNamespaceScheduledTaskSchedule[];
    /**
     * The current state of the scheduled task.
     */
    readonly state: string;
    /**
     * Status of the scheduled task. - PURGE_RESOURCE_NOT_FOUND
     */
    readonly taskStatus: string;
    /**
     * Task type.
     */
    readonly taskType: string;
    /**
     * The date and time the scheduled task was created, in the format defined by RFC3339.
     */
    readonly timeCreated: string;
    /**
     * The date and time the scheduled task was last updated, in the format defined by RFC3339.
     */
    readonly timeUpdated: string;
    /**
     * most recent Work Request Identifier [OCID] (https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) for the asynchronous request.
     */
    readonly workRequestId: string;
}
/**
 * This data source provides details about a specific Namespace Scheduled Task resource in Oracle Cloud Infrastructure Log Analytics service.
 *
 * Get the scheduled task for the specified task identifier.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testNamespaceScheduledTask = oci.LogAnalytics.getNamespaceScheduledTask({
 *     namespace: namespaceScheduledTaskNamespace,
 *     scheduledTaskId: testScheduledTask.id,
 * });
 * ```
 */
export function getNamespaceScheduledTaskOutput(args: GetNamespaceScheduledTaskOutputArgs, opts?: pulumi.InvokeOutputOptions): pulumi.Output<GetNamespaceScheduledTaskResult> {
    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts || {});
    return pulumi.runtime.invokeOutput("oci:LogAnalytics/getNamespaceScheduledTask:getNamespaceScheduledTask", {
        "namespace": args.namespace,
        "scheduledTaskId": args.scheduledTaskId,
    }, opts);
}

/**
 * A collection of arguments for invoking getNamespaceScheduledTask.
 */
export interface GetNamespaceScheduledTaskOutputArgs {
    /**
     * The Logging Analytics namespace used for the request.
     */
    namespace: pulumi.Input<string>;
    /**
     * Unique scheduledTask id returned from task create. If invalid will lead to a 404 not found.
     */
    scheduledTaskId: pulumi.Input<string>;
}
