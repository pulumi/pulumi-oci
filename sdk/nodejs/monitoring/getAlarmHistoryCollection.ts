// *** WARNING: this file was generated by pulumi-language-nodejs. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import * as inputs from "../types/input";
import * as outputs from "../types/output";
import * as utilities from "../utilities";

/**
 * This data source provides details about a specific Alarm History Collection resource in Oracle Cloud Infrastructure Monitoring service.
 *
 * Get the history of the specified alarm.
 * For more information, see
 * [Getting History of an Alarm](https://docs.cloud.oracle.com/iaas/Content/Monitoring/Tasks/get-alarm-history.htm).
 * For important limits information, see
 * [Limits on Monitoring](https://docs.cloud.oracle.com/iaas/Content/Monitoring/Concepts/monitoringoverview.htm#limits).
 *
 * This call is subject to a Monitoring limit that applies to the total number of requests across all alarm operations.
 * Monitoring might throttle this call to reject an otherwise valid request when the total rate of alarm operations exceeds 10 requests,
 * or transactions, per second (TPS) for a given tenancy.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testAlarmHistoryCollection = oci.Monitoring.getAlarmHistoryCollection({
 *     alarmId: testAlarm.id,
 *     alarmHistorytype: alarmHistoryCollectionAlarmHistorytype,
 *     timestampGreaterThanOrEqualTo: alarmHistoryCollectionTimestampGreaterThanOrEqualTo,
 *     timestampLessThan: alarmHistoryCollectionTimestampLessThan,
 * });
 * ```
 */
export function getAlarmHistoryCollection(args: GetAlarmHistoryCollectionArgs, opts?: pulumi.InvokeOptions): Promise<GetAlarmHistoryCollectionResult> {
    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts || {});
    return pulumi.runtime.invoke("oci:Monitoring/getAlarmHistoryCollection:getAlarmHistoryCollection", {
        "alarmHistorytype": args.alarmHistorytype,
        "alarmId": args.alarmId,
        "timestampGreaterThanOrEqualTo": args.timestampGreaterThanOrEqualTo,
        "timestampLessThan": args.timestampLessThan,
    }, opts);
}

/**
 * A collection of arguments for invoking getAlarmHistoryCollection.
 */
export interface GetAlarmHistoryCollectionArgs {
    /**
     * The type of history entries to retrieve. State history (STATE_HISTORY), state transition history (STATE_TRANSITION_HISTORY), rule history (RULE_HISTORY) or rule transition history (RULE_TRANSITION_HISTORY). If not specified, entries of all types are retrieved.  Example: `STATE_HISTORY`
     */
    alarmHistorytype?: string;
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of an alarm.
     */
    alarmId: string;
    /**
     * A filter to return only alarm history entries with timestamps occurring on or after the specified date and time. Format defined by RFC3339.  Example: `2023-01-01T01:00:00.789Z`
     */
    timestampGreaterThanOrEqualTo?: string;
    /**
     * A filter to return only alarm history entries with timestamps occurring before the specified date and time. Format defined by RFC3339.  Example: `2023-01-02T01:00:00.789Z`
     */
    timestampLessThan?: string;
}

/**
 * A collection of values returned by getAlarmHistoryCollection.
 */
export interface GetAlarmHistoryCollectionResult {
    readonly alarmHistorytype?: string;
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the alarm to retrieve history for.
     */
    readonly alarmId: string;
    /**
     * The set of history entries retrieved for the alarm.
     */
    readonly entries: outputs.Monitoring.GetAlarmHistoryCollectionEntry[];
    /**
     * The provider-assigned unique ID for this managed resource.
     */
    readonly id: string;
    /**
     * Whether the alarm is enabled.  Example: `true`
     */
    readonly isEnabled: boolean;
    readonly timestampGreaterThanOrEqualTo?: string;
    readonly timestampLessThan?: string;
}
/**
 * This data source provides details about a specific Alarm History Collection resource in Oracle Cloud Infrastructure Monitoring service.
 *
 * Get the history of the specified alarm.
 * For more information, see
 * [Getting History of an Alarm](https://docs.cloud.oracle.com/iaas/Content/Monitoring/Tasks/get-alarm-history.htm).
 * For important limits information, see
 * [Limits on Monitoring](https://docs.cloud.oracle.com/iaas/Content/Monitoring/Concepts/monitoringoverview.htm#limits).
 *
 * This call is subject to a Monitoring limit that applies to the total number of requests across all alarm operations.
 * Monitoring might throttle this call to reject an otherwise valid request when the total rate of alarm operations exceeds 10 requests,
 * or transactions, per second (TPS) for a given tenancy.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testAlarmHistoryCollection = oci.Monitoring.getAlarmHistoryCollection({
 *     alarmId: testAlarm.id,
 *     alarmHistorytype: alarmHistoryCollectionAlarmHistorytype,
 *     timestampGreaterThanOrEqualTo: alarmHistoryCollectionTimestampGreaterThanOrEqualTo,
 *     timestampLessThan: alarmHistoryCollectionTimestampLessThan,
 * });
 * ```
 */
export function getAlarmHistoryCollectionOutput(args: GetAlarmHistoryCollectionOutputArgs, opts?: pulumi.InvokeOutputOptions): pulumi.Output<GetAlarmHistoryCollectionResult> {
    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts || {});
    return pulumi.runtime.invokeOutput("oci:Monitoring/getAlarmHistoryCollection:getAlarmHistoryCollection", {
        "alarmHistorytype": args.alarmHistorytype,
        "alarmId": args.alarmId,
        "timestampGreaterThanOrEqualTo": args.timestampGreaterThanOrEqualTo,
        "timestampLessThan": args.timestampLessThan,
    }, opts);
}

/**
 * A collection of arguments for invoking getAlarmHistoryCollection.
 */
export interface GetAlarmHistoryCollectionOutputArgs {
    /**
     * The type of history entries to retrieve. State history (STATE_HISTORY), state transition history (STATE_TRANSITION_HISTORY), rule history (RULE_HISTORY) or rule transition history (RULE_TRANSITION_HISTORY). If not specified, entries of all types are retrieved.  Example: `STATE_HISTORY`
     */
    alarmHistorytype?: pulumi.Input<string>;
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of an alarm.
     */
    alarmId: pulumi.Input<string>;
    /**
     * A filter to return only alarm history entries with timestamps occurring on or after the specified date and time. Format defined by RFC3339.  Example: `2023-01-01T01:00:00.789Z`
     */
    timestampGreaterThanOrEqualTo?: pulumi.Input<string>;
    /**
     * A filter to return only alarm history entries with timestamps occurring before the specified date and time. Format defined by RFC3339.  Example: `2023-01-02T01:00:00.789Z`
     */
    timestampLessThan?: pulumi.Input<string>;
}
