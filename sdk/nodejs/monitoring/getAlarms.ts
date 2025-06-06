// *** WARNING: this file was generated by pulumi-language-nodejs. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import * as inputs from "../types/input";
import * as outputs from "../types/output";
import * as utilities from "../utilities";

/**
 * This data source provides the list of Alarms in Oracle Cloud Infrastructure Monitoring service.
 *
 * Lists the alarms for the specified compartment.
 * For more information, see
 * [Listing Alarms](https://docs.cloud.oracle.com/iaas/Content/Monitoring/Tasks/list-alarm.htm).
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
 * const testAlarms = oci.Monitoring.getAlarms({
 *     compartmentId: compartmentId,
 *     compartmentIdInSubtree: alarmCompartmentIdInSubtree,
 *     displayName: alarmDisplayName,
 *     state: alarmState,
 * });
 * ```
 */
export function getAlarms(args: GetAlarmsArgs, opts?: pulumi.InvokeOptions): Promise<GetAlarmsResult> {
    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts || {});
    return pulumi.runtime.invoke("oci:Monitoring/getAlarms:getAlarms", {
        "compartmentId": args.compartmentId,
        "compartmentIdInSubtree": args.compartmentIdInSubtree,
        "displayName": args.displayName,
        "filters": args.filters,
        "state": args.state,
    }, opts);
}

/**
 * A collection of arguments for invoking getAlarms.
 */
export interface GetAlarmsArgs {
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment containing the resources monitored by the metric that you are searching for. Use tenancyId to search in the root compartment.  Example: `ocid1.compartment.oc1..exampleuniqueID`
     */
    compartmentId: string;
    /**
     * When true, returns resources from all compartments and subcompartments. The parameter can only be set to true when compartmentId is the tenancy OCID (the tenancy is the root compartment). A true value requires the user to have tenancy-level permissions. If this requirement is not met, then the call is rejected. When false, returns resources from only the compartment specified in compartmentId. Default is false.
     */
    compartmentIdInSubtree?: boolean;
    /**
     * A filter to return only resources that match the given display name exactly. Use this filter to list an alarm by name. Alternatively, when you know the alarm OCID, use the GetAlarm operation.
     */
    displayName?: string;
    filters?: inputs.Monitoring.GetAlarmsFilter[];
    /**
     * A filter to return only alarms that match the given lifecycle state exactly. When not specified, only alarms in the ACTIVE lifecycle state are listed.
     */
    state?: string;
}

/**
 * A collection of values returned by getAlarms.
 */
export interface GetAlarmsResult {
    /**
     * The list of alarms.
     */
    readonly alarms: outputs.Monitoring.GetAlarmsAlarm[];
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment containing the alarm.
     */
    readonly compartmentId: string;
    readonly compartmentIdInSubtree?: boolean;
    /**
     * A user-friendly name for the alarm. It does not have to be unique, and it's changeable.
     */
    readonly displayName?: string;
    readonly filters?: outputs.Monitoring.GetAlarmsFilter[];
    /**
     * The provider-assigned unique ID for this managed resource.
     */
    readonly id: string;
    /**
     * The current lifecycle state of the alarm.  Example: `DELETED`
     */
    readonly state?: string;
}
/**
 * This data source provides the list of Alarms in Oracle Cloud Infrastructure Monitoring service.
 *
 * Lists the alarms for the specified compartment.
 * For more information, see
 * [Listing Alarms](https://docs.cloud.oracle.com/iaas/Content/Monitoring/Tasks/list-alarm.htm).
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
 * const testAlarms = oci.Monitoring.getAlarms({
 *     compartmentId: compartmentId,
 *     compartmentIdInSubtree: alarmCompartmentIdInSubtree,
 *     displayName: alarmDisplayName,
 *     state: alarmState,
 * });
 * ```
 */
export function getAlarmsOutput(args: GetAlarmsOutputArgs, opts?: pulumi.InvokeOutputOptions): pulumi.Output<GetAlarmsResult> {
    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts || {});
    return pulumi.runtime.invokeOutput("oci:Monitoring/getAlarms:getAlarms", {
        "compartmentId": args.compartmentId,
        "compartmentIdInSubtree": args.compartmentIdInSubtree,
        "displayName": args.displayName,
        "filters": args.filters,
        "state": args.state,
    }, opts);
}

/**
 * A collection of arguments for invoking getAlarms.
 */
export interface GetAlarmsOutputArgs {
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment containing the resources monitored by the metric that you are searching for. Use tenancyId to search in the root compartment.  Example: `ocid1.compartment.oc1..exampleuniqueID`
     */
    compartmentId: pulumi.Input<string>;
    /**
     * When true, returns resources from all compartments and subcompartments. The parameter can only be set to true when compartmentId is the tenancy OCID (the tenancy is the root compartment). A true value requires the user to have tenancy-level permissions. If this requirement is not met, then the call is rejected. When false, returns resources from only the compartment specified in compartmentId. Default is false.
     */
    compartmentIdInSubtree?: pulumi.Input<boolean>;
    /**
     * A filter to return only resources that match the given display name exactly. Use this filter to list an alarm by name. Alternatively, when you know the alarm OCID, use the GetAlarm operation.
     */
    displayName?: pulumi.Input<string>;
    filters?: pulumi.Input<pulumi.Input<inputs.Monitoring.GetAlarmsFilterArgs>[]>;
    /**
     * A filter to return only alarms that match the given lifecycle state exactly. When not specified, only alarms in the ACTIVE lifecycle state are listed.
     */
    state?: pulumi.Input<string>;
}
