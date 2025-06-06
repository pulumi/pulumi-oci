// *** WARNING: this file was generated by pulumi-language-nodejs. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import * as inputs from "../types/input";
import * as outputs from "../types/output";
import * as utilities from "../utilities";

/**
 * This data source provides details about a specific Monitor resource in Oracle Cloud Infrastructure APM Availability Monitoring service (aka APM Synthetics Service).
 *
 * Gets the configuration of the monitor identified by the OCID.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testMonitor = oci.ApmSynthetics.getMonitor({
 *     apmDomainId: testApmDomain.id,
 *     monitorId: testMonitorOciApmSyntheticsMonitor.id,
 * });
 * ```
 */
export function getMonitor(args: GetMonitorArgs, opts?: pulumi.InvokeOptions): Promise<GetMonitorResult> {
    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts || {});
    return pulumi.runtime.invoke("oci:ApmSynthetics/getMonitor:getMonitor", {
        "apmDomainId": args.apmDomainId,
        "monitorId": args.monitorId,
    }, opts);
}

/**
 * A collection of arguments for invoking getMonitor.
 */
export interface GetMonitorArgs {
    /**
     * The APM domain ID the request is intended for.
     */
    apmDomainId: string;
    /**
     * The OCID of the monitor.
     */
    monitorId: string;
}

/**
 * A collection of values returned by getMonitor.
 */
export interface GetMonitorResult {
    readonly apmDomainId: string;
    /**
     * Monitor availability configuration details.
     */
    readonly availabilityConfigurations: outputs.ApmSynthetics.GetMonitorAvailabilityConfiguration[];
    /**
     * Time interval between two runs in round robin batch mode (SchedulingPolicy - BATCHED_ROUND_ROBIN).
     */
    readonly batchIntervalInSeconds: number;
    /**
     * Details of monitor configuration.
     */
    readonly configurations: outputs.ApmSynthetics.GetMonitorConfiguration[];
    /**
     * Content type of the script.
     */
    readonly contentType: string;
    /**
     * Name of the user that created the monitor.
     */
    readonly createdBy: string;
    /**
     * Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
     */
    readonly definedTags: {[key: string]: string};
    /**
     * Unique name that can be edited. The name should not contain any confidential information.
     */
    readonly displayName: string;
    /**
     * Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
     */
    readonly freeformTags: {[key: string]: string};
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the monitor.
     */
    readonly id: string;
    /**
     * If enabled, domain name will resolve to an IPv6 address.
     */
    readonly isIpv6: boolean;
    /**
     * If isRunNow is enabled, then the monitor will run immediately.
     */
    readonly isRunNow: boolean;
    /**
     * If runOnce is enabled, then the monitor will run once.
     */
    readonly isRunOnce: boolean;
    /**
     * Name of the user that recently updated the monitor.
     */
    readonly lastUpdatedBy: string;
    /**
     * Details required to schedule maintenance window.
     */
    readonly maintenanceWindowSchedules: outputs.ApmSynthetics.GetMonitorMaintenanceWindowSchedule[];
    readonly monitorId: string;
    /**
     * Type of monitor.
     */
    readonly monitorType: string;
    /**
     * Interval in seconds after the start time when the job should be repeated. Minimum repeatIntervalInSeconds should be 300 seconds for Scripted REST, Scripted Browser and Browser monitors, and 60 seconds for REST monitor.
     */
    readonly repeatIntervalInSeconds: number;
    /**
     * Scheduling policy to decide the distribution of monitor executions on vantage points.
     */
    readonly schedulingPolicy: string;
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the script. scriptId is mandatory for creation of SCRIPTED_BROWSER and SCRIPTED_REST monitor types. For other monitor types, it should be set to null.
     */
    readonly scriptId: string;
    /**
     * Name of the script.
     */
    readonly scriptName: string;
    /**
     * List of script parameters. Example: `[{"monitorScriptParameter": {"paramName": "userid", "paramValue":"testuser"}, "isSecret": false, "isOverwritten": false}]`
     */
    readonly scriptParameters: outputs.ApmSynthetics.GetMonitorScriptParameter[];
    /**
     * Enables or disables the monitor.
     */
    readonly status: string;
    /**
     * Specify the endpoint on which to run the monitor. For BROWSER, REST, NETWORK, DNS and FTP monitor types, target is mandatory. If target is specified in the SCRIPTED_BROWSER monitor type, then the monitor will run the selected script (specified by scriptId in monitor) against the specified target endpoint. If target is not specified in the SCRIPTED_BROWSER monitor type, then the monitor will run the selected script as it is. For NETWORK monitor with TCP protocol, a port needs to be provided along with target. Example: 192.168.0.1:80.
     */
    readonly target: string;
    /**
     * The time the resource was created, expressed in [RFC 3339](https://tools.ietf.org/html/rfc3339) timestamp format. Example: `2020-02-12T22:47:12.613Z`
     */
    readonly timeCreated: string;
    /**
     * The time the resource was updated, expressed in [RFC 3339](https://tools.ietf.org/html/rfc3339) timestamp format. Example: `2020-02-13T22:47:12.613Z`
     */
    readonly timeUpdated: string;
    /**
     * Timeout in seconds. If isFailureRetried is true, then timeout cannot be more than 30% of repeatIntervalInSeconds time for monitors. If isFailureRetried is false, then timeout cannot be more than 50% of repeatIntervalInSeconds time for monitors. Also, timeoutInSeconds should be a multiple of 60 for Scripted REST, Scripted Browser and Browser monitors. Monitor will be allowed to run only for timeoutInSeconds time. It would be terminated after that.
     */
    readonly timeoutInSeconds: number;
    /**
     * Number of vantage points where monitor is running.
     */
    readonly vantagePointCount: number;
    /**
     * List of public, dedicated and onPremise vantage points where the monitor is running.
     */
    readonly vantagePoints: outputs.ApmSynthetics.GetMonitorVantagePoint[];
}
/**
 * This data source provides details about a specific Monitor resource in Oracle Cloud Infrastructure APM Availability Monitoring service (aka APM Synthetics Service).
 *
 * Gets the configuration of the monitor identified by the OCID.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testMonitor = oci.ApmSynthetics.getMonitor({
 *     apmDomainId: testApmDomain.id,
 *     monitorId: testMonitorOciApmSyntheticsMonitor.id,
 * });
 * ```
 */
export function getMonitorOutput(args: GetMonitorOutputArgs, opts?: pulumi.InvokeOutputOptions): pulumi.Output<GetMonitorResult> {
    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts || {});
    return pulumi.runtime.invokeOutput("oci:ApmSynthetics/getMonitor:getMonitor", {
        "apmDomainId": args.apmDomainId,
        "monitorId": args.monitorId,
    }, opts);
}

/**
 * A collection of arguments for invoking getMonitor.
 */
export interface GetMonitorOutputArgs {
    /**
     * The APM domain ID the request is intended for.
     */
    apmDomainId: pulumi.Input<string>;
    /**
     * The OCID of the monitor.
     */
    monitorId: pulumi.Input<string>;
}
