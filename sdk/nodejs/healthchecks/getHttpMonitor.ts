// *** WARNING: this file was generated by pulumi-language-nodejs. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import * as utilities from "../utilities";

/**
 * This data source provides details about a specific Http Monitor resource in Oracle Cloud Infrastructure Health Checks service.
 *
 * Gets the configuration for the specified monitor.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testHttpMonitor = oci.HealthChecks.getHttpMonitor({
 *     monitorId: testMonitor.id,
 * });
 * ```
 */
export function getHttpMonitor(args: GetHttpMonitorArgs, opts?: pulumi.InvokeOptions): Promise<GetHttpMonitorResult> {
    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts || {});
    return pulumi.runtime.invoke("oci:HealthChecks/getHttpMonitor:getHttpMonitor", {
        "monitorId": args.monitorId,
    }, opts);
}

/**
 * A collection of arguments for invoking getHttpMonitor.
 */
export interface GetHttpMonitorArgs {
    /**
     * The OCID of a monitor.
     */
    monitorId: string;
}

/**
 * A collection of values returned by getHttpMonitor.
 */
export interface GetHttpMonitorResult {
    /**
     * The OCID of the compartment.
     */
    readonly compartmentId: string;
    /**
     * Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Operations.CostCenter": "42"}`
     */
    readonly definedTags: {[key: string]: string};
    /**
     * A user-friendly and mutable name suitable for display in a user interface.
     */
    readonly displayName: string;
    /**
     * Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace.  For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Department": "Finance"}`
     */
    readonly freeformTags: {[key: string]: string};
    /**
     * A dictionary of HTTP request headers.
     */
    readonly headers: {[key: string]: string};
    /**
     * The region where updates must be made and where results must be fetched from.
     */
    readonly homeRegion: string;
    /**
     * The OCID of the resource.
     */
    readonly id: string;
    /**
     * The monitor interval in seconds. Valid values: 10, 30, and 60.
     */
    readonly intervalInSeconds: number;
    /**
     * Enables or disables the monitor. Set to 'true' to launch monitoring.
     */
    readonly isEnabled: boolean;
    /**
     * The supported HTTP methods available for probes.
     */
    readonly method: string;
    readonly monitorId: string;
    /**
     * The optional URL path to probe, including query parameters.
     */
    readonly path: string;
    /**
     * The port on which to probe endpoints. If unspecified, probes will use the default port of their protocol.
     */
    readonly port: number;
    /**
     * The supported protocols available for HTTP probes.
     */
    readonly protocol: string;
    /**
     * A URL for fetching the probe results.
     */
    readonly resultsUrl: string;
    /**
     * A list of targets (hostnames or IP addresses) of the probe.
     */
    readonly targets: string[];
    /**
     * The RFC 3339-formatted creation date and time of the probe.
     */
    readonly timeCreated: string;
    /**
     * The probe timeout in seconds. Valid values: 10, 20, 30, and 60. The probe timeout must be less than or equal to `intervalInSeconds` for monitors.
     */
    readonly timeoutInSeconds: number;
    /**
     * A list of names of vantage points from which to execute the probe.
     */
    readonly vantagePointNames: string[];
}
/**
 * This data source provides details about a specific Http Monitor resource in Oracle Cloud Infrastructure Health Checks service.
 *
 * Gets the configuration for the specified monitor.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testHttpMonitor = oci.HealthChecks.getHttpMonitor({
 *     monitorId: testMonitor.id,
 * });
 * ```
 */
export function getHttpMonitorOutput(args: GetHttpMonitorOutputArgs, opts?: pulumi.InvokeOutputOptions): pulumi.Output<GetHttpMonitorResult> {
    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts || {});
    return pulumi.runtime.invokeOutput("oci:HealthChecks/getHttpMonitor:getHttpMonitor", {
        "monitorId": args.monitorId,
    }, opts);
}

/**
 * A collection of arguments for invoking getHttpMonitor.
 */
export interface GetHttpMonitorOutputArgs {
    /**
     * The OCID of a monitor.
     */
    monitorId: pulumi.Input<string>;
}
