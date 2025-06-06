// *** WARNING: this file was generated by pulumi-language-nodejs. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import * as inputs from "../types/input";
import * as outputs from "../types/output";
import * as utilities from "../utilities";

/**
 * This data source provides the list of Monitoring Templates in Oracle Cloud Infrastructure Stack Monitoring service.
 *
 * Returns a list of Monitoring Templates.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testMonitoringTemplates = oci.StackMonitoring.getMonitoringTemplates({
 *     compartmentId: compartmentId,
 *     displayName: monitoringTemplateDisplayName,
 *     metricNames: testMetric.name,
 *     monitoringTemplateId: testMonitoringTemplate.id,
 *     namespaces: monitoringTemplateNamespace,
 *     resourceTypes: monitoringTemplateResourceTypes,
 *     state: monitoringTemplateState,
 *     status: monitoringTemplateStatus,
 * });
 * ```
 */
export function getMonitoringTemplates(args?: GetMonitoringTemplatesArgs, opts?: pulumi.InvokeOptions): Promise<GetMonitoringTemplatesResult> {
    args = args || {};
    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts || {});
    return pulumi.runtime.invoke("oci:StackMonitoring/getMonitoringTemplates:getMonitoringTemplates", {
        "compartmentId": args.compartmentId,
        "displayName": args.displayName,
        "filters": args.filters,
        "metricNames": args.metricNames,
        "monitoringTemplateId": args.monitoringTemplateId,
        "namespaces": args.namespaces,
        "resourceTypes": args.resourceTypes,
        "state": args.state,
        "status": args.status,
    }, opts);
}

/**
 * A collection of arguments for invoking getMonitoringTemplates.
 */
export interface GetMonitoringTemplatesArgs {
    /**
     * The ID of the compartment in which data is listed.
     */
    compartmentId?: string;
    /**
     * A filter to return monitoring template based on name.
     */
    displayName?: string;
    filters?: inputs.StackMonitoring.GetMonitoringTemplatesFilter[];
    /**
     * metricName filter.
     */
    metricNames?: string[];
    /**
     * A filter to return monitoring template based on input monitoringTemplateId
     */
    monitoringTemplateId?: string;
    /**
     * namespace filter.
     */
    namespaces?: string[];
    /**
     * Multiple resource types filter.
     */
    resourceTypes?: string[];
    /**
     * A filter to return monitoring template based on Lifecycle State
     */
    state?: string;
    /**
     * A filter to return monitoring template based on input status
     */
    status?: string;
}

/**
 * A collection of values returned by getMonitoringTemplates.
 */
export interface GetMonitoringTemplatesResult {
    /**
     * The OCID of the compartment containing the monitoringTemplate.
     */
    readonly compartmentId?: string;
    /**
     * A user-friendly name for the monitoring template. It should be unique, and it's mutable in nature. Avoid entering confidential information.
     */
    readonly displayName?: string;
    readonly filters?: outputs.StackMonitoring.GetMonitoringTemplatesFilter[];
    /**
     * The provider-assigned unique ID for this managed resource.
     */
    readonly id: string;
    readonly metricNames?: string[];
    /**
     * The list of monitoring_template_collection.
     */
    readonly monitoringTemplateCollections: outputs.StackMonitoring.GetMonitoringTemplatesMonitoringTemplateCollection[];
    readonly monitoringTemplateId?: string;
    readonly namespaces?: string[];
    readonly resourceTypes?: string[];
    /**
     * The current lifecycle state of the monitoring template.
     */
    readonly state?: string;
    /**
     * The current status of the monitoring template i.e. whether it is Applied or NotApplied.
     */
    readonly status?: string;
}
/**
 * This data source provides the list of Monitoring Templates in Oracle Cloud Infrastructure Stack Monitoring service.
 *
 * Returns a list of Monitoring Templates.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testMonitoringTemplates = oci.StackMonitoring.getMonitoringTemplates({
 *     compartmentId: compartmentId,
 *     displayName: monitoringTemplateDisplayName,
 *     metricNames: testMetric.name,
 *     monitoringTemplateId: testMonitoringTemplate.id,
 *     namespaces: monitoringTemplateNamespace,
 *     resourceTypes: monitoringTemplateResourceTypes,
 *     state: monitoringTemplateState,
 *     status: monitoringTemplateStatus,
 * });
 * ```
 */
export function getMonitoringTemplatesOutput(args?: GetMonitoringTemplatesOutputArgs, opts?: pulumi.InvokeOutputOptions): pulumi.Output<GetMonitoringTemplatesResult> {
    args = args || {};
    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts || {});
    return pulumi.runtime.invokeOutput("oci:StackMonitoring/getMonitoringTemplates:getMonitoringTemplates", {
        "compartmentId": args.compartmentId,
        "displayName": args.displayName,
        "filters": args.filters,
        "metricNames": args.metricNames,
        "monitoringTemplateId": args.monitoringTemplateId,
        "namespaces": args.namespaces,
        "resourceTypes": args.resourceTypes,
        "state": args.state,
        "status": args.status,
    }, opts);
}

/**
 * A collection of arguments for invoking getMonitoringTemplates.
 */
export interface GetMonitoringTemplatesOutputArgs {
    /**
     * The ID of the compartment in which data is listed.
     */
    compartmentId?: pulumi.Input<string>;
    /**
     * A filter to return monitoring template based on name.
     */
    displayName?: pulumi.Input<string>;
    filters?: pulumi.Input<pulumi.Input<inputs.StackMonitoring.GetMonitoringTemplatesFilterArgs>[]>;
    /**
     * metricName filter.
     */
    metricNames?: pulumi.Input<pulumi.Input<string>[]>;
    /**
     * A filter to return monitoring template based on input monitoringTemplateId
     */
    monitoringTemplateId?: pulumi.Input<string>;
    /**
     * namespace filter.
     */
    namespaces?: pulumi.Input<pulumi.Input<string>[]>;
    /**
     * Multiple resource types filter.
     */
    resourceTypes?: pulumi.Input<pulumi.Input<string>[]>;
    /**
     * A filter to return monitoring template based on Lifecycle State
     */
    state?: pulumi.Input<string>;
    /**
     * A filter to return monitoring template based on input status
     */
    status?: pulumi.Input<string>;
}
