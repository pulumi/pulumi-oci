// *** WARNING: this file was generated by pulumi-language-nodejs. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import * as inputs from "../types/input";
import * as outputs from "../types/output";
import * as utilities from "../utilities";

/**
 * This data source provides details about a specific Monitored Resource Type resource in Oracle Cloud Infrastructure Stack Monitoring service.
 *
 * Gets a monitored resource type by identifier [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testMonitoredResourceType = oci.StackMonitoring.getMonitoredResourceType({
 *     monitoredResourceTypeId: testMonitoredResourceTypeOciStackMonitoringMonitoredResourceType.id,
 * });
 * ```
 */
export function getMonitoredResourceType(args: GetMonitoredResourceTypeArgs, opts?: pulumi.InvokeOptions): Promise<GetMonitoredResourceTypeResult> {
    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts || {});
    return pulumi.runtime.invoke("oci:StackMonitoring/getMonitoredResourceType:getMonitoredResourceType", {
        "monitoredResourceTypeId": args.monitoredResourceTypeId,
    }, opts);
}

/**
 * A collection of arguments for invoking getMonitoredResourceType.
 */
export interface GetMonitoredResourceTypeArgs {
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of monitored resource type.
     */
    monitoredResourceTypeId: string;
}

/**
 * A collection of values returned by getMonitoredResourceType.
 */
export interface GetMonitoredResourceTypeResult {
    /**
     * Key/Value pair for additional namespaces used by stack monitoring services for SYSTEM (SMB) resource types.
     */
    readonly additionalNamespaceMap: {[key: string]: string};
    /**
     * Availability metrics details.
     */
    readonly availabilityMetricsConfigs: outputs.StackMonitoring.GetMonitoredResourceTypeAvailabilityMetricsConfig[];
    /**
     * Compartment Identifier [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
     */
    readonly compartmentId: string;
    /**
     * Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
     */
    readonly definedTags: {[key: string]: string};
    /**
     * A friendly description.
     */
    readonly description: string;
    /**
     * Monitored resource type display name.
     */
    readonly displayName: string;
    /**
     * Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
     */
    readonly freeformTags: {[key: string]: string};
    /**
     * Specific resource mapping configurations for Agent Extension Handlers.
     */
    readonly handlerConfigs: outputs.StackMonitoring.GetMonitoredResourceTypeHandlerConfig[];
    /**
     * Monitored resource type identifier [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
     */
    readonly id: string;
    /**
     * If boolean flag is true, then the resource type cannot be modified or deleted.
     */
    readonly isSystemDefined: boolean;
    /**
     * The metadata details for resource type.
     */
    readonly metadatas: outputs.StackMonitoring.GetMonitoredResourceTypeMetadata[];
    /**
     * Metric namespace for resource type.
     */
    readonly metricNamespace: string;
    readonly monitoredResourceTypeId: string;
    /**
     * A unique monitored resource type name. The name must be unique across tenancy.  Name can not be changed.
     */
    readonly name: string;
    /**
     * Resource Category to indicate the kind of resource type.
     */
    readonly resourceCategory: string;
    /**
     * Source type to indicate if the resource is stack monitoring discovered, Oracle Cloud Infrastructure native resource, etc.
     */
    readonly sourceType: string;
    /**
     * Lifecycle state of the monitored resource type.
     */
    readonly state: string;
    /**
     * Usage of system tag keys. These predefined keys are scoped to namespaces. Example: `{"orcl-cloud.free-tier-retained": "true"}`
     */
    readonly systemTags: {[key: string]: string};
    /**
     * Tenancy Identifier [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
     */
    readonly tenancyId: string;
    /**
     * The date and time when the monitored resource type was created, expressed in  [RFC 3339](https://tools.ietf.org/html/rfc3339) timestamp format.
     */
    readonly timeCreated: string;
    /**
     * The date and time when the monitored resource was updated, expressed in  [RFC 3339](https://tools.ietf.org/html/rfc3339) timestamp format.
     */
    readonly timeUpdated: string;
}
/**
 * This data source provides details about a specific Monitored Resource Type resource in Oracle Cloud Infrastructure Stack Monitoring service.
 *
 * Gets a monitored resource type by identifier [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testMonitoredResourceType = oci.StackMonitoring.getMonitoredResourceType({
 *     monitoredResourceTypeId: testMonitoredResourceTypeOciStackMonitoringMonitoredResourceType.id,
 * });
 * ```
 */
export function getMonitoredResourceTypeOutput(args: GetMonitoredResourceTypeOutputArgs, opts?: pulumi.InvokeOutputOptions): pulumi.Output<GetMonitoredResourceTypeResult> {
    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts || {});
    return pulumi.runtime.invokeOutput("oci:StackMonitoring/getMonitoredResourceType:getMonitoredResourceType", {
        "monitoredResourceTypeId": args.monitoredResourceTypeId,
    }, opts);
}

/**
 * A collection of arguments for invoking getMonitoredResourceType.
 */
export interface GetMonitoredResourceTypeOutputArgs {
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of monitored resource type.
     */
    monitoredResourceTypeId: pulumi.Input<string>;
}
