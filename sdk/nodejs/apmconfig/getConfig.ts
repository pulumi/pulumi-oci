// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import { input as inputs, output as outputs } from "../types";
import * as utilities from "../utilities";

/**
 * This data source provides details about a specific Config resource in Oracle Cloud Infrastructure Apm Config service.
 *
 * Gets the configuration item identified by the OCID.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testConfig = oci.ApmConfig.getConfig({
 *     apmDomainId: oci_apm_apm_domain.test_apm_domain.id,
 *     configId: oci_apm_config_config.test_config.id,
 * });
 * ```
 */
export function getConfig(args: GetConfigArgs, opts?: pulumi.InvokeOptions): Promise<GetConfigResult> {
    if (!opts) {
        opts = {}
    }

    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts);
    return pulumi.runtime.invoke("oci:ApmConfig/getConfig:getConfig", {
        "apmDomainId": args.apmDomainId,
        "configId": args.configId,
    }, opts);
}

/**
 * A collection of arguments for invoking getConfig.
 */
export interface GetConfigArgs {
    /**
     * The APM Domain ID the request is intended for.
     */
    apmDomainId: string;
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the configuration item.
     */
    configId: string;
}

/**
 * A collection of values returned by getConfig.
 */
export interface GetConfigResult {
    readonly apmDomainId: string;
    readonly configId: string;
    /**
     * The type of configuration item.
     */
    readonly configType: string;
    /**
     * Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
     */
    readonly definedTags: {[key: string]: any};
    /**
     * A description of the metric.
     */
    readonly description: string;
    /**
     * A list of dimensions for the metric. This variable should not be used.
     */
    readonly dimensions: outputs.ApmConfig.GetConfigDimension[];
    /**
     * The name by which a configuration entity is displayed to the end user.
     */
    readonly displayName: string;
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of a Span Filter. The filterId is mandatory for the creation of MetricGroups. A filterId is generated when a Span Filter is created.
     */
    readonly filterId: string;
    /**
     * The string that defines the Span Filter expression.
     */
    readonly filterText: string;
    /**
     * Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
     */
    readonly freeformTags: {[key: string]: any};
    /**
     * A string that specifies the group that an OPTIONS item belongs to.
     */
    readonly group: string;
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the configuration item. An OCID is generated when the item is created.
     */
    readonly id: string;
    /**
     * The list of metrics in this group.
     */
    readonly metrics: outputs.ApmConfig.GetConfigMetric[];
    /**
     * The namespace to which the metrics are published. It must be one of several predefined namespaces.
     */
    readonly namespace: string;
    readonly opcDryRun: string;
    /**
     * The options are stored here as JSON.
     */
    readonly options: string;
    readonly rules: outputs.ApmConfig.GetConfigRule[];
    /**
     * The time the resource was created, expressed in [RFC 3339](https://tools.ietf.org/html/rfc3339) timestamp format. Example: `2020-02-12T22:47:12.613Z`
     */
    readonly timeCreated: string;
    /**
     * The time the resource was updated, expressed in [RFC 3339](https://tools.ietf.org/html/rfc3339) timestamp format. Example: `2020-02-13T22:47:12.613Z`
     */
    readonly timeUpdated: string;
}

export function getConfigOutput(args: GetConfigOutputArgs, opts?: pulumi.InvokeOptions): pulumi.Output<GetConfigResult> {
    return pulumi.output(args).apply(a => getConfig(a, opts))
}

/**
 * A collection of arguments for invoking getConfig.
 */
export interface GetConfigOutputArgs {
    /**
     * The APM Domain ID the request is intended for.
     */
    apmDomainId: pulumi.Input<string>;
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the configuration item.
     */
    configId: pulumi.Input<string>;
}