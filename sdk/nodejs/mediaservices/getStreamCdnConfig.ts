// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import * as inputs from "../types/input";
import * as outputs from "../types/output";
import * as utilities from "../utilities";

/**
 * This data source provides details about a specific Stream Cdn Config resource in Oracle Cloud Infrastructure Media Services service.
 *
 * Gets a StreamCdnConfig by identifier.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testStreamCdnConfig = oci.MediaServices.getStreamCdnConfig({
 *     streamCdnConfigId: oci_media_services_stream_cdn_config.test_stream_cdn_config.id,
 * });
 * ```
 */
export function getStreamCdnConfig(args: GetStreamCdnConfigArgs, opts?: pulumi.InvokeOptions): Promise<GetStreamCdnConfigResult> {

    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts || {});
    return pulumi.runtime.invoke("oci:MediaServices/getStreamCdnConfig:getStreamCdnConfig", {
        "streamCdnConfigId": args.streamCdnConfigId,
    }, opts);
}

/**
 * A collection of arguments for invoking getStreamCdnConfig.
 */
export interface GetStreamCdnConfigArgs {
    /**
     * Unique StreamCdnConfig identifier.
     */
    streamCdnConfigId: string;
}

/**
 * A collection of values returned by getStreamCdnConfig.
 */
export interface GetStreamCdnConfigResult {
    /**
     * Compartment Identifier.
     */
    readonly compartmentId: string;
    /**
     * Base fields of the StreamCdnConfig configuration object.
     */
    readonly configs: outputs.MediaServices.GetStreamCdnConfigConfig[];
    /**
     * Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
     */
    readonly definedTags: {[key: string]: any};
    /**
     * The CDN Configuration identifier or display name, which can be renamed and is not necessarily unique. Avoid entering confidential information.
     */
    readonly displayName: string;
    /**
     * Distribution Channel Identifier.
     */
    readonly distributionChannelId: string;
    /**
     * Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
     */
    readonly freeformTags: {[key: string]: any};
    /**
     * Unique identifier that is immutable on creation.
     */
    readonly id: string;
    /**
     * Whether publishing to CDN is enabled.
     */
    readonly isEnabled: boolean;
    /**
     * A message describing the current state in more detail. For example, can be used to provide actionable information for a resource in Failed state.
     */
    readonly lifecyleDetails: string;
    /**
     * The current state of the CDN Configuration.
     */
    readonly state: string;
    readonly streamCdnConfigId: string;
    /**
     * Usage of system tag keys. These predefined keys are scoped to namespaces. Example: `{"orcl-cloud.free-tier-retained": "true"}`
     */
    readonly systemTags: {[key: string]: any};
    /**
     * The time when the CDN Config was created. An RFC3339 formatted datetime string.
     */
    readonly timeCreated: string;
    /**
     * The time when the CDN Config was updated. An RFC3339 formatted datetime string.
     */
    readonly timeUpdated: string;
}
/**
 * This data source provides details about a specific Stream Cdn Config resource in Oracle Cloud Infrastructure Media Services service.
 *
 * Gets a StreamCdnConfig by identifier.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testStreamCdnConfig = oci.MediaServices.getStreamCdnConfig({
 *     streamCdnConfigId: oci_media_services_stream_cdn_config.test_stream_cdn_config.id,
 * });
 * ```
 */
export function getStreamCdnConfigOutput(args: GetStreamCdnConfigOutputArgs, opts?: pulumi.InvokeOptions): pulumi.Output<GetStreamCdnConfigResult> {
    return pulumi.output(args).apply((a: any) => getStreamCdnConfig(a, opts))
}

/**
 * A collection of arguments for invoking getStreamCdnConfig.
 */
export interface GetStreamCdnConfigOutputArgs {
    /**
     * Unique StreamCdnConfig identifier.
     */
    streamCdnConfigId: pulumi.Input<string>;
}