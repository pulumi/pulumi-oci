// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import * as inputs from "../types/input";
import * as outputs from "../types/output";
import * as utilities from "../utilities";

/**
 * This data source provides the list of Stream Cdn Configs in Oracle Cloud Infrastructure Media Services service.
 *
 * Lists the StreamCdnConfig.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testStreamCdnConfigs = oci.MediaServices.getStreamCdnConfigs({
 *     distributionChannelId: oci_mysql_channel.test_channel.id,
 *     displayName: _var.stream_cdn_config_display_name,
 *     id: _var.stream_cdn_config_id,
 *     state: _var.stream_cdn_config_state,
 * });
 * ```
 */
export function getStreamCdnConfigs(args: GetStreamCdnConfigsArgs, opts?: pulumi.InvokeOptions): Promise<GetStreamCdnConfigsResult> {

    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts || {});
    return pulumi.runtime.invoke("oci:MediaServices/getStreamCdnConfigs:getStreamCdnConfigs", {
        "displayName": args.displayName,
        "distributionChannelId": args.distributionChannelId,
        "filters": args.filters,
        "id": args.id,
        "state": args.state,
    }, opts);
}

/**
 * A collection of arguments for invoking getStreamCdnConfigs.
 */
export interface GetStreamCdnConfigsArgs {
    /**
     * A filter to return only the resources that match the entire display name given.
     */
    displayName?: string;
    /**
     * The Stream Distribution Channel identifier this CdnConfig belongs to.
     */
    distributionChannelId: string;
    filters?: inputs.MediaServices.GetStreamCdnConfigsFilter[];
    /**
     * Unique StreamCdnConfig identifier.
     */
    id?: string;
    /**
     * A filter to return only the resources with lifecycleState matching the given lifecycleState.
     */
    state?: string;
}

/**
 * A collection of values returned by getStreamCdnConfigs.
 */
export interface GetStreamCdnConfigsResult {
    /**
     * The CDN Configuration identifier or display name, which can be renamed and is not necessarily unique. Avoid entering confidential information.
     */
    readonly displayName?: string;
    /**
     * Distribution Channel Identifier.
     */
    readonly distributionChannelId: string;
    readonly filters?: outputs.MediaServices.GetStreamCdnConfigsFilter[];
    /**
     * Unique identifier that is immutable on creation.
     */
    readonly id?: string;
    /**
     * The current state of the CDN Configuration.
     */
    readonly state?: string;
    /**
     * The list of stream_cdn_config_collection.
     */
    readonly streamCdnConfigCollections: outputs.MediaServices.GetStreamCdnConfigsStreamCdnConfigCollection[];
}
/**
 * This data source provides the list of Stream Cdn Configs in Oracle Cloud Infrastructure Media Services service.
 *
 * Lists the StreamCdnConfig.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testStreamCdnConfigs = oci.MediaServices.getStreamCdnConfigs({
 *     distributionChannelId: oci_mysql_channel.test_channel.id,
 *     displayName: _var.stream_cdn_config_display_name,
 *     id: _var.stream_cdn_config_id,
 *     state: _var.stream_cdn_config_state,
 * });
 * ```
 */
export function getStreamCdnConfigsOutput(args: GetStreamCdnConfigsOutputArgs, opts?: pulumi.InvokeOptions): pulumi.Output<GetStreamCdnConfigsResult> {
    return pulumi.output(args).apply((a: any) => getStreamCdnConfigs(a, opts))
}

/**
 * A collection of arguments for invoking getStreamCdnConfigs.
 */
export interface GetStreamCdnConfigsOutputArgs {
    /**
     * A filter to return only the resources that match the entire display name given.
     */
    displayName?: pulumi.Input<string>;
    /**
     * The Stream Distribution Channel identifier this CdnConfig belongs to.
     */
    distributionChannelId: pulumi.Input<string>;
    filters?: pulumi.Input<pulumi.Input<inputs.MediaServices.GetStreamCdnConfigsFilterArgs>[]>;
    /**
     * Unique StreamCdnConfig identifier.
     */
    id?: pulumi.Input<string>;
    /**
     * A filter to return only the resources with lifecycleState matching the given lifecycleState.
     */
    state?: pulumi.Input<string>;
}