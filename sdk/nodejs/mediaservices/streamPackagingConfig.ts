// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import * as inputs from "../types/input";
import * as outputs from "../types/output";
import * as utilities from "../utilities";

/**
 * This resource provides the Stream Packaging Config resource in Oracle Cloud Infrastructure Media Services service.
 *
 * Creates a new Packaging Configuration.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testStreamPackagingConfig = new oci.mediaservices.StreamPackagingConfig("testStreamPackagingConfig", {
 *     displayName: _var.stream_packaging_config_display_name,
 *     distributionChannelId: oci_mysql_channel.test_channel.id,
 *     segmentTimeInSeconds: _var.stream_packaging_config_segment_time_in_seconds,
 *     streamPackagingFormat: _var.stream_packaging_config_stream_packaging_format,
 *     definedTags: {
 *         "foo-namespace.bar-key": "value",
 *     },
 *     encryption: {
 *         algorithm: _var.stream_packaging_config_encryption_algorithm,
 *         kmsKeyId: oci_kms_key.test_key.id,
 *     },
 *     freeformTags: {
 *         "bar-key": "value",
 *     },
 * });
 * ```
 *
 * ## Import
 *
 * StreamPackagingConfigs can be imported using the `id`, e.g.
 *
 * ```sh
 *  $ pulumi import oci:MediaServices/streamPackagingConfig:StreamPackagingConfig test_stream_packaging_config "id"
 * ```
 */
export class StreamPackagingConfig extends pulumi.CustomResource {
    /**
     * Get an existing StreamPackagingConfig resource's state with the given name, ID, and optional extra
     * properties used to qualify the lookup.
     *
     * @param name The _unique_ name of the resulting resource.
     * @param id The _unique_ provider ID of the resource to lookup.
     * @param state Any extra arguments used during the lookup.
     * @param opts Optional settings to control the behavior of the CustomResource.
     */
    public static get(name: string, id: pulumi.Input<pulumi.ID>, state?: StreamPackagingConfigState, opts?: pulumi.CustomResourceOptions): StreamPackagingConfig {
        return new StreamPackagingConfig(name, <any>state, { ...opts, id: id });
    }

    /** @internal */
    public static readonly __pulumiType = 'oci:MediaServices/streamPackagingConfig:StreamPackagingConfig';

    /**
     * Returns true if the given object is an instance of StreamPackagingConfig.  This is designed to work even
     * when multiple copies of the Pulumi SDK have been loaded into the same process.
     */
    public static isInstance(obj: any): obj is StreamPackagingConfig {
        if (obj === undefined || obj === null) {
            return false;
        }
        return obj['__pulumiType'] === StreamPackagingConfig.__pulumiType;
    }

    /**
     * Compartment Identifier
     */
    public /*out*/ readonly compartmentId!: pulumi.Output<string>;
    /**
     * (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
     */
    public readonly definedTags!: pulumi.Output<{[key: string]: any}>;
    /**
     * (Updatable) The name of the stream Packaging Configuration. Avoid entering confidential information.
     */
    public readonly displayName!: pulumi.Output<string>;
    /**
     * Unique identifier of the Distribution Channel that this stream packaging configuration belongs to.
     */
    public readonly distributionChannelId!: pulumi.Output<string>;
    /**
     * The encryption used by the stream packaging configuration.
     */
    public readonly encryption!: pulumi.Output<outputs.MediaServices.StreamPackagingConfigEncryption>;
    /**
     * (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
     */
    public readonly freeformTags!: pulumi.Output<{[key: string]: any}>;
    /**
     * The duration in seconds for each fragment.
     */
    public readonly segmentTimeInSeconds!: pulumi.Output<number>;
    /**
     * The current state of the Packaging Configuration.
     */
    public /*out*/ readonly state!: pulumi.Output<string>;
    /**
     * The output format for the package.
     */
    public readonly streamPackagingFormat!: pulumi.Output<string>;
    /**
     * Usage of system tag keys. These predefined keys are scoped to namespaces. Example: `{"orcl-cloud.free-tier-retained": "true"}`
     */
    public /*out*/ readonly systemTags!: pulumi.Output<{[key: string]: any}>;
    /**
     * The time when the Packaging Configuration was created. An RFC3339 formatted datetime string.
     */
    public /*out*/ readonly timeCreated!: pulumi.Output<string>;
    /**
     * The time when the Packaging Configuration was updated. An RFC3339 formatted datetime string.
     */
    public /*out*/ readonly timeUpdated!: pulumi.Output<string>;

    /**
     * Create a StreamPackagingConfig resource with the given unique name, arguments, and options.
     *
     * @param name The _unique_ name of the resource.
     * @param args The arguments to use to populate this resource's properties.
     * @param opts A bag of options that control this resource's behavior.
     */
    constructor(name: string, args: StreamPackagingConfigArgs, opts?: pulumi.CustomResourceOptions)
    constructor(name: string, argsOrState?: StreamPackagingConfigArgs | StreamPackagingConfigState, opts?: pulumi.CustomResourceOptions) {
        let resourceInputs: pulumi.Inputs = {};
        opts = opts || {};
        if (opts.id) {
            const state = argsOrState as StreamPackagingConfigState | undefined;
            resourceInputs["compartmentId"] = state ? state.compartmentId : undefined;
            resourceInputs["definedTags"] = state ? state.definedTags : undefined;
            resourceInputs["displayName"] = state ? state.displayName : undefined;
            resourceInputs["distributionChannelId"] = state ? state.distributionChannelId : undefined;
            resourceInputs["encryption"] = state ? state.encryption : undefined;
            resourceInputs["freeformTags"] = state ? state.freeformTags : undefined;
            resourceInputs["segmentTimeInSeconds"] = state ? state.segmentTimeInSeconds : undefined;
            resourceInputs["state"] = state ? state.state : undefined;
            resourceInputs["streamPackagingFormat"] = state ? state.streamPackagingFormat : undefined;
            resourceInputs["systemTags"] = state ? state.systemTags : undefined;
            resourceInputs["timeCreated"] = state ? state.timeCreated : undefined;
            resourceInputs["timeUpdated"] = state ? state.timeUpdated : undefined;
        } else {
            const args = argsOrState as StreamPackagingConfigArgs | undefined;
            if ((!args || args.displayName === undefined) && !opts.urn) {
                throw new Error("Missing required property 'displayName'");
            }
            if ((!args || args.distributionChannelId === undefined) && !opts.urn) {
                throw new Error("Missing required property 'distributionChannelId'");
            }
            if ((!args || args.segmentTimeInSeconds === undefined) && !opts.urn) {
                throw new Error("Missing required property 'segmentTimeInSeconds'");
            }
            if ((!args || args.streamPackagingFormat === undefined) && !opts.urn) {
                throw new Error("Missing required property 'streamPackagingFormat'");
            }
            resourceInputs["definedTags"] = args ? args.definedTags : undefined;
            resourceInputs["displayName"] = args ? args.displayName : undefined;
            resourceInputs["distributionChannelId"] = args ? args.distributionChannelId : undefined;
            resourceInputs["encryption"] = args ? args.encryption : undefined;
            resourceInputs["freeformTags"] = args ? args.freeformTags : undefined;
            resourceInputs["segmentTimeInSeconds"] = args ? args.segmentTimeInSeconds : undefined;
            resourceInputs["streamPackagingFormat"] = args ? args.streamPackagingFormat : undefined;
            resourceInputs["compartmentId"] = undefined /*out*/;
            resourceInputs["state"] = undefined /*out*/;
            resourceInputs["systemTags"] = undefined /*out*/;
            resourceInputs["timeCreated"] = undefined /*out*/;
            resourceInputs["timeUpdated"] = undefined /*out*/;
        }
        opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts);
        super(StreamPackagingConfig.__pulumiType, name, resourceInputs, opts);
    }
}

/**
 * Input properties used for looking up and filtering StreamPackagingConfig resources.
 */
export interface StreamPackagingConfigState {
    /**
     * Compartment Identifier
     */
    compartmentId?: pulumi.Input<string>;
    /**
     * (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
     */
    definedTags?: pulumi.Input<{[key: string]: any}>;
    /**
     * (Updatable) The name of the stream Packaging Configuration. Avoid entering confidential information.
     */
    displayName?: pulumi.Input<string>;
    /**
     * Unique identifier of the Distribution Channel that this stream packaging configuration belongs to.
     */
    distributionChannelId?: pulumi.Input<string>;
    /**
     * The encryption used by the stream packaging configuration.
     */
    encryption?: pulumi.Input<inputs.MediaServices.StreamPackagingConfigEncryption>;
    /**
     * (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
     */
    freeformTags?: pulumi.Input<{[key: string]: any}>;
    /**
     * The duration in seconds for each fragment.
     */
    segmentTimeInSeconds?: pulumi.Input<number>;
    /**
     * The current state of the Packaging Configuration.
     */
    state?: pulumi.Input<string>;
    /**
     * The output format for the package.
     */
    streamPackagingFormat?: pulumi.Input<string>;
    /**
     * Usage of system tag keys. These predefined keys are scoped to namespaces. Example: `{"orcl-cloud.free-tier-retained": "true"}`
     */
    systemTags?: pulumi.Input<{[key: string]: any}>;
    /**
     * The time when the Packaging Configuration was created. An RFC3339 formatted datetime string.
     */
    timeCreated?: pulumi.Input<string>;
    /**
     * The time when the Packaging Configuration was updated. An RFC3339 formatted datetime string.
     */
    timeUpdated?: pulumi.Input<string>;
}

/**
 * The set of arguments for constructing a StreamPackagingConfig resource.
 */
export interface StreamPackagingConfigArgs {
    /**
     * (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
     */
    definedTags?: pulumi.Input<{[key: string]: any}>;
    /**
     * (Updatable) The name of the stream Packaging Configuration. Avoid entering confidential information.
     */
    displayName: pulumi.Input<string>;
    /**
     * Unique identifier of the Distribution Channel that this stream packaging configuration belongs to.
     */
    distributionChannelId: pulumi.Input<string>;
    /**
     * The encryption used by the stream packaging configuration.
     */
    encryption?: pulumi.Input<inputs.MediaServices.StreamPackagingConfigEncryption>;
    /**
     * (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
     */
    freeformTags?: pulumi.Input<{[key: string]: any}>;
    /**
     * The duration in seconds for each fragment.
     */
    segmentTimeInSeconds: pulumi.Input<number>;
    /**
     * The output format for the package.
     */
    streamPackagingFormat: pulumi.Input<string>;
}