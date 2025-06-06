// *** WARNING: this file was generated by pulumi-language-nodejs. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import * as inputs from "../types/input";
import * as outputs from "../types/output";
import * as utilities from "../utilities";

/**
 * This resource provides the Media Asset resource in Oracle Cloud Infrastructure Media Services service.
 *
 * Creates a new MediaAsset.
 *
 * ## Import
 *
 * MediaAssets can be imported using the `id`, e.g.
 *
 * ```sh
 * $ pulumi import oci:MediaServices/mediaAsset:MediaAsset test_media_asset "id"
 * ```
 */
export class MediaAsset extends pulumi.CustomResource {
    /**
     * Get an existing MediaAsset resource's state with the given name, ID, and optional extra
     * properties used to qualify the lookup.
     *
     * @param name The _unique_ name of the resulting resource.
     * @param id The _unique_ provider ID of the resource to lookup.
     * @param state Any extra arguments used during the lookup.
     * @param opts Optional settings to control the behavior of the CustomResource.
     */
    public static get(name: string, id: pulumi.Input<pulumi.ID>, state?: MediaAssetState, opts?: pulumi.CustomResourceOptions): MediaAsset {
        return new MediaAsset(name, <any>state, { ...opts, id: id });
    }

    /** @internal */
    public static readonly __pulumiType = 'oci:MediaServices/mediaAsset:MediaAsset';

    /**
     * Returns true if the given object is an instance of MediaAsset.  This is designed to work even
     * when multiple copies of the Pulumi SDK have been loaded into the same process.
     */
    public static isInstance(obj: any): obj is MediaAsset {
        if (obj === undefined || obj === null) {
            return false;
        }
        return obj['__pulumiType'] === MediaAsset.__pulumiType;
    }

    /**
     * The name of the object storage bucket where this asset is located.
     */
    public readonly bucket!: pulumi.Output<string>;
    /**
     * (Updatable) Compartment Identifier.
     */
    public readonly compartmentId!: pulumi.Output<string>;
    /**
     * (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
     */
    public readonly definedTags!: pulumi.Output<{[key: string]: string}>;
    /**
     * (Updatable) Display name for the Media Asset. Does not have to be unique. Avoid entering confidential information.
     */
    public readonly displayName!: pulumi.Output<string>;
    /**
     * (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
     */
    public readonly freeformTags!: pulumi.Output<{[key: string]: string}>;
    public readonly isLockOverride!: pulumi.Output<boolean>;
    /**
     * Locks associated with this resource.
     */
    public readonly locks!: pulumi.Output<outputs.MediaServices.MediaAssetLock[]>;
    /**
     * (Updatable) The ID of the senior most asset from which this asset is derived.
     */
    public readonly masterMediaAssetId!: pulumi.Output<string>;
    /**
     * (Updatable) list of tags for the MediaAsset.
     */
    public readonly mediaAssetTags!: pulumi.Output<outputs.MediaServices.MediaAssetMediaAssetTag[]>;
    /**
     * The ID of the MediaWorkflowJob used to produce this asset.
     */
    public readonly mediaWorkflowJobId!: pulumi.Output<string>;
    /**
     * (Updatable) List of Metadata.
     */
    public readonly metadatas!: pulumi.Output<outputs.MediaServices.MediaAssetMetadata[]>;
    /**
     * The object storage namespace where this asset is located.
     */
    public readonly namespace!: pulumi.Output<string>;
    /**
     * The object storage object name that identifies this asset.
     */
    public readonly object!: pulumi.Output<string>;
    /**
     * eTag of the underlying object storage object.
     */
    public readonly objectEtag!: pulumi.Output<string>;
    /**
     * (Updatable) The ID of the parent asset from which this asset is derived.
     */
    public readonly parentMediaAssetId!: pulumi.Output<string>;
    /**
     * The end index for video segment files.
     */
    public readonly segmentRangeEndIndex!: pulumi.Output<string>;
    /**
     * The start index for video segment files.
     */
    public readonly segmentRangeStartIndex!: pulumi.Output<string>;
    /**
     * The ID of the MediaWorkflow used to produce this asset.
     */
    public readonly sourceMediaWorkflowId!: pulumi.Output<string>;
    /**
     * The version of the MediaWorkflow used to produce this asset.
     */
    public readonly sourceMediaWorkflowVersion!: pulumi.Output<string>;
    /**
     * The current state of the MediaAsset.
     */
    public /*out*/ readonly state!: pulumi.Output<string>;
    /**
     * Usage of system tag keys. These predefined keys are scoped to namespaces. Example: `{"orcl-cloud.free-tier-retained": "true"}`
     */
    public /*out*/ readonly systemTags!: pulumi.Output<{[key: string]: string}>;
    /**
     * The time when the MediaAsset was created. An RFC3339 formatted datetime string.
     */
    public /*out*/ readonly timeCreated!: pulumi.Output<string>;
    /**
     * The time when the MediaAsset was updated. An RFC3339 formatted datetime string.
     */
    public /*out*/ readonly timeUpdated!: pulumi.Output<string>;
    /**
     * (Updatable) The type of the media asset.
     *
     *
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     */
    public readonly type!: pulumi.Output<string>;

    /**
     * Create a MediaAsset resource with the given unique name, arguments, and options.
     *
     * @param name The _unique_ name of the resource.
     * @param args The arguments to use to populate this resource's properties.
     * @param opts A bag of options that control this resource's behavior.
     */
    constructor(name: string, args: MediaAssetArgs, opts?: pulumi.CustomResourceOptions)
    constructor(name: string, argsOrState?: MediaAssetArgs | MediaAssetState, opts?: pulumi.CustomResourceOptions) {
        let resourceInputs: pulumi.Inputs = {};
        opts = opts || {};
        if (opts.id) {
            const state = argsOrState as MediaAssetState | undefined;
            resourceInputs["bucket"] = state ? state.bucket : undefined;
            resourceInputs["compartmentId"] = state ? state.compartmentId : undefined;
            resourceInputs["definedTags"] = state ? state.definedTags : undefined;
            resourceInputs["displayName"] = state ? state.displayName : undefined;
            resourceInputs["freeformTags"] = state ? state.freeformTags : undefined;
            resourceInputs["isLockOverride"] = state ? state.isLockOverride : undefined;
            resourceInputs["locks"] = state ? state.locks : undefined;
            resourceInputs["masterMediaAssetId"] = state ? state.masterMediaAssetId : undefined;
            resourceInputs["mediaAssetTags"] = state ? state.mediaAssetTags : undefined;
            resourceInputs["mediaWorkflowJobId"] = state ? state.mediaWorkflowJobId : undefined;
            resourceInputs["metadatas"] = state ? state.metadatas : undefined;
            resourceInputs["namespace"] = state ? state.namespace : undefined;
            resourceInputs["object"] = state ? state.object : undefined;
            resourceInputs["objectEtag"] = state ? state.objectEtag : undefined;
            resourceInputs["parentMediaAssetId"] = state ? state.parentMediaAssetId : undefined;
            resourceInputs["segmentRangeEndIndex"] = state ? state.segmentRangeEndIndex : undefined;
            resourceInputs["segmentRangeStartIndex"] = state ? state.segmentRangeStartIndex : undefined;
            resourceInputs["sourceMediaWorkflowId"] = state ? state.sourceMediaWorkflowId : undefined;
            resourceInputs["sourceMediaWorkflowVersion"] = state ? state.sourceMediaWorkflowVersion : undefined;
            resourceInputs["state"] = state ? state.state : undefined;
            resourceInputs["systemTags"] = state ? state.systemTags : undefined;
            resourceInputs["timeCreated"] = state ? state.timeCreated : undefined;
            resourceInputs["timeUpdated"] = state ? state.timeUpdated : undefined;
            resourceInputs["type"] = state ? state.type : undefined;
        } else {
            const args = argsOrState as MediaAssetArgs | undefined;
            if ((!args || args.compartmentId === undefined) && !opts.urn) {
                throw new Error("Missing required property 'compartmentId'");
            }
            if ((!args || args.type === undefined) && !opts.urn) {
                throw new Error("Missing required property 'type'");
            }
            resourceInputs["bucket"] = args ? args.bucket : undefined;
            resourceInputs["compartmentId"] = args ? args.compartmentId : undefined;
            resourceInputs["definedTags"] = args ? args.definedTags : undefined;
            resourceInputs["displayName"] = args ? args.displayName : undefined;
            resourceInputs["freeformTags"] = args ? args.freeformTags : undefined;
            resourceInputs["isLockOverride"] = args ? args.isLockOverride : undefined;
            resourceInputs["locks"] = args ? args.locks : undefined;
            resourceInputs["masterMediaAssetId"] = args ? args.masterMediaAssetId : undefined;
            resourceInputs["mediaAssetTags"] = args ? args.mediaAssetTags : undefined;
            resourceInputs["mediaWorkflowJobId"] = args ? args.mediaWorkflowJobId : undefined;
            resourceInputs["metadatas"] = args ? args.metadatas : undefined;
            resourceInputs["namespace"] = args ? args.namespace : undefined;
            resourceInputs["object"] = args ? args.object : undefined;
            resourceInputs["objectEtag"] = args ? args.objectEtag : undefined;
            resourceInputs["parentMediaAssetId"] = args ? args.parentMediaAssetId : undefined;
            resourceInputs["segmentRangeEndIndex"] = args ? args.segmentRangeEndIndex : undefined;
            resourceInputs["segmentRangeStartIndex"] = args ? args.segmentRangeStartIndex : undefined;
            resourceInputs["sourceMediaWorkflowId"] = args ? args.sourceMediaWorkflowId : undefined;
            resourceInputs["sourceMediaWorkflowVersion"] = args ? args.sourceMediaWorkflowVersion : undefined;
            resourceInputs["type"] = args ? args.type : undefined;
            resourceInputs["state"] = undefined /*out*/;
            resourceInputs["systemTags"] = undefined /*out*/;
            resourceInputs["timeCreated"] = undefined /*out*/;
            resourceInputs["timeUpdated"] = undefined /*out*/;
        }
        opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts);
        super(MediaAsset.__pulumiType, name, resourceInputs, opts);
    }
}

/**
 * Input properties used for looking up and filtering MediaAsset resources.
 */
export interface MediaAssetState {
    /**
     * The name of the object storage bucket where this asset is located.
     */
    bucket?: pulumi.Input<string>;
    /**
     * (Updatable) Compartment Identifier.
     */
    compartmentId?: pulumi.Input<string>;
    /**
     * (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
     */
    definedTags?: pulumi.Input<{[key: string]: pulumi.Input<string>}>;
    /**
     * (Updatable) Display name for the Media Asset. Does not have to be unique. Avoid entering confidential information.
     */
    displayName?: pulumi.Input<string>;
    /**
     * (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
     */
    freeformTags?: pulumi.Input<{[key: string]: pulumi.Input<string>}>;
    isLockOverride?: pulumi.Input<boolean>;
    /**
     * Locks associated with this resource.
     */
    locks?: pulumi.Input<pulumi.Input<inputs.MediaServices.MediaAssetLock>[]>;
    /**
     * (Updatable) The ID of the senior most asset from which this asset is derived.
     */
    masterMediaAssetId?: pulumi.Input<string>;
    /**
     * (Updatable) list of tags for the MediaAsset.
     */
    mediaAssetTags?: pulumi.Input<pulumi.Input<inputs.MediaServices.MediaAssetMediaAssetTag>[]>;
    /**
     * The ID of the MediaWorkflowJob used to produce this asset.
     */
    mediaWorkflowJobId?: pulumi.Input<string>;
    /**
     * (Updatable) List of Metadata.
     */
    metadatas?: pulumi.Input<pulumi.Input<inputs.MediaServices.MediaAssetMetadata>[]>;
    /**
     * The object storage namespace where this asset is located.
     */
    namespace?: pulumi.Input<string>;
    /**
     * The object storage object name that identifies this asset.
     */
    object?: pulumi.Input<string>;
    /**
     * eTag of the underlying object storage object.
     */
    objectEtag?: pulumi.Input<string>;
    /**
     * (Updatable) The ID of the parent asset from which this asset is derived.
     */
    parentMediaAssetId?: pulumi.Input<string>;
    /**
     * The end index for video segment files.
     */
    segmentRangeEndIndex?: pulumi.Input<string>;
    /**
     * The start index for video segment files.
     */
    segmentRangeStartIndex?: pulumi.Input<string>;
    /**
     * The ID of the MediaWorkflow used to produce this asset.
     */
    sourceMediaWorkflowId?: pulumi.Input<string>;
    /**
     * The version of the MediaWorkflow used to produce this asset.
     */
    sourceMediaWorkflowVersion?: pulumi.Input<string>;
    /**
     * The current state of the MediaAsset.
     */
    state?: pulumi.Input<string>;
    /**
     * Usage of system tag keys. These predefined keys are scoped to namespaces. Example: `{"orcl-cloud.free-tier-retained": "true"}`
     */
    systemTags?: pulumi.Input<{[key: string]: pulumi.Input<string>}>;
    /**
     * The time when the MediaAsset was created. An RFC3339 formatted datetime string.
     */
    timeCreated?: pulumi.Input<string>;
    /**
     * The time when the MediaAsset was updated. An RFC3339 formatted datetime string.
     */
    timeUpdated?: pulumi.Input<string>;
    /**
     * (Updatable) The type of the media asset.
     *
     *
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     */
    type?: pulumi.Input<string>;
}

/**
 * The set of arguments for constructing a MediaAsset resource.
 */
export interface MediaAssetArgs {
    /**
     * The name of the object storage bucket where this asset is located.
     */
    bucket?: pulumi.Input<string>;
    /**
     * (Updatable) Compartment Identifier.
     */
    compartmentId: pulumi.Input<string>;
    /**
     * (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
     */
    definedTags?: pulumi.Input<{[key: string]: pulumi.Input<string>}>;
    /**
     * (Updatable) Display name for the Media Asset. Does not have to be unique. Avoid entering confidential information.
     */
    displayName?: pulumi.Input<string>;
    /**
     * (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
     */
    freeformTags?: pulumi.Input<{[key: string]: pulumi.Input<string>}>;
    isLockOverride?: pulumi.Input<boolean>;
    /**
     * Locks associated with this resource.
     */
    locks?: pulumi.Input<pulumi.Input<inputs.MediaServices.MediaAssetLock>[]>;
    /**
     * (Updatable) The ID of the senior most asset from which this asset is derived.
     */
    masterMediaAssetId?: pulumi.Input<string>;
    /**
     * (Updatable) list of tags for the MediaAsset.
     */
    mediaAssetTags?: pulumi.Input<pulumi.Input<inputs.MediaServices.MediaAssetMediaAssetTag>[]>;
    /**
     * The ID of the MediaWorkflowJob used to produce this asset.
     */
    mediaWorkflowJobId?: pulumi.Input<string>;
    /**
     * (Updatable) List of Metadata.
     */
    metadatas?: pulumi.Input<pulumi.Input<inputs.MediaServices.MediaAssetMetadata>[]>;
    /**
     * The object storage namespace where this asset is located.
     */
    namespace?: pulumi.Input<string>;
    /**
     * The object storage object name that identifies this asset.
     */
    object?: pulumi.Input<string>;
    /**
     * eTag of the underlying object storage object.
     */
    objectEtag?: pulumi.Input<string>;
    /**
     * (Updatable) The ID of the parent asset from which this asset is derived.
     */
    parentMediaAssetId?: pulumi.Input<string>;
    /**
     * The end index for video segment files.
     */
    segmentRangeEndIndex?: pulumi.Input<string>;
    /**
     * The start index for video segment files.
     */
    segmentRangeStartIndex?: pulumi.Input<string>;
    /**
     * The ID of the MediaWorkflow used to produce this asset.
     */
    sourceMediaWorkflowId?: pulumi.Input<string>;
    /**
     * The version of the MediaWorkflow used to produce this asset.
     */
    sourceMediaWorkflowVersion?: pulumi.Input<string>;
    /**
     * (Updatable) The type of the media asset.
     *
     *
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     */
    type: pulumi.Input<string>;
}
