// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.MediaServices;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Export;
import com.pulumi.core.annotations.ResourceType;
import com.pulumi.core.internal.Codegen;
import com.pulumi.oci.MediaServices.MediaAssetArgs;
import com.pulumi.oci.MediaServices.inputs.MediaAssetState;
import com.pulumi.oci.MediaServices.outputs.MediaAssetLock;
import com.pulumi.oci.MediaServices.outputs.MediaAssetMediaAssetTag;
import com.pulumi.oci.MediaServices.outputs.MediaAssetMetadata;
import com.pulumi.oci.Utilities;
import java.lang.Boolean;
import java.lang.String;
import java.util.List;
import java.util.Map;
import javax.annotation.Nullable;

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
 * $ pulumi import oci:MediaServices/mediaAsset:MediaAsset test_media_asset &#34;id&#34;
 * ```
 * 
 */
@ResourceType(type="oci:MediaServices/mediaAsset:MediaAsset")
public class MediaAsset extends com.pulumi.resources.CustomResource {
    /**
     * The name of the object storage bucket where this asset is located.
     * 
     */
    @Export(name="bucket", refs={String.class}, tree="[0]")
    private Output<String> bucket;

    /**
     * @return The name of the object storage bucket where this asset is located.
     * 
     */
    public Output<String> bucket() {
        return this.bucket;
    }
    /**
     * (Updatable) Compartment Identifier.
     * 
     */
    @Export(name="compartmentId", refs={String.class}, tree="[0]")
    private Output<String> compartmentId;

    /**
     * @return (Updatable) Compartment Identifier.
     * 
     */
    public Output<String> compartmentId() {
        return this.compartmentId;
    }
    /**
     * (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{&#34;foo-namespace.bar-key&#34;: &#34;value&#34;}`
     * 
     */
    @Export(name="definedTags", refs={Map.class,String.class}, tree="[0,1,1]")
    private Output<Map<String,String>> definedTags;

    /**
     * @return (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{&#34;foo-namespace.bar-key&#34;: &#34;value&#34;}`
     * 
     */
    public Output<Map<String,String>> definedTags() {
        return this.definedTags;
    }
    /**
     * (Updatable) Display name for the Media Asset. Does not have to be unique. Avoid entering confidential information.
     * 
     */
    @Export(name="displayName", refs={String.class}, tree="[0]")
    private Output<String> displayName;

    /**
     * @return (Updatable) Display name for the Media Asset. Does not have to be unique. Avoid entering confidential information.
     * 
     */
    public Output<String> displayName() {
        return this.displayName;
    }
    /**
     * (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{&#34;bar-key&#34;: &#34;value&#34;}`
     * 
     */
    @Export(name="freeformTags", refs={Map.class,String.class}, tree="[0,1,1]")
    private Output<Map<String,String>> freeformTags;

    /**
     * @return (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{&#34;bar-key&#34;: &#34;value&#34;}`
     * 
     */
    public Output<Map<String,String>> freeformTags() {
        return this.freeformTags;
    }
    @Export(name="isLockOverride", refs={Boolean.class}, tree="[0]")
    private Output<Boolean> isLockOverride;

    public Output<Boolean> isLockOverride() {
        return this.isLockOverride;
    }
    /**
     * Locks associated with this resource.
     * 
     */
    @Export(name="locks", refs={List.class,MediaAssetLock.class}, tree="[0,1]")
    private Output<List<MediaAssetLock>> locks;

    /**
     * @return Locks associated with this resource.
     * 
     */
    public Output<List<MediaAssetLock>> locks() {
        return this.locks;
    }
    /**
     * (Updatable) The ID of the senior most asset from which this asset is derived.
     * 
     */
    @Export(name="masterMediaAssetId", refs={String.class}, tree="[0]")
    private Output<String> masterMediaAssetId;

    /**
     * @return (Updatable) The ID of the senior most asset from which this asset is derived.
     * 
     */
    public Output<String> masterMediaAssetId() {
        return this.masterMediaAssetId;
    }
    /**
     * (Updatable) list of tags for the MediaAsset.
     * 
     */
    @Export(name="mediaAssetTags", refs={List.class,MediaAssetMediaAssetTag.class}, tree="[0,1]")
    private Output<List<MediaAssetMediaAssetTag>> mediaAssetTags;

    /**
     * @return (Updatable) list of tags for the MediaAsset.
     * 
     */
    public Output<List<MediaAssetMediaAssetTag>> mediaAssetTags() {
        return this.mediaAssetTags;
    }
    /**
     * The ID of the MediaWorkflowJob used to produce this asset.
     * 
     */
    @Export(name="mediaWorkflowJobId", refs={String.class}, tree="[0]")
    private Output<String> mediaWorkflowJobId;

    /**
     * @return The ID of the MediaWorkflowJob used to produce this asset.
     * 
     */
    public Output<String> mediaWorkflowJobId() {
        return this.mediaWorkflowJobId;
    }
    /**
     * (Updatable) List of Metadata.
     * 
     */
    @Export(name="metadatas", refs={List.class,MediaAssetMetadata.class}, tree="[0,1]")
    private Output<List<MediaAssetMetadata>> metadatas;

    /**
     * @return (Updatable) List of Metadata.
     * 
     */
    public Output<List<MediaAssetMetadata>> metadatas() {
        return this.metadatas;
    }
    /**
     * The object storage namespace where this asset is located.
     * 
     */
    @Export(name="namespace", refs={String.class}, tree="[0]")
    private Output<String> namespace;

    /**
     * @return The object storage namespace where this asset is located.
     * 
     */
    public Output<String> namespace() {
        return this.namespace;
    }
    /**
     * The object storage object name that identifies this asset.
     * 
     */
    @Export(name="object", refs={String.class}, tree="[0]")
    private Output<String> object;

    /**
     * @return The object storage object name that identifies this asset.
     * 
     */
    public Output<String> object() {
        return this.object;
    }
    /**
     * eTag of the underlying object storage object.
     * 
     */
    @Export(name="objectEtag", refs={String.class}, tree="[0]")
    private Output<String> objectEtag;

    /**
     * @return eTag of the underlying object storage object.
     * 
     */
    public Output<String> objectEtag() {
        return this.objectEtag;
    }
    /**
     * (Updatable) The ID of the parent asset from which this asset is derived.
     * 
     */
    @Export(name="parentMediaAssetId", refs={String.class}, tree="[0]")
    private Output<String> parentMediaAssetId;

    /**
     * @return (Updatable) The ID of the parent asset from which this asset is derived.
     * 
     */
    public Output<String> parentMediaAssetId() {
        return this.parentMediaAssetId;
    }
    /**
     * The end index for video segment files.
     * 
     */
    @Export(name="segmentRangeEndIndex", refs={String.class}, tree="[0]")
    private Output<String> segmentRangeEndIndex;

    /**
     * @return The end index for video segment files.
     * 
     */
    public Output<String> segmentRangeEndIndex() {
        return this.segmentRangeEndIndex;
    }
    /**
     * The start index for video segment files.
     * 
     */
    @Export(name="segmentRangeStartIndex", refs={String.class}, tree="[0]")
    private Output<String> segmentRangeStartIndex;

    /**
     * @return The start index for video segment files.
     * 
     */
    public Output<String> segmentRangeStartIndex() {
        return this.segmentRangeStartIndex;
    }
    /**
     * The ID of the MediaWorkflow used to produce this asset.
     * 
     */
    @Export(name="sourceMediaWorkflowId", refs={String.class}, tree="[0]")
    private Output<String> sourceMediaWorkflowId;

    /**
     * @return The ID of the MediaWorkflow used to produce this asset.
     * 
     */
    public Output<String> sourceMediaWorkflowId() {
        return this.sourceMediaWorkflowId;
    }
    /**
     * The version of the MediaWorkflow used to produce this asset.
     * 
     */
    @Export(name="sourceMediaWorkflowVersion", refs={String.class}, tree="[0]")
    private Output<String> sourceMediaWorkflowVersion;

    /**
     * @return The version of the MediaWorkflow used to produce this asset.
     * 
     */
    public Output<String> sourceMediaWorkflowVersion() {
        return this.sourceMediaWorkflowVersion;
    }
    /**
     * The current state of the MediaAsset.
     * 
     */
    @Export(name="state", refs={String.class}, tree="[0]")
    private Output<String> state;

    /**
     * @return The current state of the MediaAsset.
     * 
     */
    public Output<String> state() {
        return this.state;
    }
    /**
     * Usage of system tag keys. These predefined keys are scoped to namespaces. Example: `{&#34;orcl-cloud.free-tier-retained&#34;: &#34;true&#34;}`
     * 
     */
    @Export(name="systemTags", refs={Map.class,String.class}, tree="[0,1,1]")
    private Output<Map<String,String>> systemTags;

    /**
     * @return Usage of system tag keys. These predefined keys are scoped to namespaces. Example: `{&#34;orcl-cloud.free-tier-retained&#34;: &#34;true&#34;}`
     * 
     */
    public Output<Map<String,String>> systemTags() {
        return this.systemTags;
    }
    /**
     * The time when the MediaAsset was created. An RFC3339 formatted datetime string.
     * 
     */
    @Export(name="timeCreated", refs={String.class}, tree="[0]")
    private Output<String> timeCreated;

    /**
     * @return The time when the MediaAsset was created. An RFC3339 formatted datetime string.
     * 
     */
    public Output<String> timeCreated() {
        return this.timeCreated;
    }
    /**
     * The time when the MediaAsset was updated. An RFC3339 formatted datetime string.
     * 
     */
    @Export(name="timeUpdated", refs={String.class}, tree="[0]")
    private Output<String> timeUpdated;

    /**
     * @return The time when the MediaAsset was updated. An RFC3339 formatted datetime string.
     * 
     */
    public Output<String> timeUpdated() {
        return this.timeUpdated;
    }
    /**
     * (Updatable) The type of the media asset.
     * 
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     * 
     */
    @Export(name="type", refs={String.class}, tree="[0]")
    private Output<String> type;

    /**
     * @return (Updatable) The type of the media asset.
     * 
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     * 
     */
    public Output<String> type() {
        return this.type;
    }

    /**
     *
     * @param name The _unique_ name of the resulting resource.
     */
    public MediaAsset(java.lang.String name) {
        this(name, MediaAssetArgs.Empty);
    }
    /**
     *
     * @param name The _unique_ name of the resulting resource.
     * @param args The arguments to use to populate this resource's properties.
     */
    public MediaAsset(java.lang.String name, MediaAssetArgs args) {
        this(name, args, null);
    }
    /**
     *
     * @param name The _unique_ name of the resulting resource.
     * @param args The arguments to use to populate this resource's properties.
     * @param options A bag of options that control this resource's behavior.
     */
    public MediaAsset(java.lang.String name, MediaAssetArgs args, @Nullable com.pulumi.resources.CustomResourceOptions options) {
        super("oci:MediaServices/mediaAsset:MediaAsset", name, makeArgs(args, options), makeResourceOptions(options, Codegen.empty()), false);
    }

    private MediaAsset(java.lang.String name, Output<java.lang.String> id, @Nullable MediaAssetState state, @Nullable com.pulumi.resources.CustomResourceOptions options) {
        super("oci:MediaServices/mediaAsset:MediaAsset", name, state, makeResourceOptions(options, id), false);
    }

    private static MediaAssetArgs makeArgs(MediaAssetArgs args, @Nullable com.pulumi.resources.CustomResourceOptions options) {
        if (options != null && options.getUrn().isPresent()) {
            return null;
        }
        return args == null ? MediaAssetArgs.Empty : args;
    }

    private static com.pulumi.resources.CustomResourceOptions makeResourceOptions(@Nullable com.pulumi.resources.CustomResourceOptions options, @Nullable Output<java.lang.String> id) {
        var defaultOptions = com.pulumi.resources.CustomResourceOptions.builder()
            .version(Utilities.getVersion())
            .build();
        return com.pulumi.resources.CustomResourceOptions.merge(defaultOptions, options, id);
    }

    /**
     * Get an existing Host resource's state with the given name, ID, and optional extra
     * properties used to qualify the lookup.
     *
     * @param name The _unique_ name of the resulting resource.
     * @param id The _unique_ provider ID of the resource to lookup.
     * @param state
     * @param options Optional settings to control the behavior of the CustomResource.
     */
    public static MediaAsset get(java.lang.String name, Output<java.lang.String> id, @Nullable MediaAssetState state, @Nullable com.pulumi.resources.CustomResourceOptions options) {
        return new MediaAsset(name, id, state, options);
    }
}
