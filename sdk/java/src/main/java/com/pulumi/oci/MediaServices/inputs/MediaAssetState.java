// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.MediaServices.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import com.pulumi.oci.MediaServices.inputs.MediaAssetMediaAssetTagArgs;
import com.pulumi.oci.MediaServices.inputs.MediaAssetMetadataArgs;
import java.lang.Object;
import java.lang.String;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class MediaAssetState extends com.pulumi.resources.ResourceArgs {

    public static final MediaAssetState Empty = new MediaAssetState();

    /**
     * The name of the object storage bucket where this asset is located.
     * 
     */
    @Import(name="bucket")
    private @Nullable Output<String> bucket;

    /**
     * @return The name of the object storage bucket where this asset is located.
     * 
     */
    public Optional<Output<String>> bucket() {
        return Optional.ofNullable(this.bucket);
    }

    /**
     * (Updatable) Compartment Identifier.
     * 
     */
    @Import(name="compartmentId")
    private @Nullable Output<String> compartmentId;

    /**
     * @return (Updatable) Compartment Identifier.
     * 
     */
    public Optional<Output<String>> compartmentId() {
        return Optional.ofNullable(this.compartmentId);
    }

    /**
     * (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{&#34;foo-namespace.bar-key&#34;: &#34;value&#34;}`
     * 
     */
    @Import(name="definedTags")
    private @Nullable Output<Map<String,Object>> definedTags;

    /**
     * @return (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{&#34;foo-namespace.bar-key&#34;: &#34;value&#34;}`
     * 
     */
    public Optional<Output<Map<String,Object>>> definedTags() {
        return Optional.ofNullable(this.definedTags);
    }

    /**
     * (Updatable) Display name for the Media Asset. Does not have to be unique. Avoid entering confidential information.
     * 
     */
    @Import(name="displayName")
    private @Nullable Output<String> displayName;

    /**
     * @return (Updatable) Display name for the Media Asset. Does not have to be unique. Avoid entering confidential information.
     * 
     */
    public Optional<Output<String>> displayName() {
        return Optional.ofNullable(this.displayName);
    }

    /**
     * (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{&#34;bar-key&#34;: &#34;value&#34;}`
     * 
     */
    @Import(name="freeformTags")
    private @Nullable Output<Map<String,Object>> freeformTags;

    /**
     * @return (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{&#34;bar-key&#34;: &#34;value&#34;}`
     * 
     */
    public Optional<Output<Map<String,Object>>> freeformTags() {
        return Optional.ofNullable(this.freeformTags);
    }

    /**
     * (Updatable) The ID of the senior most asset from which this asset is derived.
     * 
     */
    @Import(name="masterMediaAssetId")
    private @Nullable Output<String> masterMediaAssetId;

    /**
     * @return (Updatable) The ID of the senior most asset from which this asset is derived.
     * 
     */
    public Optional<Output<String>> masterMediaAssetId() {
        return Optional.ofNullable(this.masterMediaAssetId);
    }

    /**
     * (Updatable) list of tags for the MediaAsset.
     * 
     */
    @Import(name="mediaAssetTags")
    private @Nullable Output<List<MediaAssetMediaAssetTagArgs>> mediaAssetTags;

    /**
     * @return (Updatable) list of tags for the MediaAsset.
     * 
     */
    public Optional<Output<List<MediaAssetMediaAssetTagArgs>>> mediaAssetTags() {
        return Optional.ofNullable(this.mediaAssetTags);
    }

    /**
     * The ID of the MediaWorkflowJob used to produce this asset.
     * 
     */
    @Import(name="mediaWorkflowJobId")
    private @Nullable Output<String> mediaWorkflowJobId;

    /**
     * @return The ID of the MediaWorkflowJob used to produce this asset.
     * 
     */
    public Optional<Output<String>> mediaWorkflowJobId() {
        return Optional.ofNullable(this.mediaWorkflowJobId);
    }

    /**
     * (Updatable) JSON string containing the technial metadata for the media asset.
     * 
     */
    @Import(name="metadatas")
    private @Nullable Output<List<MediaAssetMetadataArgs>> metadatas;

    /**
     * @return (Updatable) JSON string containing the technial metadata for the media asset.
     * 
     */
    public Optional<Output<List<MediaAssetMetadataArgs>>> metadatas() {
        return Optional.ofNullable(this.metadatas);
    }

    /**
     * The object storage namespace where this asset is located.
     * 
     */
    @Import(name="namespace")
    private @Nullable Output<String> namespace;

    /**
     * @return The object storage namespace where this asset is located.
     * 
     */
    public Optional<Output<String>> namespace() {
        return Optional.ofNullable(this.namespace);
    }

    /**
     * The object storage object name that identifies this asset.
     * 
     */
    @Import(name="object")
    private @Nullable Output<String> object;

    /**
     * @return The object storage object name that identifies this asset.
     * 
     */
    public Optional<Output<String>> object() {
        return Optional.ofNullable(this.object);
    }

    /**
     * eTag of the underlying object storage object.
     * 
     */
    @Import(name="objectEtag")
    private @Nullable Output<String> objectEtag;

    /**
     * @return eTag of the underlying object storage object.
     * 
     */
    public Optional<Output<String>> objectEtag() {
        return Optional.ofNullable(this.objectEtag);
    }

    /**
     * (Updatable) The ID of the parent asset from which this asset is derived.
     * 
     */
    @Import(name="parentMediaAssetId")
    private @Nullable Output<String> parentMediaAssetId;

    /**
     * @return (Updatable) The ID of the parent asset from which this asset is derived.
     * 
     */
    public Optional<Output<String>> parentMediaAssetId() {
        return Optional.ofNullable(this.parentMediaAssetId);
    }

    /**
     * The end index for video segment files.
     * 
     */
    @Import(name="segmentRangeEndIndex")
    private @Nullable Output<String> segmentRangeEndIndex;

    /**
     * @return The end index for video segment files.
     * 
     */
    public Optional<Output<String>> segmentRangeEndIndex() {
        return Optional.ofNullable(this.segmentRangeEndIndex);
    }

    /**
     * The start index for video segment files.
     * 
     */
    @Import(name="segmentRangeStartIndex")
    private @Nullable Output<String> segmentRangeStartIndex;

    /**
     * @return The start index for video segment files.
     * 
     */
    public Optional<Output<String>> segmentRangeStartIndex() {
        return Optional.ofNullable(this.segmentRangeStartIndex);
    }

    /**
     * The ID of the MediaWorkflow used to produce this asset.
     * 
     */
    @Import(name="sourceMediaWorkflowId")
    private @Nullable Output<String> sourceMediaWorkflowId;

    /**
     * @return The ID of the MediaWorkflow used to produce this asset.
     * 
     */
    public Optional<Output<String>> sourceMediaWorkflowId() {
        return Optional.ofNullable(this.sourceMediaWorkflowId);
    }

    /**
     * The version of the MediaWorkflow used to produce this asset.
     * 
     */
    @Import(name="sourceMediaWorkflowVersion")
    private @Nullable Output<String> sourceMediaWorkflowVersion;

    /**
     * @return The version of the MediaWorkflow used to produce this asset.
     * 
     */
    public Optional<Output<String>> sourceMediaWorkflowVersion() {
        return Optional.ofNullable(this.sourceMediaWorkflowVersion);
    }

    /**
     * The current state of the MediaAsset.
     * 
     */
    @Import(name="state")
    private @Nullable Output<String> state;

    /**
     * @return The current state of the MediaAsset.
     * 
     */
    public Optional<Output<String>> state() {
        return Optional.ofNullable(this.state);
    }

    /**
     * Usage of system tag keys. These predefined keys are scoped to namespaces. Example: `{&#34;orcl-cloud.free-tier-retained&#34;: &#34;true&#34;}`
     * 
     */
    @Import(name="systemTags")
    private @Nullable Output<Map<String,Object>> systemTags;

    /**
     * @return Usage of system tag keys. These predefined keys are scoped to namespaces. Example: `{&#34;orcl-cloud.free-tier-retained&#34;: &#34;true&#34;}`
     * 
     */
    public Optional<Output<Map<String,Object>>> systemTags() {
        return Optional.ofNullable(this.systemTags);
    }

    /**
     * The time when the MediaAsset was created. An RFC3339 formatted datetime string.
     * 
     */
    @Import(name="timeCreated")
    private @Nullable Output<String> timeCreated;

    /**
     * @return The time when the MediaAsset was created. An RFC3339 formatted datetime string.
     * 
     */
    public Optional<Output<String>> timeCreated() {
        return Optional.ofNullable(this.timeCreated);
    }

    /**
     * The time when the MediaAsset was updated. An RFC3339 formatted datetime string.
     * 
     */
    @Import(name="timeUpdated")
    private @Nullable Output<String> timeUpdated;

    /**
     * @return The time when the MediaAsset was updated. An RFC3339 formatted datetime string.
     * 
     */
    public Optional<Output<String>> timeUpdated() {
        return Optional.ofNullable(this.timeUpdated);
    }

    /**
     * (Updatable) The type of the media asset.
     * 
     */
    @Import(name="type")
    private @Nullable Output<String> type;

    /**
     * @return (Updatable) The type of the media asset.
     * 
     */
    public Optional<Output<String>> type() {
        return Optional.ofNullable(this.type);
    }

    private MediaAssetState() {}

    private MediaAssetState(MediaAssetState $) {
        this.bucket = $.bucket;
        this.compartmentId = $.compartmentId;
        this.definedTags = $.definedTags;
        this.displayName = $.displayName;
        this.freeformTags = $.freeformTags;
        this.masterMediaAssetId = $.masterMediaAssetId;
        this.mediaAssetTags = $.mediaAssetTags;
        this.mediaWorkflowJobId = $.mediaWorkflowJobId;
        this.metadatas = $.metadatas;
        this.namespace = $.namespace;
        this.object = $.object;
        this.objectEtag = $.objectEtag;
        this.parentMediaAssetId = $.parentMediaAssetId;
        this.segmentRangeEndIndex = $.segmentRangeEndIndex;
        this.segmentRangeStartIndex = $.segmentRangeStartIndex;
        this.sourceMediaWorkflowId = $.sourceMediaWorkflowId;
        this.sourceMediaWorkflowVersion = $.sourceMediaWorkflowVersion;
        this.state = $.state;
        this.systemTags = $.systemTags;
        this.timeCreated = $.timeCreated;
        this.timeUpdated = $.timeUpdated;
        this.type = $.type;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(MediaAssetState defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private MediaAssetState $;

        public Builder() {
            $ = new MediaAssetState();
        }

        public Builder(MediaAssetState defaults) {
            $ = new MediaAssetState(Objects.requireNonNull(defaults));
        }

        /**
         * @param bucket The name of the object storage bucket where this asset is located.
         * 
         * @return builder
         * 
         */
        public Builder bucket(@Nullable Output<String> bucket) {
            $.bucket = bucket;
            return this;
        }

        /**
         * @param bucket The name of the object storage bucket where this asset is located.
         * 
         * @return builder
         * 
         */
        public Builder bucket(String bucket) {
            return bucket(Output.of(bucket));
        }

        /**
         * @param compartmentId (Updatable) Compartment Identifier.
         * 
         * @return builder
         * 
         */
        public Builder compartmentId(@Nullable Output<String> compartmentId) {
            $.compartmentId = compartmentId;
            return this;
        }

        /**
         * @param compartmentId (Updatable) Compartment Identifier.
         * 
         * @return builder
         * 
         */
        public Builder compartmentId(String compartmentId) {
            return compartmentId(Output.of(compartmentId));
        }

        /**
         * @param definedTags (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{&#34;foo-namespace.bar-key&#34;: &#34;value&#34;}`
         * 
         * @return builder
         * 
         */
        public Builder definedTags(@Nullable Output<Map<String,Object>> definedTags) {
            $.definedTags = definedTags;
            return this;
        }

        /**
         * @param definedTags (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{&#34;foo-namespace.bar-key&#34;: &#34;value&#34;}`
         * 
         * @return builder
         * 
         */
        public Builder definedTags(Map<String,Object> definedTags) {
            return definedTags(Output.of(definedTags));
        }

        /**
         * @param displayName (Updatable) Display name for the Media Asset. Does not have to be unique. Avoid entering confidential information.
         * 
         * @return builder
         * 
         */
        public Builder displayName(@Nullable Output<String> displayName) {
            $.displayName = displayName;
            return this;
        }

        /**
         * @param displayName (Updatable) Display name for the Media Asset. Does not have to be unique. Avoid entering confidential information.
         * 
         * @return builder
         * 
         */
        public Builder displayName(String displayName) {
            return displayName(Output.of(displayName));
        }

        /**
         * @param freeformTags (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{&#34;bar-key&#34;: &#34;value&#34;}`
         * 
         * @return builder
         * 
         */
        public Builder freeformTags(@Nullable Output<Map<String,Object>> freeformTags) {
            $.freeformTags = freeformTags;
            return this;
        }

        /**
         * @param freeformTags (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{&#34;bar-key&#34;: &#34;value&#34;}`
         * 
         * @return builder
         * 
         */
        public Builder freeformTags(Map<String,Object> freeformTags) {
            return freeformTags(Output.of(freeformTags));
        }

        /**
         * @param masterMediaAssetId (Updatable) The ID of the senior most asset from which this asset is derived.
         * 
         * @return builder
         * 
         */
        public Builder masterMediaAssetId(@Nullable Output<String> masterMediaAssetId) {
            $.masterMediaAssetId = masterMediaAssetId;
            return this;
        }

        /**
         * @param masterMediaAssetId (Updatable) The ID of the senior most asset from which this asset is derived.
         * 
         * @return builder
         * 
         */
        public Builder masterMediaAssetId(String masterMediaAssetId) {
            return masterMediaAssetId(Output.of(masterMediaAssetId));
        }

        /**
         * @param mediaAssetTags (Updatable) list of tags for the MediaAsset.
         * 
         * @return builder
         * 
         */
        public Builder mediaAssetTags(@Nullable Output<List<MediaAssetMediaAssetTagArgs>> mediaAssetTags) {
            $.mediaAssetTags = mediaAssetTags;
            return this;
        }

        /**
         * @param mediaAssetTags (Updatable) list of tags for the MediaAsset.
         * 
         * @return builder
         * 
         */
        public Builder mediaAssetTags(List<MediaAssetMediaAssetTagArgs> mediaAssetTags) {
            return mediaAssetTags(Output.of(mediaAssetTags));
        }

        /**
         * @param mediaAssetTags (Updatable) list of tags for the MediaAsset.
         * 
         * @return builder
         * 
         */
        public Builder mediaAssetTags(MediaAssetMediaAssetTagArgs... mediaAssetTags) {
            return mediaAssetTags(List.of(mediaAssetTags));
        }

        /**
         * @param mediaWorkflowJobId The ID of the MediaWorkflowJob used to produce this asset.
         * 
         * @return builder
         * 
         */
        public Builder mediaWorkflowJobId(@Nullable Output<String> mediaWorkflowJobId) {
            $.mediaWorkflowJobId = mediaWorkflowJobId;
            return this;
        }

        /**
         * @param mediaWorkflowJobId The ID of the MediaWorkflowJob used to produce this asset.
         * 
         * @return builder
         * 
         */
        public Builder mediaWorkflowJobId(String mediaWorkflowJobId) {
            return mediaWorkflowJobId(Output.of(mediaWorkflowJobId));
        }

        /**
         * @param metadatas (Updatable) JSON string containing the technial metadata for the media asset.
         * 
         * @return builder
         * 
         */
        public Builder metadatas(@Nullable Output<List<MediaAssetMetadataArgs>> metadatas) {
            $.metadatas = metadatas;
            return this;
        }

        /**
         * @param metadatas (Updatable) JSON string containing the technial metadata for the media asset.
         * 
         * @return builder
         * 
         */
        public Builder metadatas(List<MediaAssetMetadataArgs> metadatas) {
            return metadatas(Output.of(metadatas));
        }

        /**
         * @param metadatas (Updatable) JSON string containing the technial metadata for the media asset.
         * 
         * @return builder
         * 
         */
        public Builder metadatas(MediaAssetMetadataArgs... metadatas) {
            return metadatas(List.of(metadatas));
        }

        /**
         * @param namespace The object storage namespace where this asset is located.
         * 
         * @return builder
         * 
         */
        public Builder namespace(@Nullable Output<String> namespace) {
            $.namespace = namespace;
            return this;
        }

        /**
         * @param namespace The object storage namespace where this asset is located.
         * 
         * @return builder
         * 
         */
        public Builder namespace(String namespace) {
            return namespace(Output.of(namespace));
        }

        /**
         * @param object The object storage object name that identifies this asset.
         * 
         * @return builder
         * 
         */
        public Builder object(@Nullable Output<String> object) {
            $.object = object;
            return this;
        }

        /**
         * @param object The object storage object name that identifies this asset.
         * 
         * @return builder
         * 
         */
        public Builder object(String object) {
            return object(Output.of(object));
        }

        /**
         * @param objectEtag eTag of the underlying object storage object.
         * 
         * @return builder
         * 
         */
        public Builder objectEtag(@Nullable Output<String> objectEtag) {
            $.objectEtag = objectEtag;
            return this;
        }

        /**
         * @param objectEtag eTag of the underlying object storage object.
         * 
         * @return builder
         * 
         */
        public Builder objectEtag(String objectEtag) {
            return objectEtag(Output.of(objectEtag));
        }

        /**
         * @param parentMediaAssetId (Updatable) The ID of the parent asset from which this asset is derived.
         * 
         * @return builder
         * 
         */
        public Builder parentMediaAssetId(@Nullable Output<String> parentMediaAssetId) {
            $.parentMediaAssetId = parentMediaAssetId;
            return this;
        }

        /**
         * @param parentMediaAssetId (Updatable) The ID of the parent asset from which this asset is derived.
         * 
         * @return builder
         * 
         */
        public Builder parentMediaAssetId(String parentMediaAssetId) {
            return parentMediaAssetId(Output.of(parentMediaAssetId));
        }

        /**
         * @param segmentRangeEndIndex The end index for video segment files.
         * 
         * @return builder
         * 
         */
        public Builder segmentRangeEndIndex(@Nullable Output<String> segmentRangeEndIndex) {
            $.segmentRangeEndIndex = segmentRangeEndIndex;
            return this;
        }

        /**
         * @param segmentRangeEndIndex The end index for video segment files.
         * 
         * @return builder
         * 
         */
        public Builder segmentRangeEndIndex(String segmentRangeEndIndex) {
            return segmentRangeEndIndex(Output.of(segmentRangeEndIndex));
        }

        /**
         * @param segmentRangeStartIndex The start index for video segment files.
         * 
         * @return builder
         * 
         */
        public Builder segmentRangeStartIndex(@Nullable Output<String> segmentRangeStartIndex) {
            $.segmentRangeStartIndex = segmentRangeStartIndex;
            return this;
        }

        /**
         * @param segmentRangeStartIndex The start index for video segment files.
         * 
         * @return builder
         * 
         */
        public Builder segmentRangeStartIndex(String segmentRangeStartIndex) {
            return segmentRangeStartIndex(Output.of(segmentRangeStartIndex));
        }

        /**
         * @param sourceMediaWorkflowId The ID of the MediaWorkflow used to produce this asset.
         * 
         * @return builder
         * 
         */
        public Builder sourceMediaWorkflowId(@Nullable Output<String> sourceMediaWorkflowId) {
            $.sourceMediaWorkflowId = sourceMediaWorkflowId;
            return this;
        }

        /**
         * @param sourceMediaWorkflowId The ID of the MediaWorkflow used to produce this asset.
         * 
         * @return builder
         * 
         */
        public Builder sourceMediaWorkflowId(String sourceMediaWorkflowId) {
            return sourceMediaWorkflowId(Output.of(sourceMediaWorkflowId));
        }

        /**
         * @param sourceMediaWorkflowVersion The version of the MediaWorkflow used to produce this asset.
         * 
         * @return builder
         * 
         */
        public Builder sourceMediaWorkflowVersion(@Nullable Output<String> sourceMediaWorkflowVersion) {
            $.sourceMediaWorkflowVersion = sourceMediaWorkflowVersion;
            return this;
        }

        /**
         * @param sourceMediaWorkflowVersion The version of the MediaWorkflow used to produce this asset.
         * 
         * @return builder
         * 
         */
        public Builder sourceMediaWorkflowVersion(String sourceMediaWorkflowVersion) {
            return sourceMediaWorkflowVersion(Output.of(sourceMediaWorkflowVersion));
        }

        /**
         * @param state The current state of the MediaAsset.
         * 
         * @return builder
         * 
         */
        public Builder state(@Nullable Output<String> state) {
            $.state = state;
            return this;
        }

        /**
         * @param state The current state of the MediaAsset.
         * 
         * @return builder
         * 
         */
        public Builder state(String state) {
            return state(Output.of(state));
        }

        /**
         * @param systemTags Usage of system tag keys. These predefined keys are scoped to namespaces. Example: `{&#34;orcl-cloud.free-tier-retained&#34;: &#34;true&#34;}`
         * 
         * @return builder
         * 
         */
        public Builder systemTags(@Nullable Output<Map<String,Object>> systemTags) {
            $.systemTags = systemTags;
            return this;
        }

        /**
         * @param systemTags Usage of system tag keys. These predefined keys are scoped to namespaces. Example: `{&#34;orcl-cloud.free-tier-retained&#34;: &#34;true&#34;}`
         * 
         * @return builder
         * 
         */
        public Builder systemTags(Map<String,Object> systemTags) {
            return systemTags(Output.of(systemTags));
        }

        /**
         * @param timeCreated The time when the MediaAsset was created. An RFC3339 formatted datetime string.
         * 
         * @return builder
         * 
         */
        public Builder timeCreated(@Nullable Output<String> timeCreated) {
            $.timeCreated = timeCreated;
            return this;
        }

        /**
         * @param timeCreated The time when the MediaAsset was created. An RFC3339 formatted datetime string.
         * 
         * @return builder
         * 
         */
        public Builder timeCreated(String timeCreated) {
            return timeCreated(Output.of(timeCreated));
        }

        /**
         * @param timeUpdated The time when the MediaAsset was updated. An RFC3339 formatted datetime string.
         * 
         * @return builder
         * 
         */
        public Builder timeUpdated(@Nullable Output<String> timeUpdated) {
            $.timeUpdated = timeUpdated;
            return this;
        }

        /**
         * @param timeUpdated The time when the MediaAsset was updated. An RFC3339 formatted datetime string.
         * 
         * @return builder
         * 
         */
        public Builder timeUpdated(String timeUpdated) {
            return timeUpdated(Output.of(timeUpdated));
        }

        /**
         * @param type (Updatable) The type of the media asset.
         * 
         * @return builder
         * 
         */
        public Builder type(@Nullable Output<String> type) {
            $.type = type;
            return this;
        }

        /**
         * @param type (Updatable) The type of the media asset.
         * 
         * @return builder
         * 
         */
        public Builder type(String type) {
            return type(Output.of(type));
        }

        public MediaAssetState build() {
            return $;
        }
    }

}