// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Opsi.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import java.lang.String;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class EnterpriseManagerBridgeState extends com.pulumi.resources.ResourceArgs {

    public static final EnterpriseManagerBridgeState Empty = new EnterpriseManagerBridgeState();

    /**
     * (Updatable) Compartment identifier of the Enterprise Manager bridge
     * 
     */
    @Import(name="compartmentId")
    private @Nullable Output<String> compartmentId;

    /**
     * @return (Updatable) Compartment identifier of the Enterprise Manager bridge
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
    private @Nullable Output<Map<String,String>> definedTags;

    /**
     * @return (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{&#34;foo-namespace.bar-key&#34;: &#34;value&#34;}`
     * 
     */
    public Optional<Output<Map<String,String>>> definedTags() {
        return Optional.ofNullable(this.definedTags);
    }

    /**
     * (Updatable) Description of Enterprise Manager Bridge
     * 
     */
    @Import(name="description")
    private @Nullable Output<String> description;

    /**
     * @return (Updatable) Description of Enterprise Manager Bridge
     * 
     */
    public Optional<Output<String>> description() {
        return Optional.ofNullable(this.description);
    }

    /**
     * (Updatable) User-friedly name of Enterprise Manager Bridge that does not have to be unique.
     * 
     */
    @Import(name="displayName")
    private @Nullable Output<String> displayName;

    /**
     * @return (Updatable) User-friedly name of Enterprise Manager Bridge that does not have to be unique.
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
    private @Nullable Output<Map<String,String>> freeformTags;

    /**
     * @return (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{&#34;bar-key&#34;: &#34;value&#34;}`
     * 
     */
    public Optional<Output<Map<String,String>>> freeformTags() {
        return Optional.ofNullable(this.freeformTags);
    }

    /**
     * A message describing the current state in more detail. For example, can be used to provide actionable information for a resource in Failed state.
     * 
     */
    @Import(name="lifecycleDetails")
    private @Nullable Output<String> lifecycleDetails;

    /**
     * @return A message describing the current state in more detail. For example, can be used to provide actionable information for a resource in Failed state.
     * 
     */
    public Optional<Output<String>> lifecycleDetails() {
        return Optional.ofNullable(this.lifecycleDetails);
    }

    /**
     * Object Storage Bucket Name
     * 
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     * 
     */
    @Import(name="objectStorageBucketName")
    private @Nullable Output<String> objectStorageBucketName;

    /**
     * @return Object Storage Bucket Name
     * 
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     * 
     */
    public Optional<Output<String>> objectStorageBucketName() {
        return Optional.ofNullable(this.objectStorageBucketName);
    }

    /**
     * A message describing status of the object storage bucket of this resource. For example, it can be used to provide actionable information about the permission and content validity of the bucket.
     * 
     */
    @Import(name="objectStorageBucketStatusDetails")
    private @Nullable Output<String> objectStorageBucketStatusDetails;

    /**
     * @return A message describing status of the object storage bucket of this resource. For example, it can be used to provide actionable information about the permission and content validity of the bucket.
     * 
     */
    public Optional<Output<String>> objectStorageBucketStatusDetails() {
        return Optional.ofNullable(this.objectStorageBucketStatusDetails);
    }

    /**
     * Object Storage Namespace Name
     * 
     */
    @Import(name="objectStorageNamespaceName")
    private @Nullable Output<String> objectStorageNamespaceName;

    /**
     * @return Object Storage Namespace Name
     * 
     */
    public Optional<Output<String>> objectStorageNamespaceName() {
        return Optional.ofNullable(this.objectStorageNamespaceName);
    }

    /**
     * The current state of the Enterprise Manager bridge.
     * 
     */
    @Import(name="state")
    private @Nullable Output<String> state;

    /**
     * @return The current state of the Enterprise Manager bridge.
     * 
     */
    public Optional<Output<String>> state() {
        return Optional.ofNullable(this.state);
    }

    /**
     * System tags for this resource. Each key is predefined and scoped to a namespace. Example: `{&#34;orcl-cloud.free-tier-retained&#34;: &#34;true&#34;}`
     * 
     */
    @Import(name="systemTags")
    private @Nullable Output<Map<String,String>> systemTags;

    /**
     * @return System tags for this resource. Each key is predefined and scoped to a namespace. Example: `{&#34;orcl-cloud.free-tier-retained&#34;: &#34;true&#34;}`
     * 
     */
    public Optional<Output<Map<String,String>>> systemTags() {
        return Optional.ofNullable(this.systemTags);
    }

    /**
     * The time the the Enterprise Manager bridge was first created. An RFC3339 formatted datetime string
     * 
     */
    @Import(name="timeCreated")
    private @Nullable Output<String> timeCreated;

    /**
     * @return The time the the Enterprise Manager bridge was first created. An RFC3339 formatted datetime string
     * 
     */
    public Optional<Output<String>> timeCreated() {
        return Optional.ofNullable(this.timeCreated);
    }

    /**
     * The time the Enterprise Manager bridge was updated. An RFC3339 formatted datetime string
     * 
     */
    @Import(name="timeUpdated")
    private @Nullable Output<String> timeUpdated;

    /**
     * @return The time the Enterprise Manager bridge was updated. An RFC3339 formatted datetime string
     * 
     */
    public Optional<Output<String>> timeUpdated() {
        return Optional.ofNullable(this.timeUpdated);
    }

    private EnterpriseManagerBridgeState() {}

    private EnterpriseManagerBridgeState(EnterpriseManagerBridgeState $) {
        this.compartmentId = $.compartmentId;
        this.definedTags = $.definedTags;
        this.description = $.description;
        this.displayName = $.displayName;
        this.freeformTags = $.freeformTags;
        this.lifecycleDetails = $.lifecycleDetails;
        this.objectStorageBucketName = $.objectStorageBucketName;
        this.objectStorageBucketStatusDetails = $.objectStorageBucketStatusDetails;
        this.objectStorageNamespaceName = $.objectStorageNamespaceName;
        this.state = $.state;
        this.systemTags = $.systemTags;
        this.timeCreated = $.timeCreated;
        this.timeUpdated = $.timeUpdated;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(EnterpriseManagerBridgeState defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private EnterpriseManagerBridgeState $;

        public Builder() {
            $ = new EnterpriseManagerBridgeState();
        }

        public Builder(EnterpriseManagerBridgeState defaults) {
            $ = new EnterpriseManagerBridgeState(Objects.requireNonNull(defaults));
        }

        /**
         * @param compartmentId (Updatable) Compartment identifier of the Enterprise Manager bridge
         * 
         * @return builder
         * 
         */
        public Builder compartmentId(@Nullable Output<String> compartmentId) {
            $.compartmentId = compartmentId;
            return this;
        }

        /**
         * @param compartmentId (Updatable) Compartment identifier of the Enterprise Manager bridge
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
        public Builder definedTags(@Nullable Output<Map<String,String>> definedTags) {
            $.definedTags = definedTags;
            return this;
        }

        /**
         * @param definedTags (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{&#34;foo-namespace.bar-key&#34;: &#34;value&#34;}`
         * 
         * @return builder
         * 
         */
        public Builder definedTags(Map<String,String> definedTags) {
            return definedTags(Output.of(definedTags));
        }

        /**
         * @param description (Updatable) Description of Enterprise Manager Bridge
         * 
         * @return builder
         * 
         */
        public Builder description(@Nullable Output<String> description) {
            $.description = description;
            return this;
        }

        /**
         * @param description (Updatable) Description of Enterprise Manager Bridge
         * 
         * @return builder
         * 
         */
        public Builder description(String description) {
            return description(Output.of(description));
        }

        /**
         * @param displayName (Updatable) User-friedly name of Enterprise Manager Bridge that does not have to be unique.
         * 
         * @return builder
         * 
         */
        public Builder displayName(@Nullable Output<String> displayName) {
            $.displayName = displayName;
            return this;
        }

        /**
         * @param displayName (Updatable) User-friedly name of Enterprise Manager Bridge that does not have to be unique.
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
        public Builder freeformTags(@Nullable Output<Map<String,String>> freeformTags) {
            $.freeformTags = freeformTags;
            return this;
        }

        /**
         * @param freeformTags (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{&#34;bar-key&#34;: &#34;value&#34;}`
         * 
         * @return builder
         * 
         */
        public Builder freeformTags(Map<String,String> freeformTags) {
            return freeformTags(Output.of(freeformTags));
        }

        /**
         * @param lifecycleDetails A message describing the current state in more detail. For example, can be used to provide actionable information for a resource in Failed state.
         * 
         * @return builder
         * 
         */
        public Builder lifecycleDetails(@Nullable Output<String> lifecycleDetails) {
            $.lifecycleDetails = lifecycleDetails;
            return this;
        }

        /**
         * @param lifecycleDetails A message describing the current state in more detail. For example, can be used to provide actionable information for a resource in Failed state.
         * 
         * @return builder
         * 
         */
        public Builder lifecycleDetails(String lifecycleDetails) {
            return lifecycleDetails(Output.of(lifecycleDetails));
        }

        /**
         * @param objectStorageBucketName Object Storage Bucket Name
         * 
         * ** IMPORTANT **
         * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
         * 
         * @return builder
         * 
         */
        public Builder objectStorageBucketName(@Nullable Output<String> objectStorageBucketName) {
            $.objectStorageBucketName = objectStorageBucketName;
            return this;
        }

        /**
         * @param objectStorageBucketName Object Storage Bucket Name
         * 
         * ** IMPORTANT **
         * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
         * 
         * @return builder
         * 
         */
        public Builder objectStorageBucketName(String objectStorageBucketName) {
            return objectStorageBucketName(Output.of(objectStorageBucketName));
        }

        /**
         * @param objectStorageBucketStatusDetails A message describing status of the object storage bucket of this resource. For example, it can be used to provide actionable information about the permission and content validity of the bucket.
         * 
         * @return builder
         * 
         */
        public Builder objectStorageBucketStatusDetails(@Nullable Output<String> objectStorageBucketStatusDetails) {
            $.objectStorageBucketStatusDetails = objectStorageBucketStatusDetails;
            return this;
        }

        /**
         * @param objectStorageBucketStatusDetails A message describing status of the object storage bucket of this resource. For example, it can be used to provide actionable information about the permission and content validity of the bucket.
         * 
         * @return builder
         * 
         */
        public Builder objectStorageBucketStatusDetails(String objectStorageBucketStatusDetails) {
            return objectStorageBucketStatusDetails(Output.of(objectStorageBucketStatusDetails));
        }

        /**
         * @param objectStorageNamespaceName Object Storage Namespace Name
         * 
         * @return builder
         * 
         */
        public Builder objectStorageNamespaceName(@Nullable Output<String> objectStorageNamespaceName) {
            $.objectStorageNamespaceName = objectStorageNamespaceName;
            return this;
        }

        /**
         * @param objectStorageNamespaceName Object Storage Namespace Name
         * 
         * @return builder
         * 
         */
        public Builder objectStorageNamespaceName(String objectStorageNamespaceName) {
            return objectStorageNamespaceName(Output.of(objectStorageNamespaceName));
        }

        /**
         * @param state The current state of the Enterprise Manager bridge.
         * 
         * @return builder
         * 
         */
        public Builder state(@Nullable Output<String> state) {
            $.state = state;
            return this;
        }

        /**
         * @param state The current state of the Enterprise Manager bridge.
         * 
         * @return builder
         * 
         */
        public Builder state(String state) {
            return state(Output.of(state));
        }

        /**
         * @param systemTags System tags for this resource. Each key is predefined and scoped to a namespace. Example: `{&#34;orcl-cloud.free-tier-retained&#34;: &#34;true&#34;}`
         * 
         * @return builder
         * 
         */
        public Builder systemTags(@Nullable Output<Map<String,String>> systemTags) {
            $.systemTags = systemTags;
            return this;
        }

        /**
         * @param systemTags System tags for this resource. Each key is predefined and scoped to a namespace. Example: `{&#34;orcl-cloud.free-tier-retained&#34;: &#34;true&#34;}`
         * 
         * @return builder
         * 
         */
        public Builder systemTags(Map<String,String> systemTags) {
            return systemTags(Output.of(systemTags));
        }

        /**
         * @param timeCreated The time the the Enterprise Manager bridge was first created. An RFC3339 formatted datetime string
         * 
         * @return builder
         * 
         */
        public Builder timeCreated(@Nullable Output<String> timeCreated) {
            $.timeCreated = timeCreated;
            return this;
        }

        /**
         * @param timeCreated The time the the Enterprise Manager bridge was first created. An RFC3339 formatted datetime string
         * 
         * @return builder
         * 
         */
        public Builder timeCreated(String timeCreated) {
            return timeCreated(Output.of(timeCreated));
        }

        /**
         * @param timeUpdated The time the Enterprise Manager bridge was updated. An RFC3339 formatted datetime string
         * 
         * @return builder
         * 
         */
        public Builder timeUpdated(@Nullable Output<String> timeUpdated) {
            $.timeUpdated = timeUpdated;
            return this;
        }

        /**
         * @param timeUpdated The time the Enterprise Manager bridge was updated. An RFC3339 formatted datetime string
         * 
         * @return builder
         * 
         */
        public Builder timeUpdated(String timeUpdated) {
            return timeUpdated(Output.of(timeUpdated));
        }

        public EnterpriseManagerBridgeState build() {
            return $;
        }
    }

}
