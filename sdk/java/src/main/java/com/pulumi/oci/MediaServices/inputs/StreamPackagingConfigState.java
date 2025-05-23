// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.MediaServices.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import com.pulumi.oci.MediaServices.inputs.StreamPackagingConfigEncryptionArgs;
import com.pulumi.oci.MediaServices.inputs.StreamPackagingConfigLockArgs;
import java.lang.Boolean;
import java.lang.Integer;
import java.lang.String;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class StreamPackagingConfigState extends com.pulumi.resources.ResourceArgs {

    public static final StreamPackagingConfigState Empty = new StreamPackagingConfigState();

    /**
     * The compartment ID of the lock.
     * 
     */
    @Import(name="compartmentId")
    private @Nullable Output<String> compartmentId;

    /**
     * @return The compartment ID of the lock.
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
     * (Updatable) The name of the stream Packaging Configuration. Avoid entering confidential information.
     * 
     */
    @Import(name="displayName")
    private @Nullable Output<String> displayName;

    /**
     * @return (Updatable) The name of the stream Packaging Configuration. Avoid entering confidential information.
     * 
     */
    public Optional<Output<String>> displayName() {
        return Optional.ofNullable(this.displayName);
    }

    /**
     * Unique identifier of the Distribution Channel that this stream packaging configuration belongs to.
     * 
     */
    @Import(name="distributionChannelId")
    private @Nullable Output<String> distributionChannelId;

    /**
     * @return Unique identifier of the Distribution Channel that this stream packaging configuration belongs to.
     * 
     */
    public Optional<Output<String>> distributionChannelId() {
        return Optional.ofNullable(this.distributionChannelId);
    }

    /**
     * The encryption used by the stream packaging configuration.
     * 
     */
    @Import(name="encryption")
    private @Nullable Output<StreamPackagingConfigEncryptionArgs> encryption;

    /**
     * @return The encryption used by the stream packaging configuration.
     * 
     */
    public Optional<Output<StreamPackagingConfigEncryptionArgs>> encryption() {
        return Optional.ofNullable(this.encryption);
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

    @Import(name="isLockOverride")
    private @Nullable Output<Boolean> isLockOverride;

    public Optional<Output<Boolean>> isLockOverride() {
        return Optional.ofNullable(this.isLockOverride);
    }

    /**
     * Locks associated with this resource.
     * 
     */
    @Import(name="locks")
    private @Nullable Output<List<StreamPackagingConfigLockArgs>> locks;

    /**
     * @return Locks associated with this resource.
     * 
     */
    public Optional<Output<List<StreamPackagingConfigLockArgs>>> locks() {
        return Optional.ofNullable(this.locks);
    }

    /**
     * The duration in seconds for each fragment.
     * 
     */
    @Import(name="segmentTimeInSeconds")
    private @Nullable Output<Integer> segmentTimeInSeconds;

    /**
     * @return The duration in seconds for each fragment.
     * 
     */
    public Optional<Output<Integer>> segmentTimeInSeconds() {
        return Optional.ofNullable(this.segmentTimeInSeconds);
    }

    /**
     * The current state of the Packaging Configuration.
     * 
     */
    @Import(name="state")
    private @Nullable Output<String> state;

    /**
     * @return The current state of the Packaging Configuration.
     * 
     */
    public Optional<Output<String>> state() {
        return Optional.ofNullable(this.state);
    }

    /**
     * The output format for the package.
     * 
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     * 
     */
    @Import(name="streamPackagingFormat")
    private @Nullable Output<String> streamPackagingFormat;

    /**
     * @return The output format for the package.
     * 
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     * 
     */
    public Optional<Output<String>> streamPackagingFormat() {
        return Optional.ofNullable(this.streamPackagingFormat);
    }

    /**
     * Usage of system tag keys. These predefined keys are scoped to namespaces. Example: `{&#34;orcl-cloud.free-tier-retained&#34;: &#34;true&#34;}`
     * 
     */
    @Import(name="systemTags")
    private @Nullable Output<Map<String,String>> systemTags;

    /**
     * @return Usage of system tag keys. These predefined keys are scoped to namespaces. Example: `{&#34;orcl-cloud.free-tier-retained&#34;: &#34;true&#34;}`
     * 
     */
    public Optional<Output<Map<String,String>>> systemTags() {
        return Optional.ofNullable(this.systemTags);
    }

    /**
     * The time when the Packaging Configuration was created. An RFC3339 formatted datetime string.
     * 
     */
    @Import(name="timeCreated")
    private @Nullable Output<String> timeCreated;

    /**
     * @return The time when the Packaging Configuration was created. An RFC3339 formatted datetime string.
     * 
     */
    public Optional<Output<String>> timeCreated() {
        return Optional.ofNullable(this.timeCreated);
    }

    /**
     * The time when the Packaging Configuration was updated. An RFC3339 formatted datetime string.
     * 
     */
    @Import(name="timeUpdated")
    private @Nullable Output<String> timeUpdated;

    /**
     * @return The time when the Packaging Configuration was updated. An RFC3339 formatted datetime string.
     * 
     */
    public Optional<Output<String>> timeUpdated() {
        return Optional.ofNullable(this.timeUpdated);
    }

    private StreamPackagingConfigState() {}

    private StreamPackagingConfigState(StreamPackagingConfigState $) {
        this.compartmentId = $.compartmentId;
        this.definedTags = $.definedTags;
        this.displayName = $.displayName;
        this.distributionChannelId = $.distributionChannelId;
        this.encryption = $.encryption;
        this.freeformTags = $.freeformTags;
        this.isLockOverride = $.isLockOverride;
        this.locks = $.locks;
        this.segmentTimeInSeconds = $.segmentTimeInSeconds;
        this.state = $.state;
        this.streamPackagingFormat = $.streamPackagingFormat;
        this.systemTags = $.systemTags;
        this.timeCreated = $.timeCreated;
        this.timeUpdated = $.timeUpdated;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(StreamPackagingConfigState defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private StreamPackagingConfigState $;

        public Builder() {
            $ = new StreamPackagingConfigState();
        }

        public Builder(StreamPackagingConfigState defaults) {
            $ = new StreamPackagingConfigState(Objects.requireNonNull(defaults));
        }

        /**
         * @param compartmentId The compartment ID of the lock.
         * 
         * @return builder
         * 
         */
        public Builder compartmentId(@Nullable Output<String> compartmentId) {
            $.compartmentId = compartmentId;
            return this;
        }

        /**
         * @param compartmentId The compartment ID of the lock.
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
         * @param displayName (Updatable) The name of the stream Packaging Configuration. Avoid entering confidential information.
         * 
         * @return builder
         * 
         */
        public Builder displayName(@Nullable Output<String> displayName) {
            $.displayName = displayName;
            return this;
        }

        /**
         * @param displayName (Updatable) The name of the stream Packaging Configuration. Avoid entering confidential information.
         * 
         * @return builder
         * 
         */
        public Builder displayName(String displayName) {
            return displayName(Output.of(displayName));
        }

        /**
         * @param distributionChannelId Unique identifier of the Distribution Channel that this stream packaging configuration belongs to.
         * 
         * @return builder
         * 
         */
        public Builder distributionChannelId(@Nullable Output<String> distributionChannelId) {
            $.distributionChannelId = distributionChannelId;
            return this;
        }

        /**
         * @param distributionChannelId Unique identifier of the Distribution Channel that this stream packaging configuration belongs to.
         * 
         * @return builder
         * 
         */
        public Builder distributionChannelId(String distributionChannelId) {
            return distributionChannelId(Output.of(distributionChannelId));
        }

        /**
         * @param encryption The encryption used by the stream packaging configuration.
         * 
         * @return builder
         * 
         */
        public Builder encryption(@Nullable Output<StreamPackagingConfigEncryptionArgs> encryption) {
            $.encryption = encryption;
            return this;
        }

        /**
         * @param encryption The encryption used by the stream packaging configuration.
         * 
         * @return builder
         * 
         */
        public Builder encryption(StreamPackagingConfigEncryptionArgs encryption) {
            return encryption(Output.of(encryption));
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

        public Builder isLockOverride(@Nullable Output<Boolean> isLockOverride) {
            $.isLockOverride = isLockOverride;
            return this;
        }

        public Builder isLockOverride(Boolean isLockOverride) {
            return isLockOverride(Output.of(isLockOverride));
        }

        /**
         * @param locks Locks associated with this resource.
         * 
         * @return builder
         * 
         */
        public Builder locks(@Nullable Output<List<StreamPackagingConfigLockArgs>> locks) {
            $.locks = locks;
            return this;
        }

        /**
         * @param locks Locks associated with this resource.
         * 
         * @return builder
         * 
         */
        public Builder locks(List<StreamPackagingConfigLockArgs> locks) {
            return locks(Output.of(locks));
        }

        /**
         * @param locks Locks associated with this resource.
         * 
         * @return builder
         * 
         */
        public Builder locks(StreamPackagingConfigLockArgs... locks) {
            return locks(List.of(locks));
        }

        /**
         * @param segmentTimeInSeconds The duration in seconds for each fragment.
         * 
         * @return builder
         * 
         */
        public Builder segmentTimeInSeconds(@Nullable Output<Integer> segmentTimeInSeconds) {
            $.segmentTimeInSeconds = segmentTimeInSeconds;
            return this;
        }

        /**
         * @param segmentTimeInSeconds The duration in seconds for each fragment.
         * 
         * @return builder
         * 
         */
        public Builder segmentTimeInSeconds(Integer segmentTimeInSeconds) {
            return segmentTimeInSeconds(Output.of(segmentTimeInSeconds));
        }

        /**
         * @param state The current state of the Packaging Configuration.
         * 
         * @return builder
         * 
         */
        public Builder state(@Nullable Output<String> state) {
            $.state = state;
            return this;
        }

        /**
         * @param state The current state of the Packaging Configuration.
         * 
         * @return builder
         * 
         */
        public Builder state(String state) {
            return state(Output.of(state));
        }

        /**
         * @param streamPackagingFormat The output format for the package.
         * 
         * ** IMPORTANT **
         * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
         * 
         * @return builder
         * 
         */
        public Builder streamPackagingFormat(@Nullable Output<String> streamPackagingFormat) {
            $.streamPackagingFormat = streamPackagingFormat;
            return this;
        }

        /**
         * @param streamPackagingFormat The output format for the package.
         * 
         * ** IMPORTANT **
         * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
         * 
         * @return builder
         * 
         */
        public Builder streamPackagingFormat(String streamPackagingFormat) {
            return streamPackagingFormat(Output.of(streamPackagingFormat));
        }

        /**
         * @param systemTags Usage of system tag keys. These predefined keys are scoped to namespaces. Example: `{&#34;orcl-cloud.free-tier-retained&#34;: &#34;true&#34;}`
         * 
         * @return builder
         * 
         */
        public Builder systemTags(@Nullable Output<Map<String,String>> systemTags) {
            $.systemTags = systemTags;
            return this;
        }

        /**
         * @param systemTags Usage of system tag keys. These predefined keys are scoped to namespaces. Example: `{&#34;orcl-cloud.free-tier-retained&#34;: &#34;true&#34;}`
         * 
         * @return builder
         * 
         */
        public Builder systemTags(Map<String,String> systemTags) {
            return systemTags(Output.of(systemTags));
        }

        /**
         * @param timeCreated The time when the Packaging Configuration was created. An RFC3339 formatted datetime string.
         * 
         * @return builder
         * 
         */
        public Builder timeCreated(@Nullable Output<String> timeCreated) {
            $.timeCreated = timeCreated;
            return this;
        }

        /**
         * @param timeCreated The time when the Packaging Configuration was created. An RFC3339 formatted datetime string.
         * 
         * @return builder
         * 
         */
        public Builder timeCreated(String timeCreated) {
            return timeCreated(Output.of(timeCreated));
        }

        /**
         * @param timeUpdated The time when the Packaging Configuration was updated. An RFC3339 formatted datetime string.
         * 
         * @return builder
         * 
         */
        public Builder timeUpdated(@Nullable Output<String> timeUpdated) {
            $.timeUpdated = timeUpdated;
            return this;
        }

        /**
         * @param timeUpdated The time when the Packaging Configuration was updated. An RFC3339 formatted datetime string.
         * 
         * @return builder
         * 
         */
        public Builder timeUpdated(String timeUpdated) {
            return timeUpdated(Output.of(timeUpdated));
        }

        public StreamPackagingConfigState build() {
            return $;
        }
    }

}
