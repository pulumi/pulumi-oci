// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Core.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import java.lang.Boolean;
import java.lang.String;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class InstanceConfigurationInstanceDetailsOptionBlockVolumeAttachDetailsArgs extends com.pulumi.resources.ResourceArgs {

    public static final InstanceConfigurationInstanceDetailsOptionBlockVolumeAttachDetailsArgs Empty = new InstanceConfigurationInstanceDetailsOptionBlockVolumeAttachDetailsArgs();

    /**
     * The device name.
     * 
     */
    @Import(name="device")
    private @Nullable Output<String> device;

    /**
     * @return The device name.
     * 
     */
    public Optional<Output<String>> device() {
        return Optional.ofNullable(this.device);
    }

    /**
     * A user-friendly name. Does not have to be unique, and it&#39;s changeable. Avoid entering confidential information.
     * 
     */
    @Import(name="displayName")
    private @Nullable Output<String> displayName;

    /**
     * @return A user-friendly name. Does not have to be unique, and it&#39;s changeable. Avoid entering confidential information.
     * 
     */
    public Optional<Output<String>> displayName() {
        return Optional.ofNullable(this.displayName);
    }

    /**
     * Deprecated. Instead use `isPvEncryptionInTransitEnabled` in [InstanceConfigurationLaunchInstanceDetails](https://docs.cloud.oracle.com/iaas/api/#/en/iaas/latest/datatypes/InstanceConfigurationLaunchInstanceDetails).
     * 
     */
    @Import(name="isPvEncryptionInTransitEnabled")
    private @Nullable Output<Boolean> isPvEncryptionInTransitEnabled;

    /**
     * @return Deprecated. Instead use `isPvEncryptionInTransitEnabled` in [InstanceConfigurationLaunchInstanceDetails](https://docs.cloud.oracle.com/iaas/api/#/en/iaas/latest/datatypes/InstanceConfigurationLaunchInstanceDetails).
     * 
     */
    public Optional<Output<Boolean>> isPvEncryptionInTransitEnabled() {
        return Optional.ofNullable(this.isPvEncryptionInTransitEnabled);
    }

    /**
     * Whether the attachment should be created in read-only mode.
     * 
     */
    @Import(name="isReadOnly")
    private @Nullable Output<Boolean> isReadOnly;

    /**
     * @return Whether the attachment should be created in read-only mode.
     * 
     */
    public Optional<Output<Boolean>> isReadOnly() {
        return Optional.ofNullable(this.isReadOnly);
    }

    /**
     * Whether the attachment should be created in shareable mode. If an attachment is created in shareable mode, then other instances can attach the same volume, provided that they also create their attachments in shareable mode. Only certain volume types can be attached in shareable mode. Defaults to false if not specified.
     * 
     */
    @Import(name="isShareable")
    private @Nullable Output<Boolean> isShareable;

    /**
     * @return Whether the attachment should be created in shareable mode. If an attachment is created in shareable mode, then other instances can attach the same volume, provided that they also create their attachments in shareable mode. Only certain volume types can be attached in shareable mode. Defaults to false if not specified.
     * 
     */
    public Optional<Output<Boolean>> isShareable() {
        return Optional.ofNullable(this.isShareable);
    }

    /**
     * The type of action to run when the instance is interrupted for eviction.
     * 
     */
    @Import(name="type", required=true)
    private Output<String> type;

    /**
     * @return The type of action to run when the instance is interrupted for eviction.
     * 
     */
    public Output<String> type() {
        return this.type;
    }

    /**
     * Whether to use CHAP authentication for the volume attachment. Defaults to false.
     * 
     */
    @Import(name="useChap")
    private @Nullable Output<Boolean> useChap;

    /**
     * @return Whether to use CHAP authentication for the volume attachment. Defaults to false.
     * 
     */
    public Optional<Output<Boolean>> useChap() {
        return Optional.ofNullable(this.useChap);
    }

    private InstanceConfigurationInstanceDetailsOptionBlockVolumeAttachDetailsArgs() {}

    private InstanceConfigurationInstanceDetailsOptionBlockVolumeAttachDetailsArgs(InstanceConfigurationInstanceDetailsOptionBlockVolumeAttachDetailsArgs $) {
        this.device = $.device;
        this.displayName = $.displayName;
        this.isPvEncryptionInTransitEnabled = $.isPvEncryptionInTransitEnabled;
        this.isReadOnly = $.isReadOnly;
        this.isShareable = $.isShareable;
        this.type = $.type;
        this.useChap = $.useChap;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(InstanceConfigurationInstanceDetailsOptionBlockVolumeAttachDetailsArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private InstanceConfigurationInstanceDetailsOptionBlockVolumeAttachDetailsArgs $;

        public Builder() {
            $ = new InstanceConfigurationInstanceDetailsOptionBlockVolumeAttachDetailsArgs();
        }

        public Builder(InstanceConfigurationInstanceDetailsOptionBlockVolumeAttachDetailsArgs defaults) {
            $ = new InstanceConfigurationInstanceDetailsOptionBlockVolumeAttachDetailsArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param device The device name.
         * 
         * @return builder
         * 
         */
        public Builder device(@Nullable Output<String> device) {
            $.device = device;
            return this;
        }

        /**
         * @param device The device name.
         * 
         * @return builder
         * 
         */
        public Builder device(String device) {
            return device(Output.of(device));
        }

        /**
         * @param displayName A user-friendly name. Does not have to be unique, and it&#39;s changeable. Avoid entering confidential information.
         * 
         * @return builder
         * 
         */
        public Builder displayName(@Nullable Output<String> displayName) {
            $.displayName = displayName;
            return this;
        }

        /**
         * @param displayName A user-friendly name. Does not have to be unique, and it&#39;s changeable. Avoid entering confidential information.
         * 
         * @return builder
         * 
         */
        public Builder displayName(String displayName) {
            return displayName(Output.of(displayName));
        }

        /**
         * @param isPvEncryptionInTransitEnabled Deprecated. Instead use `isPvEncryptionInTransitEnabled` in [InstanceConfigurationLaunchInstanceDetails](https://docs.cloud.oracle.com/iaas/api/#/en/iaas/latest/datatypes/InstanceConfigurationLaunchInstanceDetails).
         * 
         * @return builder
         * 
         */
        public Builder isPvEncryptionInTransitEnabled(@Nullable Output<Boolean> isPvEncryptionInTransitEnabled) {
            $.isPvEncryptionInTransitEnabled = isPvEncryptionInTransitEnabled;
            return this;
        }

        /**
         * @param isPvEncryptionInTransitEnabled Deprecated. Instead use `isPvEncryptionInTransitEnabled` in [InstanceConfigurationLaunchInstanceDetails](https://docs.cloud.oracle.com/iaas/api/#/en/iaas/latest/datatypes/InstanceConfigurationLaunchInstanceDetails).
         * 
         * @return builder
         * 
         */
        public Builder isPvEncryptionInTransitEnabled(Boolean isPvEncryptionInTransitEnabled) {
            return isPvEncryptionInTransitEnabled(Output.of(isPvEncryptionInTransitEnabled));
        }

        /**
         * @param isReadOnly Whether the attachment should be created in read-only mode.
         * 
         * @return builder
         * 
         */
        public Builder isReadOnly(@Nullable Output<Boolean> isReadOnly) {
            $.isReadOnly = isReadOnly;
            return this;
        }

        /**
         * @param isReadOnly Whether the attachment should be created in read-only mode.
         * 
         * @return builder
         * 
         */
        public Builder isReadOnly(Boolean isReadOnly) {
            return isReadOnly(Output.of(isReadOnly));
        }

        /**
         * @param isShareable Whether the attachment should be created in shareable mode. If an attachment is created in shareable mode, then other instances can attach the same volume, provided that they also create their attachments in shareable mode. Only certain volume types can be attached in shareable mode. Defaults to false if not specified.
         * 
         * @return builder
         * 
         */
        public Builder isShareable(@Nullable Output<Boolean> isShareable) {
            $.isShareable = isShareable;
            return this;
        }

        /**
         * @param isShareable Whether the attachment should be created in shareable mode. If an attachment is created in shareable mode, then other instances can attach the same volume, provided that they also create their attachments in shareable mode. Only certain volume types can be attached in shareable mode. Defaults to false if not specified.
         * 
         * @return builder
         * 
         */
        public Builder isShareable(Boolean isShareable) {
            return isShareable(Output.of(isShareable));
        }

        /**
         * @param type The type of action to run when the instance is interrupted for eviction.
         * 
         * @return builder
         * 
         */
        public Builder type(Output<String> type) {
            $.type = type;
            return this;
        }

        /**
         * @param type The type of action to run when the instance is interrupted for eviction.
         * 
         * @return builder
         * 
         */
        public Builder type(String type) {
            return type(Output.of(type));
        }

        /**
         * @param useChap Whether to use CHAP authentication for the volume attachment. Defaults to false.
         * 
         * @return builder
         * 
         */
        public Builder useChap(@Nullable Output<Boolean> useChap) {
            $.useChap = useChap;
            return this;
        }

        /**
         * @param useChap Whether to use CHAP authentication for the volume attachment. Defaults to false.
         * 
         * @return builder
         * 
         */
        public Builder useChap(Boolean useChap) {
            return useChap(Output.of(useChap));
        }

        public InstanceConfigurationInstanceDetailsOptionBlockVolumeAttachDetailsArgs build() {
            $.type = Objects.requireNonNull($.type, "expected parameter 'type' to be non-null");
            return $;
        }
    }

}