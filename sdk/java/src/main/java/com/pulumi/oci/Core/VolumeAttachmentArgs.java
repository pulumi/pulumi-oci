// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Core;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.Boolean;
import java.lang.String;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class VolumeAttachmentArgs extends com.pulumi.resources.ResourceArgs {

    public static final VolumeAttachmentArgs Empty = new VolumeAttachmentArgs();

    /**
     * The type of volume. The only supported values are &#34;iscsi&#34; and &#34;paravirtualized&#34;.
     * 
     */
    @Import(name="attachmentType", required=true)
    private Output<String> attachmentType;

    /**
     * @return The type of volume. The only supported values are &#34;iscsi&#34; and &#34;paravirtualized&#34;.
     * 
     */
    public Output<String> attachmentType() {
        return this.attachmentType;
    }

    /**
     * The OCID of the compartment.
     * 
     * @deprecated
     * The &#39;compartment_id&#39; field has been deprecated and may be removed in a future version. Do not use this field.
     * 
     */
    @Deprecated /* The 'compartment_id' field has been deprecated and may be removed in a future version. Do not use this field. */
    @Import(name="compartmentId")
    private @Nullable Output<String> compartmentId;

    /**
     * @return The OCID of the compartment.
     * 
     * @deprecated
     * The &#39;compartment_id&#39; field has been deprecated and may be removed in a future version. Do not use this field.
     * 
     */
    @Deprecated /* The 'compartment_id' field has been deprecated and may be removed in a future version. Do not use this field. */
    public Optional<Output<String>> compartmentId() {
        return Optional.ofNullable(this.compartmentId);
    }

    /**
     * The device name. To retrieve a list of devices for a given instance, see [ListInstanceDevices](https://docs.cloud.oracle.com/iaas/api/#/en/iaas/latest/Device/ListInstanceDevices).
     * 
     */
    @Import(name="device")
    private @Nullable Output<String> device;

    /**
     * @return The device name. To retrieve a list of devices for a given instance, see [ListInstanceDevices](https://docs.cloud.oracle.com/iaas/api/#/en/iaas/latest/Device/ListInstanceDevices).
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
     * Refer the top-level definition of encryptionInTransitType. The default value is NONE.
     * 
     */
    @Import(name="encryptionInTransitType")
    private @Nullable Output<String> encryptionInTransitType;

    /**
     * @return Refer the top-level definition of encryptionInTransitType. The default value is NONE.
     * 
     */
    public Optional<Output<String>> encryptionInTransitType() {
        return Optional.ofNullable(this.encryptionInTransitType);
    }

    /**
     * The OCID of the instance.
     * 
     */
    @Import(name="instanceId", required=true)
    private Output<String> instanceId;

    /**
     * @return The OCID of the instance.
     * 
     */
    public Output<String> instanceId() {
        return this.instanceId;
    }

    /**
     * Whether to enable Oracle Cloud Agent to perform the iSCSI login and logout commands after the volume attach or detach operations for non multipath-enabled iSCSI attachments.
     * 
     */
    @Import(name="isAgentAutoIscsiLoginEnabled")
    private @Nullable Output<Boolean> isAgentAutoIscsiLoginEnabled;

    /**
     * @return Whether to enable Oracle Cloud Agent to perform the iSCSI login and logout commands after the volume attach or detach operations for non multipath-enabled iSCSI attachments.
     * 
     */
    public Optional<Output<Boolean>> isAgentAutoIscsiLoginEnabled() {
        return Optional.ofNullable(this.isAgentAutoIscsiLoginEnabled);
    }

    /**
     * Whether to enable in-transit encryption for the data volume&#39;s paravirtualized attachment. The default value is false.
     * 
     */
    @Import(name="isPvEncryptionInTransitEnabled")
    private @Nullable Output<Boolean> isPvEncryptionInTransitEnabled;

    /**
     * @return Whether to enable in-transit encryption for the data volume&#39;s paravirtualized attachment. The default value is false.
     * 
     */
    public Optional<Output<Boolean>> isPvEncryptionInTransitEnabled() {
        return Optional.ofNullable(this.isPvEncryptionInTransitEnabled);
    }

    /**
     * Whether the attachment was created in read-only mode.
     * 
     */
    @Import(name="isReadOnly")
    private @Nullable Output<Boolean> isReadOnly;

    /**
     * @return Whether the attachment was created in read-only mode.
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

    /**
     * The OCID of the volume.
     * 
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     * 
     */
    @Import(name="volumeId", required=true)
    private Output<String> volumeId;

    /**
     * @return The OCID of the volume.
     * 
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     * 
     */
    public Output<String> volumeId() {
        return this.volumeId;
    }

    private VolumeAttachmentArgs() {}

    private VolumeAttachmentArgs(VolumeAttachmentArgs $) {
        this.attachmentType = $.attachmentType;
        this.compartmentId = $.compartmentId;
        this.device = $.device;
        this.displayName = $.displayName;
        this.encryptionInTransitType = $.encryptionInTransitType;
        this.instanceId = $.instanceId;
        this.isAgentAutoIscsiLoginEnabled = $.isAgentAutoIscsiLoginEnabled;
        this.isPvEncryptionInTransitEnabled = $.isPvEncryptionInTransitEnabled;
        this.isReadOnly = $.isReadOnly;
        this.isShareable = $.isShareable;
        this.useChap = $.useChap;
        this.volumeId = $.volumeId;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(VolumeAttachmentArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private VolumeAttachmentArgs $;

        public Builder() {
            $ = new VolumeAttachmentArgs();
        }

        public Builder(VolumeAttachmentArgs defaults) {
            $ = new VolumeAttachmentArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param attachmentType The type of volume. The only supported values are &#34;iscsi&#34; and &#34;paravirtualized&#34;.
         * 
         * @return builder
         * 
         */
        public Builder attachmentType(Output<String> attachmentType) {
            $.attachmentType = attachmentType;
            return this;
        }

        /**
         * @param attachmentType The type of volume. The only supported values are &#34;iscsi&#34; and &#34;paravirtualized&#34;.
         * 
         * @return builder
         * 
         */
        public Builder attachmentType(String attachmentType) {
            return attachmentType(Output.of(attachmentType));
        }

        /**
         * @param compartmentId The OCID of the compartment.
         * 
         * @return builder
         * 
         * @deprecated
         * The &#39;compartment_id&#39; field has been deprecated and may be removed in a future version. Do not use this field.
         * 
         */
        @Deprecated /* The 'compartment_id' field has been deprecated and may be removed in a future version. Do not use this field. */
        public Builder compartmentId(@Nullable Output<String> compartmentId) {
            $.compartmentId = compartmentId;
            return this;
        }

        /**
         * @param compartmentId The OCID of the compartment.
         * 
         * @return builder
         * 
         * @deprecated
         * The &#39;compartment_id&#39; field has been deprecated and may be removed in a future version. Do not use this field.
         * 
         */
        @Deprecated /* The 'compartment_id' field has been deprecated and may be removed in a future version. Do not use this field. */
        public Builder compartmentId(String compartmentId) {
            return compartmentId(Output.of(compartmentId));
        }

        /**
         * @param device The device name. To retrieve a list of devices for a given instance, see [ListInstanceDevices](https://docs.cloud.oracle.com/iaas/api/#/en/iaas/latest/Device/ListInstanceDevices).
         * 
         * @return builder
         * 
         */
        public Builder device(@Nullable Output<String> device) {
            $.device = device;
            return this;
        }

        /**
         * @param device The device name. To retrieve a list of devices for a given instance, see [ListInstanceDevices](https://docs.cloud.oracle.com/iaas/api/#/en/iaas/latest/Device/ListInstanceDevices).
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
         * @param encryptionInTransitType Refer the top-level definition of encryptionInTransitType. The default value is NONE.
         * 
         * @return builder
         * 
         */
        public Builder encryptionInTransitType(@Nullable Output<String> encryptionInTransitType) {
            $.encryptionInTransitType = encryptionInTransitType;
            return this;
        }

        /**
         * @param encryptionInTransitType Refer the top-level definition of encryptionInTransitType. The default value is NONE.
         * 
         * @return builder
         * 
         */
        public Builder encryptionInTransitType(String encryptionInTransitType) {
            return encryptionInTransitType(Output.of(encryptionInTransitType));
        }

        /**
         * @param instanceId The OCID of the instance.
         * 
         * @return builder
         * 
         */
        public Builder instanceId(Output<String> instanceId) {
            $.instanceId = instanceId;
            return this;
        }

        /**
         * @param instanceId The OCID of the instance.
         * 
         * @return builder
         * 
         */
        public Builder instanceId(String instanceId) {
            return instanceId(Output.of(instanceId));
        }

        /**
         * @param isAgentAutoIscsiLoginEnabled Whether to enable Oracle Cloud Agent to perform the iSCSI login and logout commands after the volume attach or detach operations for non multipath-enabled iSCSI attachments.
         * 
         * @return builder
         * 
         */
        public Builder isAgentAutoIscsiLoginEnabled(@Nullable Output<Boolean> isAgentAutoIscsiLoginEnabled) {
            $.isAgentAutoIscsiLoginEnabled = isAgentAutoIscsiLoginEnabled;
            return this;
        }

        /**
         * @param isAgentAutoIscsiLoginEnabled Whether to enable Oracle Cloud Agent to perform the iSCSI login and logout commands after the volume attach or detach operations for non multipath-enabled iSCSI attachments.
         * 
         * @return builder
         * 
         */
        public Builder isAgentAutoIscsiLoginEnabled(Boolean isAgentAutoIscsiLoginEnabled) {
            return isAgentAutoIscsiLoginEnabled(Output.of(isAgentAutoIscsiLoginEnabled));
        }

        /**
         * @param isPvEncryptionInTransitEnabled Whether to enable in-transit encryption for the data volume&#39;s paravirtualized attachment. The default value is false.
         * 
         * @return builder
         * 
         */
        public Builder isPvEncryptionInTransitEnabled(@Nullable Output<Boolean> isPvEncryptionInTransitEnabled) {
            $.isPvEncryptionInTransitEnabled = isPvEncryptionInTransitEnabled;
            return this;
        }

        /**
         * @param isPvEncryptionInTransitEnabled Whether to enable in-transit encryption for the data volume&#39;s paravirtualized attachment. The default value is false.
         * 
         * @return builder
         * 
         */
        public Builder isPvEncryptionInTransitEnabled(Boolean isPvEncryptionInTransitEnabled) {
            return isPvEncryptionInTransitEnabled(Output.of(isPvEncryptionInTransitEnabled));
        }

        /**
         * @param isReadOnly Whether the attachment was created in read-only mode.
         * 
         * @return builder
         * 
         */
        public Builder isReadOnly(@Nullable Output<Boolean> isReadOnly) {
            $.isReadOnly = isReadOnly;
            return this;
        }

        /**
         * @param isReadOnly Whether the attachment was created in read-only mode.
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

        /**
         * @param volumeId The OCID of the volume.
         * 
         * ** IMPORTANT **
         * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
         * 
         * @return builder
         * 
         */
        public Builder volumeId(Output<String> volumeId) {
            $.volumeId = volumeId;
            return this;
        }

        /**
         * @param volumeId The OCID of the volume.
         * 
         * ** IMPORTANT **
         * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
         * 
         * @return builder
         * 
         */
        public Builder volumeId(String volumeId) {
            return volumeId(Output.of(volumeId));
        }

        public VolumeAttachmentArgs build() {
            if ($.attachmentType == null) {
                throw new MissingRequiredPropertyException("VolumeAttachmentArgs", "attachmentType");
            }
            if ($.instanceId == null) {
                throw new MissingRequiredPropertyException("VolumeAttachmentArgs", "instanceId");
            }
            if ($.volumeId == null) {
                throw new MissingRequiredPropertyException("VolumeAttachmentArgs", "volumeId");
            }
            return $;
        }
    }

}
