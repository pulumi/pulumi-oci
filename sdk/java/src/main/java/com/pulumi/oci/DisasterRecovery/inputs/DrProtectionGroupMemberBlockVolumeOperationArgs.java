// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DisasterRecovery.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import com.pulumi.oci.DisasterRecovery.inputs.DrProtectionGroupMemberBlockVolumeOperationAttachmentDetailsArgs;
import com.pulumi.oci.DisasterRecovery.inputs.DrProtectionGroupMemberBlockVolumeOperationMountDetailsArgs;
import java.lang.String;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class DrProtectionGroupMemberBlockVolumeOperationArgs extends com.pulumi.resources.ResourceArgs {

    public static final DrProtectionGroupMemberBlockVolumeOperationArgs Empty = new DrProtectionGroupMemberBlockVolumeOperationArgs();

    /**
     * (Updatable) The details for creating a block volume attachment.
     * 
     */
    @Import(name="attachmentDetails")
    private @Nullable Output<DrProtectionGroupMemberBlockVolumeOperationAttachmentDetailsArgs> attachmentDetails;

    /**
     * @return (Updatable) The details for creating a block volume attachment.
     * 
     */
    public Optional<Output<DrProtectionGroupMemberBlockVolumeOperationAttachmentDetailsArgs>> attachmentDetails() {
        return Optional.ofNullable(this.attachmentDetails);
    }

    /**
     * (Updatable) The OCID of the block volume.  Example: `ocid1.volume.oc1..uniqueID`
     * 
     */
    @Import(name="blockVolumeId")
    private @Nullable Output<String> blockVolumeId;

    /**
     * @return (Updatable) The OCID of the block volume.  Example: `ocid1.volume.oc1..uniqueID`
     * 
     */
    public Optional<Output<String>> blockVolumeId() {
        return Optional.ofNullable(this.blockVolumeId);
    }

    /**
     * (Updatable) The details for creating a file system mount.
     * 
     */
    @Import(name="mountDetails")
    private @Nullable Output<DrProtectionGroupMemberBlockVolumeOperationMountDetailsArgs> mountDetails;

    /**
     * @return (Updatable) The details for creating a file system mount.
     * 
     */
    public Optional<Output<DrProtectionGroupMemberBlockVolumeOperationMountDetailsArgs>> mountDetails() {
        return Optional.ofNullable(this.mountDetails);
    }

    private DrProtectionGroupMemberBlockVolumeOperationArgs() {}

    private DrProtectionGroupMemberBlockVolumeOperationArgs(DrProtectionGroupMemberBlockVolumeOperationArgs $) {
        this.attachmentDetails = $.attachmentDetails;
        this.blockVolumeId = $.blockVolumeId;
        this.mountDetails = $.mountDetails;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(DrProtectionGroupMemberBlockVolumeOperationArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private DrProtectionGroupMemberBlockVolumeOperationArgs $;

        public Builder() {
            $ = new DrProtectionGroupMemberBlockVolumeOperationArgs();
        }

        public Builder(DrProtectionGroupMemberBlockVolumeOperationArgs defaults) {
            $ = new DrProtectionGroupMemberBlockVolumeOperationArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param attachmentDetails (Updatable) The details for creating a block volume attachment.
         * 
         * @return builder
         * 
         */
        public Builder attachmentDetails(@Nullable Output<DrProtectionGroupMemberBlockVolumeOperationAttachmentDetailsArgs> attachmentDetails) {
            $.attachmentDetails = attachmentDetails;
            return this;
        }

        /**
         * @param attachmentDetails (Updatable) The details for creating a block volume attachment.
         * 
         * @return builder
         * 
         */
        public Builder attachmentDetails(DrProtectionGroupMemberBlockVolumeOperationAttachmentDetailsArgs attachmentDetails) {
            return attachmentDetails(Output.of(attachmentDetails));
        }

        /**
         * @param blockVolumeId (Updatable) The OCID of the block volume.  Example: `ocid1.volume.oc1..uniqueID`
         * 
         * @return builder
         * 
         */
        public Builder blockVolumeId(@Nullable Output<String> blockVolumeId) {
            $.blockVolumeId = blockVolumeId;
            return this;
        }

        /**
         * @param blockVolumeId (Updatable) The OCID of the block volume.  Example: `ocid1.volume.oc1..uniqueID`
         * 
         * @return builder
         * 
         */
        public Builder blockVolumeId(String blockVolumeId) {
            return blockVolumeId(Output.of(blockVolumeId));
        }

        /**
         * @param mountDetails (Updatable) The details for creating a file system mount.
         * 
         * @return builder
         * 
         */
        public Builder mountDetails(@Nullable Output<DrProtectionGroupMemberBlockVolumeOperationMountDetailsArgs> mountDetails) {
            $.mountDetails = mountDetails;
            return this;
        }

        /**
         * @param mountDetails (Updatable) The details for creating a file system mount.
         * 
         * @return builder
         * 
         */
        public Builder mountDetails(DrProtectionGroupMemberBlockVolumeOperationMountDetailsArgs mountDetails) {
            return mountDetails(Output.of(mountDetails));
        }

        public DrProtectionGroupMemberBlockVolumeOperationArgs build() {
            return $;
        }
    }

}