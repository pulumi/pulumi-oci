// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DisasterRecovery.outputs;

import com.pulumi.core.annotations.CustomType;
import java.lang.String;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;

@CustomType
public final class DrProtectionGroupMemberBlockVolumeAttachAndMountOperationsAttachment {
    /**
     * @return (Updatable) The OCID of the block volume.  Example: `ocid1.volume.oc1..uniqueID`
     * 
     */
    private @Nullable String blockVolumeId;
    /**
     * @return (Updatable) The OCID of the reference compute instance needed to obtain the volume attachment details. This reference compute instance belongs to the peer DR protection group.  Example: `ocid1.instance.oc1..uniqueID`
     * 
     */
    private @Nullable String volumeAttachmentReferenceInstanceId;

    private DrProtectionGroupMemberBlockVolumeAttachAndMountOperationsAttachment() {}
    /**
     * @return (Updatable) The OCID of the block volume.  Example: `ocid1.volume.oc1..uniqueID`
     * 
     */
    public Optional<String> blockVolumeId() {
        return Optional.ofNullable(this.blockVolumeId);
    }
    /**
     * @return (Updatable) The OCID of the reference compute instance needed to obtain the volume attachment details. This reference compute instance belongs to the peer DR protection group.  Example: `ocid1.instance.oc1..uniqueID`
     * 
     */
    public Optional<String> volumeAttachmentReferenceInstanceId() {
        return Optional.ofNullable(this.volumeAttachmentReferenceInstanceId);
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(DrProtectionGroupMemberBlockVolumeAttachAndMountOperationsAttachment defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private @Nullable String blockVolumeId;
        private @Nullable String volumeAttachmentReferenceInstanceId;
        public Builder() {}
        public Builder(DrProtectionGroupMemberBlockVolumeAttachAndMountOperationsAttachment defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.blockVolumeId = defaults.blockVolumeId;
    	      this.volumeAttachmentReferenceInstanceId = defaults.volumeAttachmentReferenceInstanceId;
        }

        @CustomType.Setter
        public Builder blockVolumeId(@Nullable String blockVolumeId) {

            this.blockVolumeId = blockVolumeId;
            return this;
        }
        @CustomType.Setter
        public Builder volumeAttachmentReferenceInstanceId(@Nullable String volumeAttachmentReferenceInstanceId) {

            this.volumeAttachmentReferenceInstanceId = volumeAttachmentReferenceInstanceId;
            return this;
        }
        public DrProtectionGroupMemberBlockVolumeAttachAndMountOperationsAttachment build() {
            final var _resultValue = new DrProtectionGroupMemberBlockVolumeAttachAndMountOperationsAttachment();
            _resultValue.blockVolumeId = blockVolumeId;
            _resultValue.volumeAttachmentReferenceInstanceId = volumeAttachmentReferenceInstanceId;
            return _resultValue;
        }
    }
}
