// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.BigDataService.outputs;

import com.pulumi.core.annotations.CustomType;
import java.lang.String;
import java.util.Objects;

@CustomType
public final class GetBdsInstanceNodeAttachedBlockVolume {
    /**
     * @return The OCID of the volume attachment.
     * 
     */
    private final String volumeAttachmentId;
    /**
     * @return The size of the volume in GBs.
     * 
     */
    private final String volumeSizeInGbs;

    @CustomType.Constructor
    private GetBdsInstanceNodeAttachedBlockVolume(
        @CustomType.Parameter("volumeAttachmentId") String volumeAttachmentId,
        @CustomType.Parameter("volumeSizeInGbs") String volumeSizeInGbs) {
        this.volumeAttachmentId = volumeAttachmentId;
        this.volumeSizeInGbs = volumeSizeInGbs;
    }

    /**
     * @return The OCID of the volume attachment.
     * 
     */
    public String volumeAttachmentId() {
        return this.volumeAttachmentId;
    }
    /**
     * @return The size of the volume in GBs.
     * 
     */
    public String volumeSizeInGbs() {
        return this.volumeSizeInGbs;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetBdsInstanceNodeAttachedBlockVolume defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private String volumeAttachmentId;
        private String volumeSizeInGbs;

        public Builder() {
    	      // Empty
        }

        public Builder(GetBdsInstanceNodeAttachedBlockVolume defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.volumeAttachmentId = defaults.volumeAttachmentId;
    	      this.volumeSizeInGbs = defaults.volumeSizeInGbs;
        }

        public Builder volumeAttachmentId(String volumeAttachmentId) {
            this.volumeAttachmentId = Objects.requireNonNull(volumeAttachmentId);
            return this;
        }
        public Builder volumeSizeInGbs(String volumeSizeInGbs) {
            this.volumeSizeInGbs = Objects.requireNonNull(volumeSizeInGbs);
            return this;
        }        public GetBdsInstanceNodeAttachedBlockVolume build() {
            return new GetBdsInstanceNodeAttachedBlockVolume(volumeAttachmentId, volumeSizeInGbs);
        }
    }
}
