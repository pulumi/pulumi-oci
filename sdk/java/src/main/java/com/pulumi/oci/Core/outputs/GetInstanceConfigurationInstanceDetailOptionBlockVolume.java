// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Core.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.Core.outputs.GetInstanceConfigurationInstanceDetailOptionBlockVolumeAttachDetail;
import com.pulumi.oci.Core.outputs.GetInstanceConfigurationInstanceDetailOptionBlockVolumeCreateDetail;
import java.lang.String;
import java.util.List;
import java.util.Objects;

@CustomType
public final class GetInstanceConfigurationInstanceDetailOptionBlockVolume {
    /**
     * @return Volume attachmentDetails. Please see [AttachVolumeDetails](https://docs.cloud.oracle.com/iaas/api/#/en/iaas/latest/AttachVolumeDetails/)
     * 
     */
    private List<GetInstanceConfigurationInstanceDetailOptionBlockVolumeAttachDetail> attachDetails;
    /**
     * @return Creates a new block volume. Please see [CreateVolumeDetails](https://docs.cloud.oracle.com/iaas/api/#/en/iaas/latest/CreateVolumeDetails/)
     * 
     */
    private List<GetInstanceConfigurationInstanceDetailOptionBlockVolumeCreateDetail> createDetails;
    /**
     * @return The OCID of the volume.
     * 
     */
    private String volumeId;

    private GetInstanceConfigurationInstanceDetailOptionBlockVolume() {}
    /**
     * @return Volume attachmentDetails. Please see [AttachVolumeDetails](https://docs.cloud.oracle.com/iaas/api/#/en/iaas/latest/AttachVolumeDetails/)
     * 
     */
    public List<GetInstanceConfigurationInstanceDetailOptionBlockVolumeAttachDetail> attachDetails() {
        return this.attachDetails;
    }
    /**
     * @return Creates a new block volume. Please see [CreateVolumeDetails](https://docs.cloud.oracle.com/iaas/api/#/en/iaas/latest/CreateVolumeDetails/)
     * 
     */
    public List<GetInstanceConfigurationInstanceDetailOptionBlockVolumeCreateDetail> createDetails() {
        return this.createDetails;
    }
    /**
     * @return The OCID of the volume.
     * 
     */
    public String volumeId() {
        return this.volumeId;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetInstanceConfigurationInstanceDetailOptionBlockVolume defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private List<GetInstanceConfigurationInstanceDetailOptionBlockVolumeAttachDetail> attachDetails;
        private List<GetInstanceConfigurationInstanceDetailOptionBlockVolumeCreateDetail> createDetails;
        private String volumeId;
        public Builder() {}
        public Builder(GetInstanceConfigurationInstanceDetailOptionBlockVolume defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.attachDetails = defaults.attachDetails;
    	      this.createDetails = defaults.createDetails;
    	      this.volumeId = defaults.volumeId;
        }

        @CustomType.Setter
        public Builder attachDetails(List<GetInstanceConfigurationInstanceDetailOptionBlockVolumeAttachDetail> attachDetails) {
            if (attachDetails == null) {
              throw new MissingRequiredPropertyException("GetInstanceConfigurationInstanceDetailOptionBlockVolume", "attachDetails");
            }
            this.attachDetails = attachDetails;
            return this;
        }
        public Builder attachDetails(GetInstanceConfigurationInstanceDetailOptionBlockVolumeAttachDetail... attachDetails) {
            return attachDetails(List.of(attachDetails));
        }
        @CustomType.Setter
        public Builder createDetails(List<GetInstanceConfigurationInstanceDetailOptionBlockVolumeCreateDetail> createDetails) {
            if (createDetails == null) {
              throw new MissingRequiredPropertyException("GetInstanceConfigurationInstanceDetailOptionBlockVolume", "createDetails");
            }
            this.createDetails = createDetails;
            return this;
        }
        public Builder createDetails(GetInstanceConfigurationInstanceDetailOptionBlockVolumeCreateDetail... createDetails) {
            return createDetails(List.of(createDetails));
        }
        @CustomType.Setter
        public Builder volumeId(String volumeId) {
            if (volumeId == null) {
              throw new MissingRequiredPropertyException("GetInstanceConfigurationInstanceDetailOptionBlockVolume", "volumeId");
            }
            this.volumeId = volumeId;
            return this;
        }
        public GetInstanceConfigurationInstanceDetailOptionBlockVolume build() {
            final var _resultValue = new GetInstanceConfigurationInstanceDetailOptionBlockVolume();
            _resultValue.attachDetails = attachDetails;
            _resultValue.createDetails = createDetails;
            _resultValue.volumeId = volumeId;
            return _resultValue;
        }
    }
}
