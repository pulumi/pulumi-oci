// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Core.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.oci.Core.outputs.GetInstanceConfigurationsInstanceConfigurationInstanceDetailBlockVolumeAttachDetail;
import com.pulumi.oci.Core.outputs.GetInstanceConfigurationsInstanceConfigurationInstanceDetailBlockVolumeCreateDetail;
import java.lang.String;
import java.util.List;
import java.util.Objects;

@CustomType
public final class GetInstanceConfigurationsInstanceConfigurationInstanceDetailBlockVolume {
    /**
     * @return Volume attachmentDetails. Please see [AttachVolumeDetails](https://docs.cloud.oracle.com/iaas/api/#/en/iaas/latest/AttachVolumeDetails/)
     * 
     */
    private final List<GetInstanceConfigurationsInstanceConfigurationInstanceDetailBlockVolumeAttachDetail> attachDetails;
    /**
     * @return Creates a new block volume. Please see [CreateVolumeDetails](https://docs.cloud.oracle.com/iaas/api/#/en/iaas/latest/CreateVolumeDetails/)
     * 
     */
    private final List<GetInstanceConfigurationsInstanceConfigurationInstanceDetailBlockVolumeCreateDetail> createDetails;
    /**
     * @return The OCID of the volume.
     * 
     */
    private final String volumeId;

    @CustomType.Constructor
    private GetInstanceConfigurationsInstanceConfigurationInstanceDetailBlockVolume(
        @CustomType.Parameter("attachDetails") List<GetInstanceConfigurationsInstanceConfigurationInstanceDetailBlockVolumeAttachDetail> attachDetails,
        @CustomType.Parameter("createDetails") List<GetInstanceConfigurationsInstanceConfigurationInstanceDetailBlockVolumeCreateDetail> createDetails,
        @CustomType.Parameter("volumeId") String volumeId) {
        this.attachDetails = attachDetails;
        this.createDetails = createDetails;
        this.volumeId = volumeId;
    }

    /**
     * @return Volume attachmentDetails. Please see [AttachVolumeDetails](https://docs.cloud.oracle.com/iaas/api/#/en/iaas/latest/AttachVolumeDetails/)
     * 
     */
    public List<GetInstanceConfigurationsInstanceConfigurationInstanceDetailBlockVolumeAttachDetail> attachDetails() {
        return this.attachDetails;
    }
    /**
     * @return Creates a new block volume. Please see [CreateVolumeDetails](https://docs.cloud.oracle.com/iaas/api/#/en/iaas/latest/CreateVolumeDetails/)
     * 
     */
    public List<GetInstanceConfigurationsInstanceConfigurationInstanceDetailBlockVolumeCreateDetail> createDetails() {
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

    public static Builder builder(GetInstanceConfigurationsInstanceConfigurationInstanceDetailBlockVolume defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private List<GetInstanceConfigurationsInstanceConfigurationInstanceDetailBlockVolumeAttachDetail> attachDetails;
        private List<GetInstanceConfigurationsInstanceConfigurationInstanceDetailBlockVolumeCreateDetail> createDetails;
        private String volumeId;

        public Builder() {
    	      // Empty
        }

        public Builder(GetInstanceConfigurationsInstanceConfigurationInstanceDetailBlockVolume defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.attachDetails = defaults.attachDetails;
    	      this.createDetails = defaults.createDetails;
    	      this.volumeId = defaults.volumeId;
        }

        public Builder attachDetails(List<GetInstanceConfigurationsInstanceConfigurationInstanceDetailBlockVolumeAttachDetail> attachDetails) {
            this.attachDetails = Objects.requireNonNull(attachDetails);
            return this;
        }
        public Builder attachDetails(GetInstanceConfigurationsInstanceConfigurationInstanceDetailBlockVolumeAttachDetail... attachDetails) {
            return attachDetails(List.of(attachDetails));
        }
        public Builder createDetails(List<GetInstanceConfigurationsInstanceConfigurationInstanceDetailBlockVolumeCreateDetail> createDetails) {
            this.createDetails = Objects.requireNonNull(createDetails);
            return this;
        }
        public Builder createDetails(GetInstanceConfigurationsInstanceConfigurationInstanceDetailBlockVolumeCreateDetail... createDetails) {
            return createDetails(List.of(createDetails));
        }
        public Builder volumeId(String volumeId) {
            this.volumeId = Objects.requireNonNull(volumeId);
            return this;
        }        public GetInstanceConfigurationsInstanceConfigurationInstanceDetailBlockVolume build() {
            return new GetInstanceConfigurationsInstanceConfigurationInstanceDetailBlockVolume(attachDetails, createDetails, volumeId);
        }
    }
}
