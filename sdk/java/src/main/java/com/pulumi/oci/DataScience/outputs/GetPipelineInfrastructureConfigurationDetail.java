// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DataScience.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.oci.DataScience.outputs.GetPipelineInfrastructureConfigurationDetailShapeConfigDetail;
import java.lang.Integer;
import java.lang.String;
import java.util.List;
import java.util.Objects;

@CustomType
public final class GetPipelineInfrastructureConfigurationDetail {
    /**
     * @return The size of the block storage volume to attach to the instance.
     * 
     */
    private Integer blockStorageSizeInGbs;
    /**
     * @return Details for the pipeline step run shape configuration. Specify only when a flex shape is selected.
     * 
     */
    private List<GetPipelineInfrastructureConfigurationDetailShapeConfigDetail> shapeConfigDetails;
    /**
     * @return The shape used to launch the instance for all step runs in the pipeline.
     * 
     */
    private String shapeName;

    private GetPipelineInfrastructureConfigurationDetail() {}
    /**
     * @return The size of the block storage volume to attach to the instance.
     * 
     */
    public Integer blockStorageSizeInGbs() {
        return this.blockStorageSizeInGbs;
    }
    /**
     * @return Details for the pipeline step run shape configuration. Specify only when a flex shape is selected.
     * 
     */
    public List<GetPipelineInfrastructureConfigurationDetailShapeConfigDetail> shapeConfigDetails() {
        return this.shapeConfigDetails;
    }
    /**
     * @return The shape used to launch the instance for all step runs in the pipeline.
     * 
     */
    public String shapeName() {
        return this.shapeName;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetPipelineInfrastructureConfigurationDetail defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private Integer blockStorageSizeInGbs;
        private List<GetPipelineInfrastructureConfigurationDetailShapeConfigDetail> shapeConfigDetails;
        private String shapeName;
        public Builder() {}
        public Builder(GetPipelineInfrastructureConfigurationDetail defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.blockStorageSizeInGbs = defaults.blockStorageSizeInGbs;
    	      this.shapeConfigDetails = defaults.shapeConfigDetails;
    	      this.shapeName = defaults.shapeName;
        }

        @CustomType.Setter
        public Builder blockStorageSizeInGbs(Integer blockStorageSizeInGbs) {
            this.blockStorageSizeInGbs = Objects.requireNonNull(blockStorageSizeInGbs);
            return this;
        }
        @CustomType.Setter
        public Builder shapeConfigDetails(List<GetPipelineInfrastructureConfigurationDetailShapeConfigDetail> shapeConfigDetails) {
            this.shapeConfigDetails = Objects.requireNonNull(shapeConfigDetails);
            return this;
        }
        public Builder shapeConfigDetails(GetPipelineInfrastructureConfigurationDetailShapeConfigDetail... shapeConfigDetails) {
            return shapeConfigDetails(List.of(shapeConfigDetails));
        }
        @CustomType.Setter
        public Builder shapeName(String shapeName) {
            this.shapeName = Objects.requireNonNull(shapeName);
            return this;
        }
        public GetPipelineInfrastructureConfigurationDetail build() {
            final var o = new GetPipelineInfrastructureConfigurationDetail();
            o.blockStorageSizeInGbs = blockStorageSizeInGbs;
            o.shapeConfigDetails = shapeConfigDetails;
            o.shapeName = shapeName;
            return o;
        }
    }
}