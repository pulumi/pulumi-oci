// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Core.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.Core.outputs.GetInstanceConfigurationsInstanceConfigurationInstanceDetailBlockVolume;
import com.pulumi.oci.Core.outputs.GetInstanceConfigurationsInstanceConfigurationInstanceDetailLaunchDetail;
import com.pulumi.oci.Core.outputs.GetInstanceConfigurationsInstanceConfigurationInstanceDetailOption;
import com.pulumi.oci.Core.outputs.GetInstanceConfigurationsInstanceConfigurationInstanceDetailSecondaryVnic;
import java.lang.String;
import java.util.List;
import java.util.Objects;

@CustomType
public final class GetInstanceConfigurationsInstanceConfigurationInstanceDetail {
    /**
     * @return Block volume parameters.
     * 
     */
    private List<GetInstanceConfigurationsInstanceConfigurationInstanceDetailBlockVolume> blockVolumes;
    /**
     * @return The type of instance details. Supported instanceType is compute
     * 
     */
    private String instanceType;
    /**
     * @return Instance launch details for creating an instance from an instance configuration. Use the `sourceDetails` parameter to specify whether a boot volume or an image should be used to launch a new instance.
     * 
     */
    private List<GetInstanceConfigurationsInstanceConfigurationInstanceDetailLaunchDetail> launchDetails;
    /**
     * @return Multiple Compute Instance Configuration instance details.
     * 
     */
    private List<GetInstanceConfigurationsInstanceConfigurationInstanceDetailOption> options;
    /**
     * @return Secondary VNIC parameters.
     * 
     */
    private List<GetInstanceConfigurationsInstanceConfigurationInstanceDetailSecondaryVnic> secondaryVnics;

    private GetInstanceConfigurationsInstanceConfigurationInstanceDetail() {}
    /**
     * @return Block volume parameters.
     * 
     */
    public List<GetInstanceConfigurationsInstanceConfigurationInstanceDetailBlockVolume> blockVolumes() {
        return this.blockVolumes;
    }
    /**
     * @return The type of instance details. Supported instanceType is compute
     * 
     */
    public String instanceType() {
        return this.instanceType;
    }
    /**
     * @return Instance launch details for creating an instance from an instance configuration. Use the `sourceDetails` parameter to specify whether a boot volume or an image should be used to launch a new instance.
     * 
     */
    public List<GetInstanceConfigurationsInstanceConfigurationInstanceDetailLaunchDetail> launchDetails() {
        return this.launchDetails;
    }
    /**
     * @return Multiple Compute Instance Configuration instance details.
     * 
     */
    public List<GetInstanceConfigurationsInstanceConfigurationInstanceDetailOption> options() {
        return this.options;
    }
    /**
     * @return Secondary VNIC parameters.
     * 
     */
    public List<GetInstanceConfigurationsInstanceConfigurationInstanceDetailSecondaryVnic> secondaryVnics() {
        return this.secondaryVnics;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetInstanceConfigurationsInstanceConfigurationInstanceDetail defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private List<GetInstanceConfigurationsInstanceConfigurationInstanceDetailBlockVolume> blockVolumes;
        private String instanceType;
        private List<GetInstanceConfigurationsInstanceConfigurationInstanceDetailLaunchDetail> launchDetails;
        private List<GetInstanceConfigurationsInstanceConfigurationInstanceDetailOption> options;
        private List<GetInstanceConfigurationsInstanceConfigurationInstanceDetailSecondaryVnic> secondaryVnics;
        public Builder() {}
        public Builder(GetInstanceConfigurationsInstanceConfigurationInstanceDetail defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.blockVolumes = defaults.blockVolumes;
    	      this.instanceType = defaults.instanceType;
    	      this.launchDetails = defaults.launchDetails;
    	      this.options = defaults.options;
    	      this.secondaryVnics = defaults.secondaryVnics;
        }

        @CustomType.Setter
        public Builder blockVolumes(List<GetInstanceConfigurationsInstanceConfigurationInstanceDetailBlockVolume> blockVolumes) {
            if (blockVolumes == null) {
              throw new MissingRequiredPropertyException("GetInstanceConfigurationsInstanceConfigurationInstanceDetail", "blockVolumes");
            }
            this.blockVolumes = blockVolumes;
            return this;
        }
        public Builder blockVolumes(GetInstanceConfigurationsInstanceConfigurationInstanceDetailBlockVolume... blockVolumes) {
            return blockVolumes(List.of(blockVolumes));
        }
        @CustomType.Setter
        public Builder instanceType(String instanceType) {
            if (instanceType == null) {
              throw new MissingRequiredPropertyException("GetInstanceConfigurationsInstanceConfigurationInstanceDetail", "instanceType");
            }
            this.instanceType = instanceType;
            return this;
        }
        @CustomType.Setter
        public Builder launchDetails(List<GetInstanceConfigurationsInstanceConfigurationInstanceDetailLaunchDetail> launchDetails) {
            if (launchDetails == null) {
              throw new MissingRequiredPropertyException("GetInstanceConfigurationsInstanceConfigurationInstanceDetail", "launchDetails");
            }
            this.launchDetails = launchDetails;
            return this;
        }
        public Builder launchDetails(GetInstanceConfigurationsInstanceConfigurationInstanceDetailLaunchDetail... launchDetails) {
            return launchDetails(List.of(launchDetails));
        }
        @CustomType.Setter
        public Builder options(List<GetInstanceConfigurationsInstanceConfigurationInstanceDetailOption> options) {
            if (options == null) {
              throw new MissingRequiredPropertyException("GetInstanceConfigurationsInstanceConfigurationInstanceDetail", "options");
            }
            this.options = options;
            return this;
        }
        public Builder options(GetInstanceConfigurationsInstanceConfigurationInstanceDetailOption... options) {
            return options(List.of(options));
        }
        @CustomType.Setter
        public Builder secondaryVnics(List<GetInstanceConfigurationsInstanceConfigurationInstanceDetailSecondaryVnic> secondaryVnics) {
            if (secondaryVnics == null) {
              throw new MissingRequiredPropertyException("GetInstanceConfigurationsInstanceConfigurationInstanceDetail", "secondaryVnics");
            }
            this.secondaryVnics = secondaryVnics;
            return this;
        }
        public Builder secondaryVnics(GetInstanceConfigurationsInstanceConfigurationInstanceDetailSecondaryVnic... secondaryVnics) {
            return secondaryVnics(List.of(secondaryVnics));
        }
        public GetInstanceConfigurationsInstanceConfigurationInstanceDetail build() {
            final var _resultValue = new GetInstanceConfigurationsInstanceConfigurationInstanceDetail();
            _resultValue.blockVolumes = blockVolumes;
            _resultValue.instanceType = instanceType;
            _resultValue.launchDetails = launchDetails;
            _resultValue.options = options;
            _resultValue.secondaryVnics = secondaryVnics;
            return _resultValue;
        }
    }
}
