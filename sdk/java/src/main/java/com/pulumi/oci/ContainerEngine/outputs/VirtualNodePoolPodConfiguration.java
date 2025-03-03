// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.ContainerEngine.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import javax.annotation.Nullable;

@CustomType
public final class VirtualNodePoolPodConfiguration {
    /**
     * @return (Updatable) List of network security group IDs applied to the Pod VNIC.
     * 
     */
    private @Nullable List<String> nsgIds;
    /**
     * @return (Updatable) Shape of the pods.
     * 
     */
    private String shape;
    /**
     * @return (Updatable) The regional subnet where pods&#39; VNIC will be placed.
     * 
     */
    private String subnetId;

    private VirtualNodePoolPodConfiguration() {}
    /**
     * @return (Updatable) List of network security group IDs applied to the Pod VNIC.
     * 
     */
    public List<String> nsgIds() {
        return this.nsgIds == null ? List.of() : this.nsgIds;
    }
    /**
     * @return (Updatable) Shape of the pods.
     * 
     */
    public String shape() {
        return this.shape;
    }
    /**
     * @return (Updatable) The regional subnet where pods&#39; VNIC will be placed.
     * 
     */
    public String subnetId() {
        return this.subnetId;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(VirtualNodePoolPodConfiguration defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private @Nullable List<String> nsgIds;
        private String shape;
        private String subnetId;
        public Builder() {}
        public Builder(VirtualNodePoolPodConfiguration defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.nsgIds = defaults.nsgIds;
    	      this.shape = defaults.shape;
    	      this.subnetId = defaults.subnetId;
        }

        @CustomType.Setter
        public Builder nsgIds(@Nullable List<String> nsgIds) {

            this.nsgIds = nsgIds;
            return this;
        }
        public Builder nsgIds(String... nsgIds) {
            return nsgIds(List.of(nsgIds));
        }
        @CustomType.Setter
        public Builder shape(String shape) {
            if (shape == null) {
              throw new MissingRequiredPropertyException("VirtualNodePoolPodConfiguration", "shape");
            }
            this.shape = shape;
            return this;
        }
        @CustomType.Setter
        public Builder subnetId(String subnetId) {
            if (subnetId == null) {
              throw new MissingRequiredPropertyException("VirtualNodePoolPodConfiguration", "subnetId");
            }
            this.subnetId = subnetId;
            return this;
        }
        public VirtualNodePoolPodConfiguration build() {
            final var _resultValue = new VirtualNodePoolPodConfiguration();
            _resultValue.nsgIds = nsgIds;
            _resultValue.shape = shape;
            _resultValue.subnetId = subnetId;
            return _resultValue;
        }
    }
}
