// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.CloudBridge.outputs;

import com.pulumi.core.annotations.CustomType;
import java.lang.Integer;
import java.lang.String;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;

@CustomType
public final class AssetComputeNvdimm {
    /**
     * @return (Updatable) Controller key.
     * 
     */
    private @Nullable Integer controllerKey;
    /**
     * @return (Updatable) Provides a label and summary information for the device.
     * 
     */
    private @Nullable String label;
    /**
     * @return (Updatable) The unit number of the SCSI controller.
     * 
     */
    private @Nullable Integer unitNumber;

    private AssetComputeNvdimm() {}
    /**
     * @return (Updatable) Controller key.
     * 
     */
    public Optional<Integer> controllerKey() {
        return Optional.ofNullable(this.controllerKey);
    }
    /**
     * @return (Updatable) Provides a label and summary information for the device.
     * 
     */
    public Optional<String> label() {
        return Optional.ofNullable(this.label);
    }
    /**
     * @return (Updatable) The unit number of the SCSI controller.
     * 
     */
    public Optional<Integer> unitNumber() {
        return Optional.ofNullable(this.unitNumber);
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(AssetComputeNvdimm defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private @Nullable Integer controllerKey;
        private @Nullable String label;
        private @Nullable Integer unitNumber;
        public Builder() {}
        public Builder(AssetComputeNvdimm defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.controllerKey = defaults.controllerKey;
    	      this.label = defaults.label;
    	      this.unitNumber = defaults.unitNumber;
        }

        @CustomType.Setter
        public Builder controllerKey(@Nullable Integer controllerKey) {
            this.controllerKey = controllerKey;
            return this;
        }
        @CustomType.Setter
        public Builder label(@Nullable String label) {
            this.label = label;
            return this;
        }
        @CustomType.Setter
        public Builder unitNumber(@Nullable Integer unitNumber) {
            this.unitNumber = unitNumber;
            return this;
        }
        public AssetComputeNvdimm build() {
            final var o = new AssetComputeNvdimm();
            o.controllerKey = controllerKey;
            o.label = label;
            o.unitNumber = unitNumber;
            return o;
        }
    }
}