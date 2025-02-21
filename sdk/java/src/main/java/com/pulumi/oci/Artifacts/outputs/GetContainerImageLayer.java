// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Artifacts.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.String;
import java.util.Objects;

@CustomType
public final class GetContainerImageLayer {
    /**
     * @return The sha256 digest of the image layer.
     * 
     */
    private String digest;
    /**
     * @return The size of the layer in bytes.
     * 
     */
    private String sizeInBytes;
    /**
     * @return The creation time of the version.
     * 
     */
    private String timeCreated;

    private GetContainerImageLayer() {}
    /**
     * @return The sha256 digest of the image layer.
     * 
     */
    public String digest() {
        return this.digest;
    }
    /**
     * @return The size of the layer in bytes.
     * 
     */
    public String sizeInBytes() {
        return this.sizeInBytes;
    }
    /**
     * @return The creation time of the version.
     * 
     */
    public String timeCreated() {
        return this.timeCreated;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetContainerImageLayer defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String digest;
        private String sizeInBytes;
        private String timeCreated;
        public Builder() {}
        public Builder(GetContainerImageLayer defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.digest = defaults.digest;
    	      this.sizeInBytes = defaults.sizeInBytes;
    	      this.timeCreated = defaults.timeCreated;
        }

        @CustomType.Setter
        public Builder digest(String digest) {
            if (digest == null) {
              throw new MissingRequiredPropertyException("GetContainerImageLayer", "digest");
            }
            this.digest = digest;
            return this;
        }
        @CustomType.Setter
        public Builder sizeInBytes(String sizeInBytes) {
            if (sizeInBytes == null) {
              throw new MissingRequiredPropertyException("GetContainerImageLayer", "sizeInBytes");
            }
            this.sizeInBytes = sizeInBytes;
            return this;
        }
        @CustomType.Setter
        public Builder timeCreated(String timeCreated) {
            if (timeCreated == null) {
              throw new MissingRequiredPropertyException("GetContainerImageLayer", "timeCreated");
            }
            this.timeCreated = timeCreated;
            return this;
        }
        public GetContainerImageLayer build() {
            final var _resultValue = new GetContainerImageLayer();
            _resultValue.digest = digest;
            _resultValue.sizeInBytes = sizeInBytes;
            _resultValue.timeCreated = timeCreated;
            return _resultValue;
        }
    }
}
