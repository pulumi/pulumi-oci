// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.MediaServices.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.String;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;

@CustomType
public final class MediaAssetMediaAssetTag {
    /**
     * @return (Updatable) Type of the tag.
     * 
     */
    private @Nullable String type;
    /**
     * @return (Updatable) Tag of the MediaAsset.
     * 
     */
    private String value;

    private MediaAssetMediaAssetTag() {}
    /**
     * @return (Updatable) Type of the tag.
     * 
     */
    public Optional<String> type() {
        return Optional.ofNullable(this.type);
    }
    /**
     * @return (Updatable) Tag of the MediaAsset.
     * 
     */
    public String value() {
        return this.value;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(MediaAssetMediaAssetTag defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private @Nullable String type;
        private String value;
        public Builder() {}
        public Builder(MediaAssetMediaAssetTag defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.type = defaults.type;
    	      this.value = defaults.value;
        }

        @CustomType.Setter
        public Builder type(@Nullable String type) {

            this.type = type;
            return this;
        }
        @CustomType.Setter
        public Builder value(String value) {
            if (value == null) {
              throw new MissingRequiredPropertyException("MediaAssetMediaAssetTag", "value");
            }
            this.value = value;
            return this;
        }
        public MediaAssetMediaAssetTag build() {
            final var _resultValue = new MediaAssetMediaAssetTag();
            _resultValue.type = type;
            _resultValue.value = value;
            return _resultValue;
        }
    }
}
