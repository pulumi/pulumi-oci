// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Core.outputs;

import com.pulumi.core.annotations.CustomType;
import java.lang.Boolean;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;

@CustomType
public final class ImageAgentFeature {
    /**
     * @return This attribute is not used.
     * 
     */
    private @Nullable Boolean isManagementSupported;
    /**
     * @return This attribute is not used.
     * 
     */
    private @Nullable Boolean isMonitoringSupported;

    private ImageAgentFeature() {}
    /**
     * @return This attribute is not used.
     * 
     */
    public Optional<Boolean> isManagementSupported() {
        return Optional.ofNullable(this.isManagementSupported);
    }
    /**
     * @return This attribute is not used.
     * 
     */
    public Optional<Boolean> isMonitoringSupported() {
        return Optional.ofNullable(this.isMonitoringSupported);
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(ImageAgentFeature defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private @Nullable Boolean isManagementSupported;
        private @Nullable Boolean isMonitoringSupported;
        public Builder() {}
        public Builder(ImageAgentFeature defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.isManagementSupported = defaults.isManagementSupported;
    	      this.isMonitoringSupported = defaults.isMonitoringSupported;
        }

        @CustomType.Setter
        public Builder isManagementSupported(@Nullable Boolean isManagementSupported) {
            this.isManagementSupported = isManagementSupported;
            return this;
        }
        @CustomType.Setter
        public Builder isMonitoringSupported(@Nullable Boolean isMonitoringSupported) {
            this.isMonitoringSupported = isMonitoringSupported;
            return this;
        }
        public ImageAgentFeature build() {
            final var o = new ImageAgentFeature();
            o.isManagementSupported = isManagementSupported;
            o.isMonitoringSupported = isMonitoringSupported;
            return o;
        }
    }
}