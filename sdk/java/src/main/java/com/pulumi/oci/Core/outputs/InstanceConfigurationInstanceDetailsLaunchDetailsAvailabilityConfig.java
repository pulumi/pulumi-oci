// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Core.outputs;

import com.pulumi.core.annotations.CustomType;
import java.lang.String;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;

@CustomType
public final class InstanceConfigurationInstanceDetailsLaunchDetailsAvailabilityConfig {
    /**
     * @return The lifecycle state for an instance when it is recovered after infrastructure maintenance.
     * 
     */
    private @Nullable String recoveryAction;

    private InstanceConfigurationInstanceDetailsLaunchDetailsAvailabilityConfig() {}
    /**
     * @return The lifecycle state for an instance when it is recovered after infrastructure maintenance.
     * 
     */
    public Optional<String> recoveryAction() {
        return Optional.ofNullable(this.recoveryAction);
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(InstanceConfigurationInstanceDetailsLaunchDetailsAvailabilityConfig defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private @Nullable String recoveryAction;
        public Builder() {}
        public Builder(InstanceConfigurationInstanceDetailsLaunchDetailsAvailabilityConfig defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.recoveryAction = defaults.recoveryAction;
        }

        @CustomType.Setter
        public Builder recoveryAction(@Nullable String recoveryAction) {
            this.recoveryAction = recoveryAction;
            return this;
        }
        public InstanceConfigurationInstanceDetailsLaunchDetailsAvailabilityConfig build() {
            final var o = new InstanceConfigurationInstanceDetailsLaunchDetailsAvailabilityConfig();
            o.recoveryAction = recoveryAction;
            return o;
        }
    }
}