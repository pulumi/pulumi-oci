// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Core.outputs;

import com.pulumi.core.annotations.CustomType;
import java.lang.Boolean;
import java.lang.String;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;

@CustomType
public final class InstanceAvailabilityConfig {
    /**
     * @return (Updatable) Whether live migration is preferred for infrastructure maintenance.  If null preference is specified, live migration will be preferred for infrastructure maintenance for applicable instances.
     * 
     */
    private @Nullable Boolean isLiveMigrationPreferred;
    /**
     * @return (Updatable) The lifecycle state for an instance when it is recovered after infrastructure maintenance.
     * 
     */
    private @Nullable String recoveryAction;

    private InstanceAvailabilityConfig() {}
    /**
     * @return (Updatable) Whether live migration is preferred for infrastructure maintenance.  If null preference is specified, live migration will be preferred for infrastructure maintenance for applicable instances.
     * 
     */
    public Optional<Boolean> isLiveMigrationPreferred() {
        return Optional.ofNullable(this.isLiveMigrationPreferred);
    }
    /**
     * @return (Updatable) The lifecycle state for an instance when it is recovered after infrastructure maintenance.
     * 
     */
    public Optional<String> recoveryAction() {
        return Optional.ofNullable(this.recoveryAction);
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(InstanceAvailabilityConfig defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private @Nullable Boolean isLiveMigrationPreferred;
        private @Nullable String recoveryAction;
        public Builder() {}
        public Builder(InstanceAvailabilityConfig defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.isLiveMigrationPreferred = defaults.isLiveMigrationPreferred;
    	      this.recoveryAction = defaults.recoveryAction;
        }

        @CustomType.Setter
        public Builder isLiveMigrationPreferred(@Nullable Boolean isLiveMigrationPreferred) {
            this.isLiveMigrationPreferred = isLiveMigrationPreferred;
            return this;
        }
        @CustomType.Setter
        public Builder recoveryAction(@Nullable String recoveryAction) {
            this.recoveryAction = recoveryAction;
            return this;
        }
        public InstanceAvailabilityConfig build() {
            final var o = new InstanceAvailabilityConfig();
            o.isLiveMigrationPreferred = isLiveMigrationPreferred;
            o.recoveryAction = recoveryAction;
            return o;
        }
    }
}