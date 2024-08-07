// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Database.outputs;

import com.pulumi.core.annotations.CustomType;
import java.lang.Boolean;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;

@CustomType
public final class PluggableDatabaseRefreshableCloneConfig {
    /**
     * @return Indicates whether the Pluggable Database is a refreshable clone.
     * 
     */
    private @Nullable Boolean isRefreshableClone;

    private PluggableDatabaseRefreshableCloneConfig() {}
    /**
     * @return Indicates whether the Pluggable Database is a refreshable clone.
     * 
     */
    public Optional<Boolean> isRefreshableClone() {
        return Optional.ofNullable(this.isRefreshableClone);
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(PluggableDatabaseRefreshableCloneConfig defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private @Nullable Boolean isRefreshableClone;
        public Builder() {}
        public Builder(PluggableDatabaseRefreshableCloneConfig defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.isRefreshableClone = defaults.isRefreshableClone;
        }

        @CustomType.Setter
        public Builder isRefreshableClone(@Nullable Boolean isRefreshableClone) {

            this.isRefreshableClone = isRefreshableClone;
            return this;
        }
        public PluggableDatabaseRefreshableCloneConfig build() {
            final var _resultValue = new PluggableDatabaseRefreshableCloneConfig();
            _resultValue.isRefreshableClone = isRefreshableClone;
            return _resultValue;
        }
    }
}
