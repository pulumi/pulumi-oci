// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Database.outputs;

import com.pulumi.core.annotations.CustomType;
import java.lang.Boolean;
import java.util.Objects;

@CustomType
public final class GetPluggableDatabaseRefreshableCloneConfig {
    /**
     * @return Indicates whether the Pluggable Database is a refreshable clone.
     * 
     */
    private Boolean isRefreshableClone;

    private GetPluggableDatabaseRefreshableCloneConfig() {}
    /**
     * @return Indicates whether the Pluggable Database is a refreshable clone.
     * 
     */
    public Boolean isRefreshableClone() {
        return this.isRefreshableClone;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetPluggableDatabaseRefreshableCloneConfig defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private Boolean isRefreshableClone;
        public Builder() {}
        public Builder(GetPluggableDatabaseRefreshableCloneConfig defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.isRefreshableClone = defaults.isRefreshableClone;
        }

        @CustomType.Setter
        public Builder isRefreshableClone(Boolean isRefreshableClone) {
            this.isRefreshableClone = Objects.requireNonNull(isRefreshableClone);
            return this;
        }
        public GetPluggableDatabaseRefreshableCloneConfig build() {
            final var o = new GetPluggableDatabaseRefreshableCloneConfig();
            o.isRefreshableClone = isRefreshableClone;
            return o;
        }
    }
}