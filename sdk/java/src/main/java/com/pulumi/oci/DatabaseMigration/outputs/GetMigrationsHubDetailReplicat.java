// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DatabaseMigration.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.String;
import java.util.Objects;

@CustomType
public final class GetMigrationsHubDetailReplicat {
    /**
     * @return Replicat performance.
     * 
     */
    private String performanceProfile;

    private GetMigrationsHubDetailReplicat() {}
    /**
     * @return Replicat performance.
     * 
     */
    public String performanceProfile() {
        return this.performanceProfile;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetMigrationsHubDetailReplicat defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String performanceProfile;
        public Builder() {}
        public Builder(GetMigrationsHubDetailReplicat defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.performanceProfile = defaults.performanceProfile;
        }

        @CustomType.Setter
        public Builder performanceProfile(String performanceProfile) {
            if (performanceProfile == null) {
              throw new MissingRequiredPropertyException("GetMigrationsHubDetailReplicat", "performanceProfile");
            }
            this.performanceProfile = performanceProfile;
            return this;
        }
        public GetMigrationsHubDetailReplicat build() {
            final var _resultValue = new GetMigrationsHubDetailReplicat();
            _resultValue.performanceProfile = performanceProfile;
            return _resultValue;
        }
    }
}
