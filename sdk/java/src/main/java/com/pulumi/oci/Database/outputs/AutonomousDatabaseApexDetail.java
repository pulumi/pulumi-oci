// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Database.outputs;

import com.pulumi.core.annotations.CustomType;
import java.lang.String;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;

@CustomType
public final class AutonomousDatabaseApexDetail {
    /**
     * @return The Oracle APEX Application Development version.
     * 
     */
    private @Nullable String apexVersion;
    /**
     * @return The Oracle REST Data Services (ORDS) version.
     * 
     */
    private @Nullable String ordsVersion;

    private AutonomousDatabaseApexDetail() {}
    /**
     * @return The Oracle APEX Application Development version.
     * 
     */
    public Optional<String> apexVersion() {
        return Optional.ofNullable(this.apexVersion);
    }
    /**
     * @return The Oracle REST Data Services (ORDS) version.
     * 
     */
    public Optional<String> ordsVersion() {
        return Optional.ofNullable(this.ordsVersion);
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(AutonomousDatabaseApexDetail defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private @Nullable String apexVersion;
        private @Nullable String ordsVersion;
        public Builder() {}
        public Builder(AutonomousDatabaseApexDetail defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.apexVersion = defaults.apexVersion;
    	      this.ordsVersion = defaults.ordsVersion;
        }

        @CustomType.Setter
        public Builder apexVersion(@Nullable String apexVersion) {
            this.apexVersion = apexVersion;
            return this;
        }
        @CustomType.Setter
        public Builder ordsVersion(@Nullable String ordsVersion) {
            this.ordsVersion = ordsVersion;
            return this;
        }
        public AutonomousDatabaseApexDetail build() {
            final var o = new AutonomousDatabaseApexDetail();
            o.apexVersion = apexVersion;
            o.ordsVersion = ordsVersion;
            return o;
        }
    }
}