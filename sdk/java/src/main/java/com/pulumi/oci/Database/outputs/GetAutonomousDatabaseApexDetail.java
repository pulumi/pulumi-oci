// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Database.outputs;

import com.pulumi.core.annotations.CustomType;
import java.lang.String;
import java.util.Objects;

@CustomType
public final class GetAutonomousDatabaseApexDetail {
    /**
     * @return The Oracle APEX Application Development version.
     * 
     */
    private String apexVersion;
    /**
     * @return The Oracle REST Data Services (ORDS) version.
     * 
     */
    private String ordsVersion;

    private GetAutonomousDatabaseApexDetail() {}
    /**
     * @return The Oracle APEX Application Development version.
     * 
     */
    public String apexVersion() {
        return this.apexVersion;
    }
    /**
     * @return The Oracle REST Data Services (ORDS) version.
     * 
     */
    public String ordsVersion() {
        return this.ordsVersion;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetAutonomousDatabaseApexDetail defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String apexVersion;
        private String ordsVersion;
        public Builder() {}
        public Builder(GetAutonomousDatabaseApexDetail defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.apexVersion = defaults.apexVersion;
    	      this.ordsVersion = defaults.ordsVersion;
        }

        @CustomType.Setter
        public Builder apexVersion(String apexVersion) {
            this.apexVersion = Objects.requireNonNull(apexVersion);
            return this;
        }
        @CustomType.Setter
        public Builder ordsVersion(String ordsVersion) {
            this.ordsVersion = Objects.requireNonNull(ordsVersion);
            return this;
        }
        public GetAutonomousDatabaseApexDetail build() {
            final var o = new GetAutonomousDatabaseApexDetail();
            o.apexVersion = apexVersion;
            o.ordsVersion = ordsVersion;
            return o;
        }
    }
}