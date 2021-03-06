// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Mysql.outputs;

import com.pulumi.core.annotations.CustomType;
import java.lang.String;
import java.util.Objects;

@CustomType
public final class GetMysqlDbSystemCurrentPlacement {
    /**
     * @return The availability domain in which the DB System is placed.
     * 
     */
    private final String availabilityDomain;
    /**
     * @return The fault domain on which to deploy the Read/Write endpoint. This defines the preferred primary instance.
     * 
     */
    private final String faultDomain;

    @CustomType.Constructor
    private GetMysqlDbSystemCurrentPlacement(
        @CustomType.Parameter("availabilityDomain") String availabilityDomain,
        @CustomType.Parameter("faultDomain") String faultDomain) {
        this.availabilityDomain = availabilityDomain;
        this.faultDomain = faultDomain;
    }

    /**
     * @return The availability domain in which the DB System is placed.
     * 
     */
    public String availabilityDomain() {
        return this.availabilityDomain;
    }
    /**
     * @return The fault domain on which to deploy the Read/Write endpoint. This defines the preferred primary instance.
     * 
     */
    public String faultDomain() {
        return this.faultDomain;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetMysqlDbSystemCurrentPlacement defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private String availabilityDomain;
        private String faultDomain;

        public Builder() {
    	      // Empty
        }

        public Builder(GetMysqlDbSystemCurrentPlacement defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.availabilityDomain = defaults.availabilityDomain;
    	      this.faultDomain = defaults.faultDomain;
        }

        public Builder availabilityDomain(String availabilityDomain) {
            this.availabilityDomain = Objects.requireNonNull(availabilityDomain);
            return this;
        }
        public Builder faultDomain(String faultDomain) {
            this.faultDomain = Objects.requireNonNull(faultDomain);
            return this;
        }        public GetMysqlDbSystemCurrentPlacement build() {
            return new GetMysqlDbSystemCurrentPlacement(availabilityDomain, faultDomain);
        }
    }
}
