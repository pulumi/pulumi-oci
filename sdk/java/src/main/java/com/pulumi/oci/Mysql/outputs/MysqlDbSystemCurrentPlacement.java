// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Mysql.outputs;

import com.pulumi.core.annotations.CustomType;
import java.lang.String;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;

@CustomType
public final class MysqlDbSystemCurrentPlacement {
    /**
     * @return The availability domain on which to deploy the Read/Write endpoint. This defines the preferred primary instance.
     * 
     * In a failover scenario, the Read/Write endpoint is redirected to one of the other availability domains and the MySQL instance in that domain is promoted to the primary instance. This redirection does not affect the IP address of the DB System in any way.
     * 
     * For a standalone DB System, this defines the availability domain in which the DB System is placed.
     * 
     */
    private @Nullable String availabilityDomain;
    /**
     * @return The fault domain on which to deploy the Read/Write endpoint. This defines the preferred primary instance.
     * 
     * In a failover scenario, the Read/Write endpoint is redirected to one of the other fault domains and the MySQL instance in that domain is promoted to the primary instance. This redirection does not affect the IP address of the DB System in any way.
     * 
     * For a standalone DB System, this defines the fault domain in which the DB System is placed.
     * 
     */
    private @Nullable String faultDomain;

    private MysqlDbSystemCurrentPlacement() {}
    /**
     * @return The availability domain on which to deploy the Read/Write endpoint. This defines the preferred primary instance.
     * 
     * In a failover scenario, the Read/Write endpoint is redirected to one of the other availability domains and the MySQL instance in that domain is promoted to the primary instance. This redirection does not affect the IP address of the DB System in any way.
     * 
     * For a standalone DB System, this defines the availability domain in which the DB System is placed.
     * 
     */
    public Optional<String> availabilityDomain() {
        return Optional.ofNullable(this.availabilityDomain);
    }
    /**
     * @return The fault domain on which to deploy the Read/Write endpoint. This defines the preferred primary instance.
     * 
     * In a failover scenario, the Read/Write endpoint is redirected to one of the other fault domains and the MySQL instance in that domain is promoted to the primary instance. This redirection does not affect the IP address of the DB System in any way.
     * 
     * For a standalone DB System, this defines the fault domain in which the DB System is placed.
     * 
     */
    public Optional<String> faultDomain() {
        return Optional.ofNullable(this.faultDomain);
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(MysqlDbSystemCurrentPlacement defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private @Nullable String availabilityDomain;
        private @Nullable String faultDomain;
        public Builder() {}
        public Builder(MysqlDbSystemCurrentPlacement defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.availabilityDomain = defaults.availabilityDomain;
    	      this.faultDomain = defaults.faultDomain;
        }

        @CustomType.Setter
        public Builder availabilityDomain(@Nullable String availabilityDomain) {

            this.availabilityDomain = availabilityDomain;
            return this;
        }
        @CustomType.Setter
        public Builder faultDomain(@Nullable String faultDomain) {

            this.faultDomain = faultDomain;
            return this;
        }
        public MysqlDbSystemCurrentPlacement build() {
            final var _resultValue = new MysqlDbSystemCurrentPlacement();
            _resultValue.availabilityDomain = availabilityDomain;
            _resultValue.faultDomain = faultDomain;
            return _resultValue;
        }
    }
}
