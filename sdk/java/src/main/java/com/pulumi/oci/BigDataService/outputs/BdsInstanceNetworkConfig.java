// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.BigDataService.outputs;

import com.pulumi.core.annotations.CustomType;
import java.lang.Boolean;
import java.lang.String;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;

@CustomType
public final class BdsInstanceNetworkConfig {
    /**
     * @return The CIDR IP address block of the VCN.
     * 
     */
    private @Nullable String cidrBlock;
    /**
     * @return A boolean flag whether to configure a NAT gateway.
     * 
     */
    private @Nullable Boolean isNatGatewayRequired;

    private BdsInstanceNetworkConfig() {}
    /**
     * @return The CIDR IP address block of the VCN.
     * 
     */
    public Optional<String> cidrBlock() {
        return Optional.ofNullable(this.cidrBlock);
    }
    /**
     * @return A boolean flag whether to configure a NAT gateway.
     * 
     */
    public Optional<Boolean> isNatGatewayRequired() {
        return Optional.ofNullable(this.isNatGatewayRequired);
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(BdsInstanceNetworkConfig defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private @Nullable String cidrBlock;
        private @Nullable Boolean isNatGatewayRequired;
        public Builder() {}
        public Builder(BdsInstanceNetworkConfig defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.cidrBlock = defaults.cidrBlock;
    	      this.isNatGatewayRequired = defaults.isNatGatewayRequired;
        }

        @CustomType.Setter
        public Builder cidrBlock(@Nullable String cidrBlock) {
            this.cidrBlock = cidrBlock;
            return this;
        }
        @CustomType.Setter
        public Builder isNatGatewayRequired(@Nullable Boolean isNatGatewayRequired) {
            this.isNatGatewayRequired = isNatGatewayRequired;
            return this;
        }
        public BdsInstanceNetworkConfig build() {
            final var o = new BdsInstanceNetworkConfig();
            o.cidrBlock = cidrBlock;
            o.isNatGatewayRequired = isNatGatewayRequired;
            return o;
        }
    }
}