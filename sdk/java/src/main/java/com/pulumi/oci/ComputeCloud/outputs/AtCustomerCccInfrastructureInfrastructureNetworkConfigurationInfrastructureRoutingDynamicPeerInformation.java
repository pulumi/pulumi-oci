// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.ComputeCloud.outputs;

import com.pulumi.core.annotations.CustomType;
import java.lang.Integer;
import java.lang.String;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;

@CustomType
public final class AtCustomerCccInfrastructureInfrastructureNetworkConfigurationInfrastructureRoutingDynamicPeerInformation {
    /**
     * @return The Autonomous System Number (ASN) of the peer network.
     * 
     */
    private @Nullable Integer asn;
    /**
     * @return Address of the management node.
     * 
     */
    private @Nullable String ip;

    private AtCustomerCccInfrastructureInfrastructureNetworkConfigurationInfrastructureRoutingDynamicPeerInformation() {}
    /**
     * @return The Autonomous System Number (ASN) of the peer network.
     * 
     */
    public Optional<Integer> asn() {
        return Optional.ofNullable(this.asn);
    }
    /**
     * @return Address of the management node.
     * 
     */
    public Optional<String> ip() {
        return Optional.ofNullable(this.ip);
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(AtCustomerCccInfrastructureInfrastructureNetworkConfigurationInfrastructureRoutingDynamicPeerInformation defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private @Nullable Integer asn;
        private @Nullable String ip;
        public Builder() {}
        public Builder(AtCustomerCccInfrastructureInfrastructureNetworkConfigurationInfrastructureRoutingDynamicPeerInformation defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.asn = defaults.asn;
    	      this.ip = defaults.ip;
        }

        @CustomType.Setter
        public Builder asn(@Nullable Integer asn) {

            this.asn = asn;
            return this;
        }
        @CustomType.Setter
        public Builder ip(@Nullable String ip) {

            this.ip = ip;
            return this;
        }
        public AtCustomerCccInfrastructureInfrastructureNetworkConfigurationInfrastructureRoutingDynamicPeerInformation build() {
            final var _resultValue = new AtCustomerCccInfrastructureInfrastructureNetworkConfigurationInfrastructureRoutingDynamicPeerInformation();
            _resultValue.asn = asn;
            _resultValue.ip = ip;
            return _resultValue;
        }
    }
}
