// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.ComputeCloud.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import java.lang.Integer;
import java.lang.String;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class AtCustomerCccInfrastructureInfrastructureNetworkConfigurationInfrastructureRoutingDynamicPeerInformationArgs extends com.pulumi.resources.ResourceArgs {

    public static final AtCustomerCccInfrastructureInfrastructureNetworkConfigurationInfrastructureRoutingDynamicPeerInformationArgs Empty = new AtCustomerCccInfrastructureInfrastructureNetworkConfigurationInfrastructureRoutingDynamicPeerInformationArgs();

    /**
     * The Autonomous System Number (ASN) of the peer network.
     * 
     */
    @Import(name="asn")
    private @Nullable Output<Integer> asn;

    /**
     * @return The Autonomous System Number (ASN) of the peer network.
     * 
     */
    public Optional<Output<Integer>> asn() {
        return Optional.ofNullable(this.asn);
    }

    /**
     * Address of the management node.
     * 
     */
    @Import(name="ip")
    private @Nullable Output<String> ip;

    /**
     * @return Address of the management node.
     * 
     */
    public Optional<Output<String>> ip() {
        return Optional.ofNullable(this.ip);
    }

    private AtCustomerCccInfrastructureInfrastructureNetworkConfigurationInfrastructureRoutingDynamicPeerInformationArgs() {}

    private AtCustomerCccInfrastructureInfrastructureNetworkConfigurationInfrastructureRoutingDynamicPeerInformationArgs(AtCustomerCccInfrastructureInfrastructureNetworkConfigurationInfrastructureRoutingDynamicPeerInformationArgs $) {
        this.asn = $.asn;
        this.ip = $.ip;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(AtCustomerCccInfrastructureInfrastructureNetworkConfigurationInfrastructureRoutingDynamicPeerInformationArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private AtCustomerCccInfrastructureInfrastructureNetworkConfigurationInfrastructureRoutingDynamicPeerInformationArgs $;

        public Builder() {
            $ = new AtCustomerCccInfrastructureInfrastructureNetworkConfigurationInfrastructureRoutingDynamicPeerInformationArgs();
        }

        public Builder(AtCustomerCccInfrastructureInfrastructureNetworkConfigurationInfrastructureRoutingDynamicPeerInformationArgs defaults) {
            $ = new AtCustomerCccInfrastructureInfrastructureNetworkConfigurationInfrastructureRoutingDynamicPeerInformationArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param asn The Autonomous System Number (ASN) of the peer network.
         * 
         * @return builder
         * 
         */
        public Builder asn(@Nullable Output<Integer> asn) {
            $.asn = asn;
            return this;
        }

        /**
         * @param asn The Autonomous System Number (ASN) of the peer network.
         * 
         * @return builder
         * 
         */
        public Builder asn(Integer asn) {
            return asn(Output.of(asn));
        }

        /**
         * @param ip Address of the management node.
         * 
         * @return builder
         * 
         */
        public Builder ip(@Nullable Output<String> ip) {
            $.ip = ip;
            return this;
        }

        /**
         * @param ip Address of the management node.
         * 
         * @return builder
         * 
         */
        public Builder ip(String ip) {
            return ip(Output.of(ip));
        }

        public AtCustomerCccInfrastructureInfrastructureNetworkConfigurationInfrastructureRoutingDynamicPeerInformationArgs build() {
            return $;
        }
    }

}