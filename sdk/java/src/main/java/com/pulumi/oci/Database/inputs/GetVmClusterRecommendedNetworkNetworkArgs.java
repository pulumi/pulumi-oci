// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Database.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.String;
import java.util.Objects;


public final class GetVmClusterRecommendedNetworkNetworkArgs extends com.pulumi.resources.ResourceArgs {

    public static final GetVmClusterRecommendedNetworkNetworkArgs Empty = new GetVmClusterRecommendedNetworkNetworkArgs();

    /**
     * The cidr for the network.
     * 
     */
    @Import(name="cidr", required=true)
    private Output<String> cidr;

    /**
     * @return The cidr for the network.
     * 
     */
    public Output<String> cidr() {
        return this.cidr;
    }

    /**
     * The network domain name.
     * 
     */
    @Import(name="domain", required=true)
    private Output<String> domain;

    /**
     * @return The network domain name.
     * 
     */
    public Output<String> domain() {
        return this.domain;
    }

    /**
     * The network gateway.
     * 
     */
    @Import(name="gateway", required=true)
    private Output<String> gateway;

    /**
     * @return The network gateway.
     * 
     */
    public Output<String> gateway() {
        return this.gateway;
    }

    /**
     * The network netmask.
     * 
     */
    @Import(name="netmask", required=true)
    private Output<String> netmask;

    /**
     * @return The network netmask.
     * 
     */
    public Output<String> netmask() {
        return this.netmask;
    }

    /**
     * The network type.
     * 
     */
    @Import(name="networkType", required=true)
    private Output<String> networkType;

    /**
     * @return The network type.
     * 
     */
    public Output<String> networkType() {
        return this.networkType;
    }

    /**
     * The network domain name.
     * 
     */
    @Import(name="prefix", required=true)
    private Output<String> prefix;

    /**
     * @return The network domain name.
     * 
     */
    public Output<String> prefix() {
        return this.prefix;
    }

    /**
     * The network VLAN ID.
     * 
     */
    @Import(name="vlanId", required=true)
    private Output<String> vlanId;

    /**
     * @return The network VLAN ID.
     * 
     */
    public Output<String> vlanId() {
        return this.vlanId;
    }

    private GetVmClusterRecommendedNetworkNetworkArgs() {}

    private GetVmClusterRecommendedNetworkNetworkArgs(GetVmClusterRecommendedNetworkNetworkArgs $) {
        this.cidr = $.cidr;
        this.domain = $.domain;
        this.gateway = $.gateway;
        this.netmask = $.netmask;
        this.networkType = $.networkType;
        this.prefix = $.prefix;
        this.vlanId = $.vlanId;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(GetVmClusterRecommendedNetworkNetworkArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private GetVmClusterRecommendedNetworkNetworkArgs $;

        public Builder() {
            $ = new GetVmClusterRecommendedNetworkNetworkArgs();
        }

        public Builder(GetVmClusterRecommendedNetworkNetworkArgs defaults) {
            $ = new GetVmClusterRecommendedNetworkNetworkArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param cidr The cidr for the network.
         * 
         * @return builder
         * 
         */
        public Builder cidr(Output<String> cidr) {
            $.cidr = cidr;
            return this;
        }

        /**
         * @param cidr The cidr for the network.
         * 
         * @return builder
         * 
         */
        public Builder cidr(String cidr) {
            return cidr(Output.of(cidr));
        }

        /**
         * @param domain The network domain name.
         * 
         * @return builder
         * 
         */
        public Builder domain(Output<String> domain) {
            $.domain = domain;
            return this;
        }

        /**
         * @param domain The network domain name.
         * 
         * @return builder
         * 
         */
        public Builder domain(String domain) {
            return domain(Output.of(domain));
        }

        /**
         * @param gateway The network gateway.
         * 
         * @return builder
         * 
         */
        public Builder gateway(Output<String> gateway) {
            $.gateway = gateway;
            return this;
        }

        /**
         * @param gateway The network gateway.
         * 
         * @return builder
         * 
         */
        public Builder gateway(String gateway) {
            return gateway(Output.of(gateway));
        }

        /**
         * @param netmask The network netmask.
         * 
         * @return builder
         * 
         */
        public Builder netmask(Output<String> netmask) {
            $.netmask = netmask;
            return this;
        }

        /**
         * @param netmask The network netmask.
         * 
         * @return builder
         * 
         */
        public Builder netmask(String netmask) {
            return netmask(Output.of(netmask));
        }

        /**
         * @param networkType The network type.
         * 
         * @return builder
         * 
         */
        public Builder networkType(Output<String> networkType) {
            $.networkType = networkType;
            return this;
        }

        /**
         * @param networkType The network type.
         * 
         * @return builder
         * 
         */
        public Builder networkType(String networkType) {
            return networkType(Output.of(networkType));
        }

        /**
         * @param prefix The network domain name.
         * 
         * @return builder
         * 
         */
        public Builder prefix(Output<String> prefix) {
            $.prefix = prefix;
            return this;
        }

        /**
         * @param prefix The network domain name.
         * 
         * @return builder
         * 
         */
        public Builder prefix(String prefix) {
            return prefix(Output.of(prefix));
        }

        /**
         * @param vlanId The network VLAN ID.
         * 
         * @return builder
         * 
         */
        public Builder vlanId(Output<String> vlanId) {
            $.vlanId = vlanId;
            return this;
        }

        /**
         * @param vlanId The network VLAN ID.
         * 
         * @return builder
         * 
         */
        public Builder vlanId(String vlanId) {
            return vlanId(Output.of(vlanId));
        }

        public GetVmClusterRecommendedNetworkNetworkArgs build() {
            if ($.cidr == null) {
                throw new MissingRequiredPropertyException("GetVmClusterRecommendedNetworkNetworkArgs", "cidr");
            }
            if ($.domain == null) {
                throw new MissingRequiredPropertyException("GetVmClusterRecommendedNetworkNetworkArgs", "domain");
            }
            if ($.gateway == null) {
                throw new MissingRequiredPropertyException("GetVmClusterRecommendedNetworkNetworkArgs", "gateway");
            }
            if ($.netmask == null) {
                throw new MissingRequiredPropertyException("GetVmClusterRecommendedNetworkNetworkArgs", "netmask");
            }
            if ($.networkType == null) {
                throw new MissingRequiredPropertyException("GetVmClusterRecommendedNetworkNetworkArgs", "networkType");
            }
            if ($.prefix == null) {
                throw new MissingRequiredPropertyException("GetVmClusterRecommendedNetworkNetworkArgs", "prefix");
            }
            if ($.vlanId == null) {
                throw new MissingRequiredPropertyException("GetVmClusterRecommendedNetworkNetworkArgs", "vlanId");
            }
            return $;
        }
    }

}
