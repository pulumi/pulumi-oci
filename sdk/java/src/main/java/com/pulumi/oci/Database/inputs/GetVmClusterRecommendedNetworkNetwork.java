// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Database.inputs;

import com.pulumi.core.annotations.Import;
import java.lang.String;
import java.util.Objects;


public final class GetVmClusterRecommendedNetworkNetwork extends com.pulumi.resources.InvokeArgs {

    public static final GetVmClusterRecommendedNetworkNetwork Empty = new GetVmClusterRecommendedNetworkNetwork();

    /**
     * The cidr for the network.
     * 
     */
    @Import(name="cidr", required=true)
    private String cidr;

    /**
     * @return The cidr for the network.
     * 
     */
    public String cidr() {
        return this.cidr;
    }

    /**
     * The network domain name.
     * 
     */
    @Import(name="domain", required=true)
    private String domain;

    /**
     * @return The network domain name.
     * 
     */
    public String domain() {
        return this.domain;
    }

    /**
     * The network gateway.
     * 
     */
    @Import(name="gateway", required=true)
    private String gateway;

    /**
     * @return The network gateway.
     * 
     */
    public String gateway() {
        return this.gateway;
    }

    /**
     * The network netmask.
     * 
     */
    @Import(name="netmask", required=true)
    private String netmask;

    /**
     * @return The network netmask.
     * 
     */
    public String netmask() {
        return this.netmask;
    }

    /**
     * The network type.
     * 
     */
    @Import(name="networkType", required=true)
    private String networkType;

    /**
     * @return The network type.
     * 
     */
    public String networkType() {
        return this.networkType;
    }

    /**
     * The network domain name.
     * 
     */
    @Import(name="prefix", required=true)
    private String prefix;

    /**
     * @return The network domain name.
     * 
     */
    public String prefix() {
        return this.prefix;
    }

    /**
     * The network VLAN ID.
     * 
     */
    @Import(name="vlanId", required=true)
    private String vlanId;

    /**
     * @return The network VLAN ID.
     * 
     */
    public String vlanId() {
        return this.vlanId;
    }

    private GetVmClusterRecommendedNetworkNetwork() {}

    private GetVmClusterRecommendedNetworkNetwork(GetVmClusterRecommendedNetworkNetwork $) {
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
    public static Builder builder(GetVmClusterRecommendedNetworkNetwork defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private GetVmClusterRecommendedNetworkNetwork $;

        public Builder() {
            $ = new GetVmClusterRecommendedNetworkNetwork();
        }

        public Builder(GetVmClusterRecommendedNetworkNetwork defaults) {
            $ = new GetVmClusterRecommendedNetworkNetwork(Objects.requireNonNull(defaults));
        }

        /**
         * @param cidr The cidr for the network.
         * 
         * @return builder
         * 
         */
        public Builder cidr(String cidr) {
            $.cidr = cidr;
            return this;
        }

        /**
         * @param domain The network domain name.
         * 
         * @return builder
         * 
         */
        public Builder domain(String domain) {
            $.domain = domain;
            return this;
        }

        /**
         * @param gateway The network gateway.
         * 
         * @return builder
         * 
         */
        public Builder gateway(String gateway) {
            $.gateway = gateway;
            return this;
        }

        /**
         * @param netmask The network netmask.
         * 
         * @return builder
         * 
         */
        public Builder netmask(String netmask) {
            $.netmask = netmask;
            return this;
        }

        /**
         * @param networkType The network type.
         * 
         * @return builder
         * 
         */
        public Builder networkType(String networkType) {
            $.networkType = networkType;
            return this;
        }

        /**
         * @param prefix The network domain name.
         * 
         * @return builder
         * 
         */
        public Builder prefix(String prefix) {
            $.prefix = prefix;
            return this;
        }

        /**
         * @param vlanId The network VLAN ID.
         * 
         * @return builder
         * 
         */
        public Builder vlanId(String vlanId) {
            $.vlanId = vlanId;
            return this;
        }

        public GetVmClusterRecommendedNetworkNetwork build() {
            $.cidr = Objects.requireNonNull($.cidr, "expected parameter 'cidr' to be non-null");
            $.domain = Objects.requireNonNull($.domain, "expected parameter 'domain' to be non-null");
            $.gateway = Objects.requireNonNull($.gateway, "expected parameter 'gateway' to be non-null");
            $.netmask = Objects.requireNonNull($.netmask, "expected parameter 'netmask' to be non-null");
            $.networkType = Objects.requireNonNull($.networkType, "expected parameter 'networkType' to be non-null");
            $.prefix = Objects.requireNonNull($.prefix, "expected parameter 'prefix' to be non-null");
            $.vlanId = Objects.requireNonNull($.vlanId, "expected parameter 'vlanId' to be non-null");
            return $;
        }
    }

}