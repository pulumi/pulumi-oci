// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Database.outputs;

import com.pulumi.core.annotations.CustomType;
import java.lang.String;
import java.util.Objects;

@CustomType
public final class GetVmClusterRecommendedNetworkNetwork {
    /**
     * @return The cidr for the network.
     * 
     */
    private String cidr;
    /**
     * @return The network domain name.
     * 
     */
    private String domain;
    /**
     * @return The network gateway.
     * 
     */
    private String gateway;
    /**
     * @return The network netmask.
     * 
     */
    private String netmask;
    /**
     * @return The network type.
     * 
     */
    private String networkType;
    /**
     * @return The network domain name.
     * 
     */
    private String prefix;
    /**
     * @return The network VLAN ID.
     * 
     */
    private String vlanId;

    private GetVmClusterRecommendedNetworkNetwork() {}
    /**
     * @return The cidr for the network.
     * 
     */
    public String cidr() {
        return this.cidr;
    }
    /**
     * @return The network domain name.
     * 
     */
    public String domain() {
        return this.domain;
    }
    /**
     * @return The network gateway.
     * 
     */
    public String gateway() {
        return this.gateway;
    }
    /**
     * @return The network netmask.
     * 
     */
    public String netmask() {
        return this.netmask;
    }
    /**
     * @return The network type.
     * 
     */
    public String networkType() {
        return this.networkType;
    }
    /**
     * @return The network domain name.
     * 
     */
    public String prefix() {
        return this.prefix;
    }
    /**
     * @return The network VLAN ID.
     * 
     */
    public String vlanId() {
        return this.vlanId;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetVmClusterRecommendedNetworkNetwork defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String cidr;
        private String domain;
        private String gateway;
        private String netmask;
        private String networkType;
        private String prefix;
        private String vlanId;
        public Builder() {}
        public Builder(GetVmClusterRecommendedNetworkNetwork defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.cidr = defaults.cidr;
    	      this.domain = defaults.domain;
    	      this.gateway = defaults.gateway;
    	      this.netmask = defaults.netmask;
    	      this.networkType = defaults.networkType;
    	      this.prefix = defaults.prefix;
    	      this.vlanId = defaults.vlanId;
        }

        @CustomType.Setter
        public Builder cidr(String cidr) {
            this.cidr = Objects.requireNonNull(cidr);
            return this;
        }
        @CustomType.Setter
        public Builder domain(String domain) {
            this.domain = Objects.requireNonNull(domain);
            return this;
        }
        @CustomType.Setter
        public Builder gateway(String gateway) {
            this.gateway = Objects.requireNonNull(gateway);
            return this;
        }
        @CustomType.Setter
        public Builder netmask(String netmask) {
            this.netmask = Objects.requireNonNull(netmask);
            return this;
        }
        @CustomType.Setter
        public Builder networkType(String networkType) {
            this.networkType = Objects.requireNonNull(networkType);
            return this;
        }
        @CustomType.Setter
        public Builder prefix(String prefix) {
            this.prefix = Objects.requireNonNull(prefix);
            return this;
        }
        @CustomType.Setter
        public Builder vlanId(String vlanId) {
            this.vlanId = Objects.requireNonNull(vlanId);
            return this;
        }
        public GetVmClusterRecommendedNetworkNetwork build() {
            final var o = new GetVmClusterRecommendedNetworkNetwork();
            o.cidr = cidr;
            o.domain = domain;
            o.gateway = gateway;
            o.netmask = netmask;
            o.networkType = networkType;
            o.prefix = prefix;
            o.vlanId = vlanId;
            return o;
        }
    }
}