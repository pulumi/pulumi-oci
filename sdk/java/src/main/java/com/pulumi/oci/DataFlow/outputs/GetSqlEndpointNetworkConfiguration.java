// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DataFlow.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.oci.DataFlow.outputs.GetSqlEndpointNetworkConfigurationAccessControlRule;
import java.lang.String;
import java.util.List;
import java.util.Objects;

@CustomType
public final class GetSqlEndpointNetworkConfiguration {
    /**
     * @return A list of SecureAccessControlRule&#39;s to which access is limited to
     * 
     */
    private List<GetSqlEndpointNetworkConfigurationAccessControlRule> accessControlRules;
    /**
     * @return The host name prefix.
     * 
     */
    private String hostNamePrefix;
    /**
     * @return The type of network configuration.
     * 
     */
    private String networkType;
    /**
     * @return Ip Address of private endpoint
     * 
     */
    private String privateEndpointIp;
    /**
     * @return Ip Address of public endpoint
     * 
     */
    private String publicEndpointIp;
    /**
     * @return The VCN Subnet OCID.
     * 
     */
    private String subnetId;
    /**
     * @return The VCN OCID.
     * 
     */
    private String vcnId;

    private GetSqlEndpointNetworkConfiguration() {}
    /**
     * @return A list of SecureAccessControlRule&#39;s to which access is limited to
     * 
     */
    public List<GetSqlEndpointNetworkConfigurationAccessControlRule> accessControlRules() {
        return this.accessControlRules;
    }
    /**
     * @return The host name prefix.
     * 
     */
    public String hostNamePrefix() {
        return this.hostNamePrefix;
    }
    /**
     * @return The type of network configuration.
     * 
     */
    public String networkType() {
        return this.networkType;
    }
    /**
     * @return Ip Address of private endpoint
     * 
     */
    public String privateEndpointIp() {
        return this.privateEndpointIp;
    }
    /**
     * @return Ip Address of public endpoint
     * 
     */
    public String publicEndpointIp() {
        return this.publicEndpointIp;
    }
    /**
     * @return The VCN Subnet OCID.
     * 
     */
    public String subnetId() {
        return this.subnetId;
    }
    /**
     * @return The VCN OCID.
     * 
     */
    public String vcnId() {
        return this.vcnId;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetSqlEndpointNetworkConfiguration defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private List<GetSqlEndpointNetworkConfigurationAccessControlRule> accessControlRules;
        private String hostNamePrefix;
        private String networkType;
        private String privateEndpointIp;
        private String publicEndpointIp;
        private String subnetId;
        private String vcnId;
        public Builder() {}
        public Builder(GetSqlEndpointNetworkConfiguration defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.accessControlRules = defaults.accessControlRules;
    	      this.hostNamePrefix = defaults.hostNamePrefix;
    	      this.networkType = defaults.networkType;
    	      this.privateEndpointIp = defaults.privateEndpointIp;
    	      this.publicEndpointIp = defaults.publicEndpointIp;
    	      this.subnetId = defaults.subnetId;
    	      this.vcnId = defaults.vcnId;
        }

        @CustomType.Setter
        public Builder accessControlRules(List<GetSqlEndpointNetworkConfigurationAccessControlRule> accessControlRules) {
            this.accessControlRules = Objects.requireNonNull(accessControlRules);
            return this;
        }
        public Builder accessControlRules(GetSqlEndpointNetworkConfigurationAccessControlRule... accessControlRules) {
            return accessControlRules(List.of(accessControlRules));
        }
        @CustomType.Setter
        public Builder hostNamePrefix(String hostNamePrefix) {
            this.hostNamePrefix = Objects.requireNonNull(hostNamePrefix);
            return this;
        }
        @CustomType.Setter
        public Builder networkType(String networkType) {
            this.networkType = Objects.requireNonNull(networkType);
            return this;
        }
        @CustomType.Setter
        public Builder privateEndpointIp(String privateEndpointIp) {
            this.privateEndpointIp = Objects.requireNonNull(privateEndpointIp);
            return this;
        }
        @CustomType.Setter
        public Builder publicEndpointIp(String publicEndpointIp) {
            this.publicEndpointIp = Objects.requireNonNull(publicEndpointIp);
            return this;
        }
        @CustomType.Setter
        public Builder subnetId(String subnetId) {
            this.subnetId = Objects.requireNonNull(subnetId);
            return this;
        }
        @CustomType.Setter
        public Builder vcnId(String vcnId) {
            this.vcnId = Objects.requireNonNull(vcnId);
            return this;
        }
        public GetSqlEndpointNetworkConfiguration build() {
            final var o = new GetSqlEndpointNetworkConfiguration();
            o.accessControlRules = accessControlRules;
            o.hostNamePrefix = hostNamePrefix;
            o.networkType = networkType;
            o.privateEndpointIp = privateEndpointIp;
            o.publicEndpointIp = publicEndpointIp;
            o.subnetId = subnetId;
            o.vcnId = vcnId;
            return o;
        }
    }
}