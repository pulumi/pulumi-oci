// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Analytics.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.oci.Analytics.outputs.GetAnalyticsInstanceNetworkEndpointDetailWhitelistedVcn;
import java.lang.String;
import java.util.List;
import java.util.Objects;

@CustomType
public final class GetAnalyticsInstanceNetworkEndpointDetail {
    /**
     * @return The type of network endpoint.
     * 
     */
    private String networkEndpointType;
    /**
     * @return Network Security Group OCIDs for an Analytics instance.
     * 
     */
    private List<String> networkSecurityGroupIds;
    /**
     * @return OCID of the customer subnet connected to private access channel.
     * 
     */
    private String subnetId;
    /**
     * @return OCID of the customer VCN peered with private access channel.
     * 
     */
    private String vcnId;
    /**
     * @return Source IP addresses or IP address ranges in ingress rules.
     * 
     */
    private List<String> whitelistedIps;
    /**
     * @return Oracle Cloud Services that are allowed to access this Analytics instance.
     * 
     */
    private List<String> whitelistedServices;
    /**
     * @return Virtual Cloud Networks allowed to access this network endpoint.
     * 
     */
    private List<GetAnalyticsInstanceNetworkEndpointDetailWhitelistedVcn> whitelistedVcns;

    private GetAnalyticsInstanceNetworkEndpointDetail() {}
    /**
     * @return The type of network endpoint.
     * 
     */
    public String networkEndpointType() {
        return this.networkEndpointType;
    }
    /**
     * @return Network Security Group OCIDs for an Analytics instance.
     * 
     */
    public List<String> networkSecurityGroupIds() {
        return this.networkSecurityGroupIds;
    }
    /**
     * @return OCID of the customer subnet connected to private access channel.
     * 
     */
    public String subnetId() {
        return this.subnetId;
    }
    /**
     * @return OCID of the customer VCN peered with private access channel.
     * 
     */
    public String vcnId() {
        return this.vcnId;
    }
    /**
     * @return Source IP addresses or IP address ranges in ingress rules.
     * 
     */
    public List<String> whitelistedIps() {
        return this.whitelistedIps;
    }
    /**
     * @return Oracle Cloud Services that are allowed to access this Analytics instance.
     * 
     */
    public List<String> whitelistedServices() {
        return this.whitelistedServices;
    }
    /**
     * @return Virtual Cloud Networks allowed to access this network endpoint.
     * 
     */
    public List<GetAnalyticsInstanceNetworkEndpointDetailWhitelistedVcn> whitelistedVcns() {
        return this.whitelistedVcns;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetAnalyticsInstanceNetworkEndpointDetail defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String networkEndpointType;
        private List<String> networkSecurityGroupIds;
        private String subnetId;
        private String vcnId;
        private List<String> whitelistedIps;
        private List<String> whitelistedServices;
        private List<GetAnalyticsInstanceNetworkEndpointDetailWhitelistedVcn> whitelistedVcns;
        public Builder() {}
        public Builder(GetAnalyticsInstanceNetworkEndpointDetail defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.networkEndpointType = defaults.networkEndpointType;
    	      this.networkSecurityGroupIds = defaults.networkSecurityGroupIds;
    	      this.subnetId = defaults.subnetId;
    	      this.vcnId = defaults.vcnId;
    	      this.whitelistedIps = defaults.whitelistedIps;
    	      this.whitelistedServices = defaults.whitelistedServices;
    	      this.whitelistedVcns = defaults.whitelistedVcns;
        }

        @CustomType.Setter
        public Builder networkEndpointType(String networkEndpointType) {
            this.networkEndpointType = Objects.requireNonNull(networkEndpointType);
            return this;
        }
        @CustomType.Setter
        public Builder networkSecurityGroupIds(List<String> networkSecurityGroupIds) {
            this.networkSecurityGroupIds = Objects.requireNonNull(networkSecurityGroupIds);
            return this;
        }
        public Builder networkSecurityGroupIds(String... networkSecurityGroupIds) {
            return networkSecurityGroupIds(List.of(networkSecurityGroupIds));
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
        @CustomType.Setter
        public Builder whitelistedIps(List<String> whitelistedIps) {
            this.whitelistedIps = Objects.requireNonNull(whitelistedIps);
            return this;
        }
        public Builder whitelistedIps(String... whitelistedIps) {
            return whitelistedIps(List.of(whitelistedIps));
        }
        @CustomType.Setter
        public Builder whitelistedServices(List<String> whitelistedServices) {
            this.whitelistedServices = Objects.requireNonNull(whitelistedServices);
            return this;
        }
        public Builder whitelistedServices(String... whitelistedServices) {
            return whitelistedServices(List.of(whitelistedServices));
        }
        @CustomType.Setter
        public Builder whitelistedVcns(List<GetAnalyticsInstanceNetworkEndpointDetailWhitelistedVcn> whitelistedVcns) {
            this.whitelistedVcns = Objects.requireNonNull(whitelistedVcns);
            return this;
        }
        public Builder whitelistedVcns(GetAnalyticsInstanceNetworkEndpointDetailWhitelistedVcn... whitelistedVcns) {
            return whitelistedVcns(List.of(whitelistedVcns));
        }
        public GetAnalyticsInstanceNetworkEndpointDetail build() {
            final var o = new GetAnalyticsInstanceNetworkEndpointDetail();
            o.networkEndpointType = networkEndpointType;
            o.networkSecurityGroupIds = networkSecurityGroupIds;
            o.subnetId = subnetId;
            o.vcnId = vcnId;
            o.whitelistedIps = whitelistedIps;
            o.whitelistedServices = whitelistedServices;
            o.whitelistedVcns = whitelistedVcns;
            return o;
        }
    }
}