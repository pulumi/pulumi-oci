// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Core.outputs;

import com.pulumi.core.annotations.CustomType;
import java.lang.String;
import java.util.Objects;

@CustomType
public final class GetTunnelSecurityAssociationsTunnelSecurityAssociation {
    /**
     * @return The IP address and mask of the partner subnet used in policy based VPNs or static routes.
     * 
     */
    private String cpeSubnet;
    /**
     * @return The IP address and mask of the local subnet used in policy based VPNs or static routes.
     * 
     */
    private String oracleSubnet;
    /**
     * @return Time in the current state, in seconds.
     * 
     */
    private String time;
    /**
     * @return Current state if the IPSec tunnel status is not `UP`, including phase one and phase two details and a possible reason the tunnel is not `UP`.
     * 
     */
    private String tunnelSaErrorInfo;
    /**
     * @return The IPSec tunnel&#39;s phase one status.
     * 
     */
    private String tunnelSaStatus;

    private GetTunnelSecurityAssociationsTunnelSecurityAssociation() {}
    /**
     * @return The IP address and mask of the partner subnet used in policy based VPNs or static routes.
     * 
     */
    public String cpeSubnet() {
        return this.cpeSubnet;
    }
    /**
     * @return The IP address and mask of the local subnet used in policy based VPNs or static routes.
     * 
     */
    public String oracleSubnet() {
        return this.oracleSubnet;
    }
    /**
     * @return Time in the current state, in seconds.
     * 
     */
    public String time() {
        return this.time;
    }
    /**
     * @return Current state if the IPSec tunnel status is not `UP`, including phase one and phase two details and a possible reason the tunnel is not `UP`.
     * 
     */
    public String tunnelSaErrorInfo() {
        return this.tunnelSaErrorInfo;
    }
    /**
     * @return The IPSec tunnel&#39;s phase one status.
     * 
     */
    public String tunnelSaStatus() {
        return this.tunnelSaStatus;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetTunnelSecurityAssociationsTunnelSecurityAssociation defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String cpeSubnet;
        private String oracleSubnet;
        private String time;
        private String tunnelSaErrorInfo;
        private String tunnelSaStatus;
        public Builder() {}
        public Builder(GetTunnelSecurityAssociationsTunnelSecurityAssociation defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.cpeSubnet = defaults.cpeSubnet;
    	      this.oracleSubnet = defaults.oracleSubnet;
    	      this.time = defaults.time;
    	      this.tunnelSaErrorInfo = defaults.tunnelSaErrorInfo;
    	      this.tunnelSaStatus = defaults.tunnelSaStatus;
        }

        @CustomType.Setter
        public Builder cpeSubnet(String cpeSubnet) {
            this.cpeSubnet = Objects.requireNonNull(cpeSubnet);
            return this;
        }
        @CustomType.Setter
        public Builder oracleSubnet(String oracleSubnet) {
            this.oracleSubnet = Objects.requireNonNull(oracleSubnet);
            return this;
        }
        @CustomType.Setter
        public Builder time(String time) {
            this.time = Objects.requireNonNull(time);
            return this;
        }
        @CustomType.Setter
        public Builder tunnelSaErrorInfo(String tunnelSaErrorInfo) {
            this.tunnelSaErrorInfo = Objects.requireNonNull(tunnelSaErrorInfo);
            return this;
        }
        @CustomType.Setter
        public Builder tunnelSaStatus(String tunnelSaStatus) {
            this.tunnelSaStatus = Objects.requireNonNull(tunnelSaStatus);
            return this;
        }
        public GetTunnelSecurityAssociationsTunnelSecurityAssociation build() {
            final var o = new GetTunnelSecurityAssociationsTunnelSecurityAssociation();
            o.cpeSubnet = cpeSubnet;
            o.oracleSubnet = oracleSubnet;
            o.time = time;
            o.tunnelSaErrorInfo = tunnelSaErrorInfo;
            o.tunnelSaStatus = tunnelSaStatus;
            return o;
        }
    }
}