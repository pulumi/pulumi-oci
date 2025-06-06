// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Core.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.String;
import java.util.List;
import java.util.Objects;

@CustomType
public final class GetIpsecConnectionsConnectionTunnelConfiguration {
    private List<String> associatedVirtualCircuits;
    private String drgRouteTableId;
    private String oracleTunnelIp;

    private GetIpsecConnectionsConnectionTunnelConfiguration() {}
    public List<String> associatedVirtualCircuits() {
        return this.associatedVirtualCircuits;
    }
    public String drgRouteTableId() {
        return this.drgRouteTableId;
    }
    public String oracleTunnelIp() {
        return this.oracleTunnelIp;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetIpsecConnectionsConnectionTunnelConfiguration defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private List<String> associatedVirtualCircuits;
        private String drgRouteTableId;
        private String oracleTunnelIp;
        public Builder() {}
        public Builder(GetIpsecConnectionsConnectionTunnelConfiguration defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.associatedVirtualCircuits = defaults.associatedVirtualCircuits;
    	      this.drgRouteTableId = defaults.drgRouteTableId;
    	      this.oracleTunnelIp = defaults.oracleTunnelIp;
        }

        @CustomType.Setter
        public Builder associatedVirtualCircuits(List<String> associatedVirtualCircuits) {
            if (associatedVirtualCircuits == null) {
              throw new MissingRequiredPropertyException("GetIpsecConnectionsConnectionTunnelConfiguration", "associatedVirtualCircuits");
            }
            this.associatedVirtualCircuits = associatedVirtualCircuits;
            return this;
        }
        public Builder associatedVirtualCircuits(String... associatedVirtualCircuits) {
            return associatedVirtualCircuits(List.of(associatedVirtualCircuits));
        }
        @CustomType.Setter
        public Builder drgRouteTableId(String drgRouteTableId) {
            if (drgRouteTableId == null) {
              throw new MissingRequiredPropertyException("GetIpsecConnectionsConnectionTunnelConfiguration", "drgRouteTableId");
            }
            this.drgRouteTableId = drgRouteTableId;
            return this;
        }
        @CustomType.Setter
        public Builder oracleTunnelIp(String oracleTunnelIp) {
            if (oracleTunnelIp == null) {
              throw new MissingRequiredPropertyException("GetIpsecConnectionsConnectionTunnelConfiguration", "oracleTunnelIp");
            }
            this.oracleTunnelIp = oracleTunnelIp;
            return this;
        }
        public GetIpsecConnectionsConnectionTunnelConfiguration build() {
            final var _resultValue = new GetIpsecConnectionsConnectionTunnelConfiguration();
            _resultValue.associatedVirtualCircuits = associatedVirtualCircuits;
            _resultValue.drgRouteTableId = drgRouteTableId;
            _resultValue.oracleTunnelIp = oracleTunnelIp;
            return _resultValue;
        }
    }
}
