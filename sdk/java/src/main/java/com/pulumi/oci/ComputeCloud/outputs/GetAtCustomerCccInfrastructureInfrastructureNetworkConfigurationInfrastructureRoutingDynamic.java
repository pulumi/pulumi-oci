// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.ComputeCloud.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.ComputeCloud.outputs.GetAtCustomerCccInfrastructureInfrastructureNetworkConfigurationInfrastructureRoutingDynamicPeerInformation;
import java.lang.Integer;
import java.lang.String;
import java.util.List;
import java.util.Objects;

@CustomType
public final class GetAtCustomerCccInfrastructureInfrastructureNetworkConfigurationInfrastructureRoutingDynamic {
    /**
     * @return The topology in use for the Border Gateway Protocol (BGP) configuration.
     * 
     */
    private String bgpTopology;
    /**
     * @return The Oracle Autonomous System Number (ASN) to control routing and exchange information within the dynamic routing configuration.
     * 
     */
    private Integer oracleAsn;
    /**
     * @return The list of peer devices in the dynamic routing configuration.
     * 
     */
    private List<GetAtCustomerCccInfrastructureInfrastructureNetworkConfigurationInfrastructureRoutingDynamicPeerInformation> peerInformations;

    private GetAtCustomerCccInfrastructureInfrastructureNetworkConfigurationInfrastructureRoutingDynamic() {}
    /**
     * @return The topology in use for the Border Gateway Protocol (BGP) configuration.
     * 
     */
    public String bgpTopology() {
        return this.bgpTopology;
    }
    /**
     * @return The Oracle Autonomous System Number (ASN) to control routing and exchange information within the dynamic routing configuration.
     * 
     */
    public Integer oracleAsn() {
        return this.oracleAsn;
    }
    /**
     * @return The list of peer devices in the dynamic routing configuration.
     * 
     */
    public List<GetAtCustomerCccInfrastructureInfrastructureNetworkConfigurationInfrastructureRoutingDynamicPeerInformation> peerInformations() {
        return this.peerInformations;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetAtCustomerCccInfrastructureInfrastructureNetworkConfigurationInfrastructureRoutingDynamic defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String bgpTopology;
        private Integer oracleAsn;
        private List<GetAtCustomerCccInfrastructureInfrastructureNetworkConfigurationInfrastructureRoutingDynamicPeerInformation> peerInformations;
        public Builder() {}
        public Builder(GetAtCustomerCccInfrastructureInfrastructureNetworkConfigurationInfrastructureRoutingDynamic defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.bgpTopology = defaults.bgpTopology;
    	      this.oracleAsn = defaults.oracleAsn;
    	      this.peerInformations = defaults.peerInformations;
        }

        @CustomType.Setter
        public Builder bgpTopology(String bgpTopology) {
            if (bgpTopology == null) {
              throw new MissingRequiredPropertyException("GetAtCustomerCccInfrastructureInfrastructureNetworkConfigurationInfrastructureRoutingDynamic", "bgpTopology");
            }
            this.bgpTopology = bgpTopology;
            return this;
        }
        @CustomType.Setter
        public Builder oracleAsn(Integer oracleAsn) {
            if (oracleAsn == null) {
              throw new MissingRequiredPropertyException("GetAtCustomerCccInfrastructureInfrastructureNetworkConfigurationInfrastructureRoutingDynamic", "oracleAsn");
            }
            this.oracleAsn = oracleAsn;
            return this;
        }
        @CustomType.Setter
        public Builder peerInformations(List<GetAtCustomerCccInfrastructureInfrastructureNetworkConfigurationInfrastructureRoutingDynamicPeerInformation> peerInformations) {
            if (peerInformations == null) {
              throw new MissingRequiredPropertyException("GetAtCustomerCccInfrastructureInfrastructureNetworkConfigurationInfrastructureRoutingDynamic", "peerInformations");
            }
            this.peerInformations = peerInformations;
            return this;
        }
        public Builder peerInformations(GetAtCustomerCccInfrastructureInfrastructureNetworkConfigurationInfrastructureRoutingDynamicPeerInformation... peerInformations) {
            return peerInformations(List.of(peerInformations));
        }
        public GetAtCustomerCccInfrastructureInfrastructureNetworkConfigurationInfrastructureRoutingDynamic build() {
            final var _resultValue = new GetAtCustomerCccInfrastructureInfrastructureNetworkConfigurationInfrastructureRoutingDynamic();
            _resultValue.bgpTopology = bgpTopology;
            _resultValue.oracleAsn = oracleAsn;
            _resultValue.peerInformations = peerInformations;
            return _resultValue;
        }
    }
}
