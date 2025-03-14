// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Blockchain.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.Blockchain.outputs.GetBlockchainPlatformComponentDetailPeerOcpuAllocationParam;
import java.lang.String;
import java.util.List;
import java.util.Objects;

@CustomType
public final class GetBlockchainPlatformComponentDetailPeer {
    /**
     * @return Availability Domain of peer
     * 
     */
    private String ad;
    /**
     * @return peer alias
     * 
     */
    private String alias;
    /**
     * @return Host name of VM
     * 
     */
    private String host;
    /**
     * @return OCPU allocation parameter
     * 
     */
    private List<GetBlockchainPlatformComponentDetailPeerOcpuAllocationParam> ocpuAllocationParams;
    /**
     * @return peer identifier
     * 
     */
    private String peerKey;
    /**
     * @return Peer role
     * 
     */
    private String role;
    /**
     * @return The current state of the Platform Instance.
     * 
     */
    private String state;

    private GetBlockchainPlatformComponentDetailPeer() {}
    /**
     * @return Availability Domain of peer
     * 
     */
    public String ad() {
        return this.ad;
    }
    /**
     * @return peer alias
     * 
     */
    public String alias() {
        return this.alias;
    }
    /**
     * @return Host name of VM
     * 
     */
    public String host() {
        return this.host;
    }
    /**
     * @return OCPU allocation parameter
     * 
     */
    public List<GetBlockchainPlatformComponentDetailPeerOcpuAllocationParam> ocpuAllocationParams() {
        return this.ocpuAllocationParams;
    }
    /**
     * @return peer identifier
     * 
     */
    public String peerKey() {
        return this.peerKey;
    }
    /**
     * @return Peer role
     * 
     */
    public String role() {
        return this.role;
    }
    /**
     * @return The current state of the Platform Instance.
     * 
     */
    public String state() {
        return this.state;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetBlockchainPlatformComponentDetailPeer defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String ad;
        private String alias;
        private String host;
        private List<GetBlockchainPlatformComponentDetailPeerOcpuAllocationParam> ocpuAllocationParams;
        private String peerKey;
        private String role;
        private String state;
        public Builder() {}
        public Builder(GetBlockchainPlatformComponentDetailPeer defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.ad = defaults.ad;
    	      this.alias = defaults.alias;
    	      this.host = defaults.host;
    	      this.ocpuAllocationParams = defaults.ocpuAllocationParams;
    	      this.peerKey = defaults.peerKey;
    	      this.role = defaults.role;
    	      this.state = defaults.state;
        }

        @CustomType.Setter
        public Builder ad(String ad) {
            if (ad == null) {
              throw new MissingRequiredPropertyException("GetBlockchainPlatformComponentDetailPeer", "ad");
            }
            this.ad = ad;
            return this;
        }
        @CustomType.Setter
        public Builder alias(String alias) {
            if (alias == null) {
              throw new MissingRequiredPropertyException("GetBlockchainPlatformComponentDetailPeer", "alias");
            }
            this.alias = alias;
            return this;
        }
        @CustomType.Setter
        public Builder host(String host) {
            if (host == null) {
              throw new MissingRequiredPropertyException("GetBlockchainPlatformComponentDetailPeer", "host");
            }
            this.host = host;
            return this;
        }
        @CustomType.Setter
        public Builder ocpuAllocationParams(List<GetBlockchainPlatformComponentDetailPeerOcpuAllocationParam> ocpuAllocationParams) {
            if (ocpuAllocationParams == null) {
              throw new MissingRequiredPropertyException("GetBlockchainPlatformComponentDetailPeer", "ocpuAllocationParams");
            }
            this.ocpuAllocationParams = ocpuAllocationParams;
            return this;
        }
        public Builder ocpuAllocationParams(GetBlockchainPlatformComponentDetailPeerOcpuAllocationParam... ocpuAllocationParams) {
            return ocpuAllocationParams(List.of(ocpuAllocationParams));
        }
        @CustomType.Setter
        public Builder peerKey(String peerKey) {
            if (peerKey == null) {
              throw new MissingRequiredPropertyException("GetBlockchainPlatformComponentDetailPeer", "peerKey");
            }
            this.peerKey = peerKey;
            return this;
        }
        @CustomType.Setter
        public Builder role(String role) {
            if (role == null) {
              throw new MissingRequiredPropertyException("GetBlockchainPlatformComponentDetailPeer", "role");
            }
            this.role = role;
            return this;
        }
        @CustomType.Setter
        public Builder state(String state) {
            if (state == null) {
              throw new MissingRequiredPropertyException("GetBlockchainPlatformComponentDetailPeer", "state");
            }
            this.state = state;
            return this;
        }
        public GetBlockchainPlatformComponentDetailPeer build() {
            final var _resultValue = new GetBlockchainPlatformComponentDetailPeer();
            _resultValue.ad = ad;
            _resultValue.alias = alias;
            _resultValue.host = host;
            _resultValue.ocpuAllocationParams = ocpuAllocationParams;
            _resultValue.peerKey = peerKey;
            _resultValue.role = role;
            _resultValue.state = state;
            return _resultValue;
        }
    }
}
