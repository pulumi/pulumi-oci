// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Core.outputs;

import com.pulumi.core.annotations.CustomType;
import java.lang.String;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;

@CustomType
public final class DrgDefaultDrgRouteTable {
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the default DRG route table assigned to DRG attachments of type IPSEC_TUNNEL on creation.
     * 
     */
    private @Nullable String ipsecTunnel;
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the default DRG route table to be assigned to DRG attachments of type REMOTE_PEERING_CONNECTION on creation.
     * 
     */
    private @Nullable String remotePeeringConnection;
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the default DRG route table to be assigned to DRG attachments of type VCN on creation.
     * 
     */
    private @Nullable String vcn;
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the default DRG route table to be assigned to DRG attachments of type VIRTUAL_CIRCUIT on creation.
     * 
     */
    private @Nullable String virtualCircuit;

    private DrgDefaultDrgRouteTable() {}
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the default DRG route table assigned to DRG attachments of type IPSEC_TUNNEL on creation.
     * 
     */
    public Optional<String> ipsecTunnel() {
        return Optional.ofNullable(this.ipsecTunnel);
    }
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the default DRG route table to be assigned to DRG attachments of type REMOTE_PEERING_CONNECTION on creation.
     * 
     */
    public Optional<String> remotePeeringConnection() {
        return Optional.ofNullable(this.remotePeeringConnection);
    }
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the default DRG route table to be assigned to DRG attachments of type VCN on creation.
     * 
     */
    public Optional<String> vcn() {
        return Optional.ofNullable(this.vcn);
    }
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the default DRG route table to be assigned to DRG attachments of type VIRTUAL_CIRCUIT on creation.
     * 
     */
    public Optional<String> virtualCircuit() {
        return Optional.ofNullable(this.virtualCircuit);
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(DrgDefaultDrgRouteTable defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private @Nullable String ipsecTunnel;
        private @Nullable String remotePeeringConnection;
        private @Nullable String vcn;
        private @Nullable String virtualCircuit;
        public Builder() {}
        public Builder(DrgDefaultDrgRouteTable defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.ipsecTunnel = defaults.ipsecTunnel;
    	      this.remotePeeringConnection = defaults.remotePeeringConnection;
    	      this.vcn = defaults.vcn;
    	      this.virtualCircuit = defaults.virtualCircuit;
        }

        @CustomType.Setter
        public Builder ipsecTunnel(@Nullable String ipsecTunnel) {
            this.ipsecTunnel = ipsecTunnel;
            return this;
        }
        @CustomType.Setter
        public Builder remotePeeringConnection(@Nullable String remotePeeringConnection) {
            this.remotePeeringConnection = remotePeeringConnection;
            return this;
        }
        @CustomType.Setter
        public Builder vcn(@Nullable String vcn) {
            this.vcn = vcn;
            return this;
        }
        @CustomType.Setter
        public Builder virtualCircuit(@Nullable String virtualCircuit) {
            this.virtualCircuit = virtualCircuit;
            return this;
        }
        public DrgDefaultDrgRouteTable build() {
            final var o = new DrgDefaultDrgRouteTable();
            o.ipsecTunnel = ipsecTunnel;
            o.remotePeeringConnection = remotePeeringConnection;
            o.vcn = vcn;
            o.virtualCircuit = virtualCircuit;
            return o;
        }
    }
}