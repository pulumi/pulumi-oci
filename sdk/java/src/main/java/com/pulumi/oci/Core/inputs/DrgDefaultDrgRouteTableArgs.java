// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Core.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import java.lang.String;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class DrgDefaultDrgRouteTableArgs extends com.pulumi.resources.ResourceArgs {

    public static final DrgDefaultDrgRouteTableArgs Empty = new DrgDefaultDrgRouteTableArgs();

    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the default DRG route table assigned to DRG attachments of type IPSEC_TUNNEL on creation.
     * 
     */
    @Import(name="ipsecTunnel")
    private @Nullable Output<String> ipsecTunnel;

    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the default DRG route table assigned to DRG attachments of type IPSEC_TUNNEL on creation.
     * 
     */
    public Optional<Output<String>> ipsecTunnel() {
        return Optional.ofNullable(this.ipsecTunnel);
    }

    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the default DRG route table to be assigned to DRG attachments of type REMOTE_PEERING_CONNECTION on creation.
     * 
     */
    @Import(name="remotePeeringConnection")
    private @Nullable Output<String> remotePeeringConnection;

    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the default DRG route table to be assigned to DRG attachments of type REMOTE_PEERING_CONNECTION on creation.
     * 
     */
    public Optional<Output<String>> remotePeeringConnection() {
        return Optional.ofNullable(this.remotePeeringConnection);
    }

    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the default DRG route table to be assigned to DRG attachments of type VCN on creation.
     * 
     */
    @Import(name="vcn")
    private @Nullable Output<String> vcn;

    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the default DRG route table to be assigned to DRG attachments of type VCN on creation.
     * 
     */
    public Optional<Output<String>> vcn() {
        return Optional.ofNullable(this.vcn);
    }

    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the default DRG route table to be assigned to DRG attachments of type VIRTUAL_CIRCUIT on creation.
     * 
     */
    @Import(name="virtualCircuit")
    private @Nullable Output<String> virtualCircuit;

    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the default DRG route table to be assigned to DRG attachments of type VIRTUAL_CIRCUIT on creation.
     * 
     */
    public Optional<Output<String>> virtualCircuit() {
        return Optional.ofNullable(this.virtualCircuit);
    }

    private DrgDefaultDrgRouteTableArgs() {}

    private DrgDefaultDrgRouteTableArgs(DrgDefaultDrgRouteTableArgs $) {
        this.ipsecTunnel = $.ipsecTunnel;
        this.remotePeeringConnection = $.remotePeeringConnection;
        this.vcn = $.vcn;
        this.virtualCircuit = $.virtualCircuit;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(DrgDefaultDrgRouteTableArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private DrgDefaultDrgRouteTableArgs $;

        public Builder() {
            $ = new DrgDefaultDrgRouteTableArgs();
        }

        public Builder(DrgDefaultDrgRouteTableArgs defaults) {
            $ = new DrgDefaultDrgRouteTableArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param ipsecTunnel The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the default DRG route table assigned to DRG attachments of type IPSEC_TUNNEL on creation.
         * 
         * @return builder
         * 
         */
        public Builder ipsecTunnel(@Nullable Output<String> ipsecTunnel) {
            $.ipsecTunnel = ipsecTunnel;
            return this;
        }

        /**
         * @param ipsecTunnel The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the default DRG route table assigned to DRG attachments of type IPSEC_TUNNEL on creation.
         * 
         * @return builder
         * 
         */
        public Builder ipsecTunnel(String ipsecTunnel) {
            return ipsecTunnel(Output.of(ipsecTunnel));
        }

        /**
         * @param remotePeeringConnection The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the default DRG route table to be assigned to DRG attachments of type REMOTE_PEERING_CONNECTION on creation.
         * 
         * @return builder
         * 
         */
        public Builder remotePeeringConnection(@Nullable Output<String> remotePeeringConnection) {
            $.remotePeeringConnection = remotePeeringConnection;
            return this;
        }

        /**
         * @param remotePeeringConnection The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the default DRG route table to be assigned to DRG attachments of type REMOTE_PEERING_CONNECTION on creation.
         * 
         * @return builder
         * 
         */
        public Builder remotePeeringConnection(String remotePeeringConnection) {
            return remotePeeringConnection(Output.of(remotePeeringConnection));
        }

        /**
         * @param vcn The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the default DRG route table to be assigned to DRG attachments of type VCN on creation.
         * 
         * @return builder
         * 
         */
        public Builder vcn(@Nullable Output<String> vcn) {
            $.vcn = vcn;
            return this;
        }

        /**
         * @param vcn The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the default DRG route table to be assigned to DRG attachments of type VCN on creation.
         * 
         * @return builder
         * 
         */
        public Builder vcn(String vcn) {
            return vcn(Output.of(vcn));
        }

        /**
         * @param virtualCircuit The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the default DRG route table to be assigned to DRG attachments of type VIRTUAL_CIRCUIT on creation.
         * 
         * @return builder
         * 
         */
        public Builder virtualCircuit(@Nullable Output<String> virtualCircuit) {
            $.virtualCircuit = virtualCircuit;
            return this;
        }

        /**
         * @param virtualCircuit The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the default DRG route table to be assigned to DRG attachments of type VIRTUAL_CIRCUIT on creation.
         * 
         * @return builder
         * 
         */
        public Builder virtualCircuit(String virtualCircuit) {
            return virtualCircuit(Output.of(virtualCircuit));
        }

        public DrgDefaultDrgRouteTableArgs build() {
            return $;
        }
    }

}