// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Database.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import java.lang.String;
import java.util.Objects;


public final class GetVmClusterNetworkArgs extends com.pulumi.resources.InvokeArgs {

    public static final GetVmClusterNetworkArgs Empty = new GetVmClusterNetworkArgs();

    /**
     * The Exadata infrastructure [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
     * 
     */
    @Import(name="exadataInfrastructureId", required=true)
    private Output<String> exadataInfrastructureId;

    /**
     * @return The Exadata infrastructure [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
     * 
     */
    public Output<String> exadataInfrastructureId() {
        return this.exadataInfrastructureId;
    }

    /**
     * The VM cluster network [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
     * 
     */
    @Import(name="vmClusterNetworkId", required=true)
    private Output<String> vmClusterNetworkId;

    /**
     * @return The VM cluster network [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
     * 
     */
    public Output<String> vmClusterNetworkId() {
        return this.vmClusterNetworkId;
    }

    private GetVmClusterNetworkArgs() {}

    private GetVmClusterNetworkArgs(GetVmClusterNetworkArgs $) {
        this.exadataInfrastructureId = $.exadataInfrastructureId;
        this.vmClusterNetworkId = $.vmClusterNetworkId;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(GetVmClusterNetworkArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private GetVmClusterNetworkArgs $;

        public Builder() {
            $ = new GetVmClusterNetworkArgs();
        }

        public Builder(GetVmClusterNetworkArgs defaults) {
            $ = new GetVmClusterNetworkArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param exadataInfrastructureId The Exadata infrastructure [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
         * 
         * @return builder
         * 
         */
        public Builder exadataInfrastructureId(Output<String> exadataInfrastructureId) {
            $.exadataInfrastructureId = exadataInfrastructureId;
            return this;
        }

        /**
         * @param exadataInfrastructureId The Exadata infrastructure [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
         * 
         * @return builder
         * 
         */
        public Builder exadataInfrastructureId(String exadataInfrastructureId) {
            return exadataInfrastructureId(Output.of(exadataInfrastructureId));
        }

        /**
         * @param vmClusterNetworkId The VM cluster network [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
         * 
         * @return builder
         * 
         */
        public Builder vmClusterNetworkId(Output<String> vmClusterNetworkId) {
            $.vmClusterNetworkId = vmClusterNetworkId;
            return this;
        }

        /**
         * @param vmClusterNetworkId The VM cluster network [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
         * 
         * @return builder
         * 
         */
        public Builder vmClusterNetworkId(String vmClusterNetworkId) {
            return vmClusterNetworkId(Output.of(vmClusterNetworkId));
        }

        public GetVmClusterNetworkArgs build() {
            $.exadataInfrastructureId = Objects.requireNonNull($.exadataInfrastructureId, "expected parameter 'exadataInfrastructureId' to be non-null");
            $.vmClusterNetworkId = Objects.requireNonNull($.vmClusterNetworkId, "expected parameter 'vmClusterNetworkId' to be non-null");
            return $;
        }
    }

}