// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Core.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.String;
import java.util.Objects;


public final class GetVirtualCircuitArgs extends com.pulumi.resources.InvokeArgs {

    public static final GetVirtualCircuitArgs Empty = new GetVirtualCircuitArgs();

    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the virtual circuit.
     * 
     */
    @Import(name="virtualCircuitId", required=true)
    private Output<String> virtualCircuitId;

    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the virtual circuit.
     * 
     */
    public Output<String> virtualCircuitId() {
        return this.virtualCircuitId;
    }

    private GetVirtualCircuitArgs() {}

    private GetVirtualCircuitArgs(GetVirtualCircuitArgs $) {
        this.virtualCircuitId = $.virtualCircuitId;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(GetVirtualCircuitArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private GetVirtualCircuitArgs $;

        public Builder() {
            $ = new GetVirtualCircuitArgs();
        }

        public Builder(GetVirtualCircuitArgs defaults) {
            $ = new GetVirtualCircuitArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param virtualCircuitId The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the virtual circuit.
         * 
         * @return builder
         * 
         */
        public Builder virtualCircuitId(Output<String> virtualCircuitId) {
            $.virtualCircuitId = virtualCircuitId;
            return this;
        }

        /**
         * @param virtualCircuitId The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the virtual circuit.
         * 
         * @return builder
         * 
         */
        public Builder virtualCircuitId(String virtualCircuitId) {
            return virtualCircuitId(Output.of(virtualCircuitId));
        }

        public GetVirtualCircuitArgs build() {
            if ($.virtualCircuitId == null) {
                throw new MissingRequiredPropertyException("GetVirtualCircuitArgs", "virtualCircuitId");
            }
            return $;
        }
    }

}
