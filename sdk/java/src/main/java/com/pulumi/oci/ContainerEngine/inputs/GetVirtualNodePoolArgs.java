// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.ContainerEngine.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.String;
import java.util.Objects;


public final class GetVirtualNodePoolArgs extends com.pulumi.resources.InvokeArgs {

    public static final GetVirtualNodePoolArgs Empty = new GetVirtualNodePoolArgs();

    /**
     * The OCID of the virtual node pool.
     * 
     */
    @Import(name="virtualNodePoolId", required=true)
    private Output<String> virtualNodePoolId;

    /**
     * @return The OCID of the virtual node pool.
     * 
     */
    public Output<String> virtualNodePoolId() {
        return this.virtualNodePoolId;
    }

    private GetVirtualNodePoolArgs() {}

    private GetVirtualNodePoolArgs(GetVirtualNodePoolArgs $) {
        this.virtualNodePoolId = $.virtualNodePoolId;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(GetVirtualNodePoolArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private GetVirtualNodePoolArgs $;

        public Builder() {
            $ = new GetVirtualNodePoolArgs();
        }

        public Builder(GetVirtualNodePoolArgs defaults) {
            $ = new GetVirtualNodePoolArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param virtualNodePoolId The OCID of the virtual node pool.
         * 
         * @return builder
         * 
         */
        public Builder virtualNodePoolId(Output<String> virtualNodePoolId) {
            $.virtualNodePoolId = virtualNodePoolId;
            return this;
        }

        /**
         * @param virtualNodePoolId The OCID of the virtual node pool.
         * 
         * @return builder
         * 
         */
        public Builder virtualNodePoolId(String virtualNodePoolId) {
            return virtualNodePoolId(Output.of(virtualNodePoolId));
        }

        public GetVirtualNodePoolArgs build() {
            if ($.virtualNodePoolId == null) {
                throw new MissingRequiredPropertyException("GetVirtualNodePoolArgs", "virtualNodePoolId");
            }
            return $;
        }
    }

}
