// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.ServiceMesh.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import java.lang.String;
import java.util.Objects;


public final class GetVirtualServiceRouteTableArgs extends com.pulumi.resources.InvokeArgs {

    public static final GetVirtualServiceRouteTableArgs Empty = new GetVirtualServiceRouteTableArgs();

    /**
     * Unique VirtualServiceRouteTable identifier.
     * 
     */
    @Import(name="virtualServiceRouteTableId", required=true)
    private Output<String> virtualServiceRouteTableId;

    /**
     * @return Unique VirtualServiceRouteTable identifier.
     * 
     */
    public Output<String> virtualServiceRouteTableId() {
        return this.virtualServiceRouteTableId;
    }

    private GetVirtualServiceRouteTableArgs() {}

    private GetVirtualServiceRouteTableArgs(GetVirtualServiceRouteTableArgs $) {
        this.virtualServiceRouteTableId = $.virtualServiceRouteTableId;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(GetVirtualServiceRouteTableArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private GetVirtualServiceRouteTableArgs $;

        public Builder() {
            $ = new GetVirtualServiceRouteTableArgs();
        }

        public Builder(GetVirtualServiceRouteTableArgs defaults) {
            $ = new GetVirtualServiceRouteTableArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param virtualServiceRouteTableId Unique VirtualServiceRouteTable identifier.
         * 
         * @return builder
         * 
         */
        public Builder virtualServiceRouteTableId(Output<String> virtualServiceRouteTableId) {
            $.virtualServiceRouteTableId = virtualServiceRouteTableId;
            return this;
        }

        /**
         * @param virtualServiceRouteTableId Unique VirtualServiceRouteTable identifier.
         * 
         * @return builder
         * 
         */
        public Builder virtualServiceRouteTableId(String virtualServiceRouteTableId) {
            return virtualServiceRouteTableId(Output.of(virtualServiceRouteTableId));
        }

        public GetVirtualServiceRouteTableArgs build() {
            $.virtualServiceRouteTableId = Objects.requireNonNull($.virtualServiceRouteTableId, "expected parameter 'virtualServiceRouteTableId' to be non-null");
            return $;
        }
    }

}