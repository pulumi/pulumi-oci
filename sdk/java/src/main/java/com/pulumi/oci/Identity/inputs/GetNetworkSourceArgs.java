// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Identity.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import java.lang.String;
import java.util.Objects;


public final class GetNetworkSourceArgs extends com.pulumi.resources.InvokeArgs {

    public static final GetNetworkSourceArgs Empty = new GetNetworkSourceArgs();

    /**
     * The OCID of the network source.
     * 
     */
    @Import(name="networkSourceId", required=true)
    private Output<String> networkSourceId;

    /**
     * @return The OCID of the network source.
     * 
     */
    public Output<String> networkSourceId() {
        return this.networkSourceId;
    }

    private GetNetworkSourceArgs() {}

    private GetNetworkSourceArgs(GetNetworkSourceArgs $) {
        this.networkSourceId = $.networkSourceId;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(GetNetworkSourceArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private GetNetworkSourceArgs $;

        public Builder() {
            $ = new GetNetworkSourceArgs();
        }

        public Builder(GetNetworkSourceArgs defaults) {
            $ = new GetNetworkSourceArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param networkSourceId The OCID of the network source.
         * 
         * @return builder
         * 
         */
        public Builder networkSourceId(Output<String> networkSourceId) {
            $.networkSourceId = networkSourceId;
            return this;
        }

        /**
         * @param networkSourceId The OCID of the network source.
         * 
         * @return builder
         * 
         */
        public Builder networkSourceId(String networkSourceId) {
            return networkSourceId(Output.of(networkSourceId));
        }

        public GetNetworkSourceArgs build() {
            $.networkSourceId = Objects.requireNonNull($.networkSourceId, "expected parameter 'networkSourceId' to be non-null");
            return $;
        }
    }

}