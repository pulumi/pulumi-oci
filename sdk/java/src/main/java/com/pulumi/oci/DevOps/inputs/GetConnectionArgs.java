// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DevOps.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import java.lang.String;
import java.util.Objects;


public final class GetConnectionArgs extends com.pulumi.resources.InvokeArgs {

    public static final GetConnectionArgs Empty = new GetConnectionArgs();

    /**
     * Unique connection identifier.
     * 
     */
    @Import(name="connectionId", required=true)
    private Output<String> connectionId;

    /**
     * @return Unique connection identifier.
     * 
     */
    public Output<String> connectionId() {
        return this.connectionId;
    }

    private GetConnectionArgs() {}

    private GetConnectionArgs(GetConnectionArgs $) {
        this.connectionId = $.connectionId;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(GetConnectionArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private GetConnectionArgs $;

        public Builder() {
            $ = new GetConnectionArgs();
        }

        public Builder(GetConnectionArgs defaults) {
            $ = new GetConnectionArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param connectionId Unique connection identifier.
         * 
         * @return builder
         * 
         */
        public Builder connectionId(Output<String> connectionId) {
            $.connectionId = connectionId;
            return this;
        }

        /**
         * @param connectionId Unique connection identifier.
         * 
         * @return builder
         * 
         */
        public Builder connectionId(String connectionId) {
            return connectionId(Output.of(connectionId));
        }

        public GetConnectionArgs build() {
            $.connectionId = Objects.requireNonNull($.connectionId, "expected parameter 'connectionId' to be non-null");
            return $;
        }
    }

}