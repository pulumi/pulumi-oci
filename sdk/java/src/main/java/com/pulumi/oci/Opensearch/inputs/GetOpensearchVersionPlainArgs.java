// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Opensearch.inputs;

import com.pulumi.core.annotations.Import;
import java.lang.String;
import java.util.Objects;


public final class GetOpensearchVersionPlainArgs extends com.pulumi.resources.InvokeArgs {

    public static final GetOpensearchVersionPlainArgs Empty = new GetOpensearchVersionPlainArgs();

    /**
     * The ID of the compartment in which to list resources.
     * 
     */
    @Import(name="compartmentId", required=true)
    private String compartmentId;

    /**
     * @return The ID of the compartment in which to list resources.
     * 
     */
    public String compartmentId() {
        return this.compartmentId;
    }

    private GetOpensearchVersionPlainArgs() {}

    private GetOpensearchVersionPlainArgs(GetOpensearchVersionPlainArgs $) {
        this.compartmentId = $.compartmentId;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(GetOpensearchVersionPlainArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private GetOpensearchVersionPlainArgs $;

        public Builder() {
            $ = new GetOpensearchVersionPlainArgs();
        }

        public Builder(GetOpensearchVersionPlainArgs defaults) {
            $ = new GetOpensearchVersionPlainArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param compartmentId The ID of the compartment in which to list resources.
         * 
         * @return builder
         * 
         */
        public Builder compartmentId(String compartmentId) {
            $.compartmentId = compartmentId;
            return this;
        }

        public GetOpensearchVersionPlainArgs build() {
            $.compartmentId = Objects.requireNonNull($.compartmentId, "expected parameter 'compartmentId' to be non-null");
            return $;
        }
    }

}