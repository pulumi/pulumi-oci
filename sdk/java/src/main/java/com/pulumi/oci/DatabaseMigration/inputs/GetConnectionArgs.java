// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DatabaseMigration.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.String;
import java.util.Objects;


public final class GetConnectionArgs extends com.pulumi.resources.InvokeArgs {

    public static final GetConnectionArgs Empty = new GetConnectionArgs();

    /**
     * The OCID of the database connection.
     * 
     */
    @Import(name="connectionId", required=true)
    private Output<String> connectionId;

    /**
     * @return The OCID of the database connection.
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
         * @param connectionId The OCID of the database connection.
         * 
         * @return builder
         * 
         */
        public Builder connectionId(Output<String> connectionId) {
            $.connectionId = connectionId;
            return this;
        }

        /**
         * @param connectionId The OCID of the database connection.
         * 
         * @return builder
         * 
         */
        public Builder connectionId(String connectionId) {
            return connectionId(Output.of(connectionId));
        }

        public GetConnectionArgs build() {
            if ($.connectionId == null) {
                throw new MissingRequiredPropertyException("GetConnectionArgs", "connectionId");
            }
            return $;
        }
    }

}
