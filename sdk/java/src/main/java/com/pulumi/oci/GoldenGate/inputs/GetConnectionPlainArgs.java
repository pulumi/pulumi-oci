// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.GoldenGate.inputs;

import com.pulumi.core.annotations.Import;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.String;
import java.util.Objects;


public final class GetConnectionPlainArgs extends com.pulumi.resources.InvokeArgs {

    public static final GetConnectionPlainArgs Empty = new GetConnectionPlainArgs();

    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of a Connection.
     * 
     */
    @Import(name="connectionId", required=true)
    private String connectionId;

    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of a Connection.
     * 
     */
    public String connectionId() {
        return this.connectionId;
    }

    private GetConnectionPlainArgs() {}

    private GetConnectionPlainArgs(GetConnectionPlainArgs $) {
        this.connectionId = $.connectionId;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(GetConnectionPlainArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private GetConnectionPlainArgs $;

        public Builder() {
            $ = new GetConnectionPlainArgs();
        }

        public Builder(GetConnectionPlainArgs defaults) {
            $ = new GetConnectionPlainArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param connectionId The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of a Connection.
         * 
         * @return builder
         * 
         */
        public Builder connectionId(String connectionId) {
            $.connectionId = connectionId;
            return this;
        }

        public GetConnectionPlainArgs build() {
            if ($.connectionId == null) {
                throw new MissingRequiredPropertyException("GetConnectionPlainArgs", "connectionId");
            }
            return $;
        }
    }

}
