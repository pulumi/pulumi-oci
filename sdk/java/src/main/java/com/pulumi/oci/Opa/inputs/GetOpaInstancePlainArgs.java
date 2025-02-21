// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Opa.inputs;

import com.pulumi.core.annotations.Import;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.String;
import java.util.Objects;


public final class GetOpaInstancePlainArgs extends com.pulumi.resources.InvokeArgs {

    public static final GetOpaInstancePlainArgs Empty = new GetOpaInstancePlainArgs();

    /**
     * unique OpaInstance identifier
     * 
     */
    @Import(name="opaInstanceId", required=true)
    private String opaInstanceId;

    /**
     * @return unique OpaInstance identifier
     * 
     */
    public String opaInstanceId() {
        return this.opaInstanceId;
    }

    private GetOpaInstancePlainArgs() {}

    private GetOpaInstancePlainArgs(GetOpaInstancePlainArgs $) {
        this.opaInstanceId = $.opaInstanceId;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(GetOpaInstancePlainArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private GetOpaInstancePlainArgs $;

        public Builder() {
            $ = new GetOpaInstancePlainArgs();
        }

        public Builder(GetOpaInstancePlainArgs defaults) {
            $ = new GetOpaInstancePlainArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param opaInstanceId unique OpaInstance identifier
         * 
         * @return builder
         * 
         */
        public Builder opaInstanceId(String opaInstanceId) {
            $.opaInstanceId = opaInstanceId;
            return this;
        }

        public GetOpaInstancePlainArgs build() {
            if ($.opaInstanceId == null) {
                throw new MissingRequiredPropertyException("GetOpaInstancePlainArgs", "opaInstanceId");
            }
            return $;
        }
    }

}
