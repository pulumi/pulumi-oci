// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Opa.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.String;
import java.util.Objects;


public final class GetOpaInstanceArgs extends com.pulumi.resources.InvokeArgs {

    public static final GetOpaInstanceArgs Empty = new GetOpaInstanceArgs();

    /**
     * unique OpaInstance identifier
     * 
     */
    @Import(name="opaInstanceId", required=true)
    private Output<String> opaInstanceId;

    /**
     * @return unique OpaInstance identifier
     * 
     */
    public Output<String> opaInstanceId() {
        return this.opaInstanceId;
    }

    private GetOpaInstanceArgs() {}

    private GetOpaInstanceArgs(GetOpaInstanceArgs $) {
        this.opaInstanceId = $.opaInstanceId;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(GetOpaInstanceArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private GetOpaInstanceArgs $;

        public Builder() {
            $ = new GetOpaInstanceArgs();
        }

        public Builder(GetOpaInstanceArgs defaults) {
            $ = new GetOpaInstanceArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param opaInstanceId unique OpaInstance identifier
         * 
         * @return builder
         * 
         */
        public Builder opaInstanceId(Output<String> opaInstanceId) {
            $.opaInstanceId = opaInstanceId;
            return this;
        }

        /**
         * @param opaInstanceId unique OpaInstance identifier
         * 
         * @return builder
         * 
         */
        public Builder opaInstanceId(String opaInstanceId) {
            return opaInstanceId(Output.of(opaInstanceId));
        }

        public GetOpaInstanceArgs build() {
            if ($.opaInstanceId == null) {
                throw new MissingRequiredPropertyException("GetOpaInstanceArgs", "opaInstanceId");
            }
            return $;
        }
    }

}
