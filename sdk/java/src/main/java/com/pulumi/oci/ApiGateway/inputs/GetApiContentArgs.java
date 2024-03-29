// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.ApiGateway.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.String;
import java.util.Objects;


public final class GetApiContentArgs extends com.pulumi.resources.InvokeArgs {

    public static final GetApiContentArgs Empty = new GetApiContentArgs();

    /**
     * The ocid of the API.
     * 
     */
    @Import(name="apiId", required=true)
    private Output<String> apiId;

    /**
     * @return The ocid of the API.
     * 
     */
    public Output<String> apiId() {
        return this.apiId;
    }

    private GetApiContentArgs() {}

    private GetApiContentArgs(GetApiContentArgs $) {
        this.apiId = $.apiId;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(GetApiContentArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private GetApiContentArgs $;

        public Builder() {
            $ = new GetApiContentArgs();
        }

        public Builder(GetApiContentArgs defaults) {
            $ = new GetApiContentArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param apiId The ocid of the API.
         * 
         * @return builder
         * 
         */
        public Builder apiId(Output<String> apiId) {
            $.apiId = apiId;
            return this;
        }

        /**
         * @param apiId The ocid of the API.
         * 
         * @return builder
         * 
         */
        public Builder apiId(String apiId) {
            return apiId(Output.of(apiId));
        }

        public GetApiContentArgs build() {
            if ($.apiId == null) {
                throw new MissingRequiredPropertyException("GetApiContentArgs", "apiId");
            }
            return $;
        }
    }

}
