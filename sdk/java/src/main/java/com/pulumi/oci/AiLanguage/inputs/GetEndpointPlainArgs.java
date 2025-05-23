// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.AiLanguage.inputs;

import com.pulumi.core.annotations.Import;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.String;
import java.util.Objects;


public final class GetEndpointPlainArgs extends com.pulumi.resources.InvokeArgs {

    public static final GetEndpointPlainArgs Empty = new GetEndpointPlainArgs();

    /**
     * Unique identifier endpoint OCID of an endpoint that is immutable on creation.
     * 
     */
    @Import(name="id", required=true)
    private String id;

    /**
     * @return Unique identifier endpoint OCID of an endpoint that is immutable on creation.
     * 
     */
    public String id() {
        return this.id;
    }

    private GetEndpointPlainArgs() {}

    private GetEndpointPlainArgs(GetEndpointPlainArgs $) {
        this.id = $.id;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(GetEndpointPlainArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private GetEndpointPlainArgs $;

        public Builder() {
            $ = new GetEndpointPlainArgs();
        }

        public Builder(GetEndpointPlainArgs defaults) {
            $ = new GetEndpointPlainArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param id Unique identifier endpoint OCID of an endpoint that is immutable on creation.
         * 
         * @return builder
         * 
         */
        public Builder id(String id) {
            $.id = id;
            return this;
        }

        public GetEndpointPlainArgs build() {
            if ($.id == null) {
                throw new MissingRequiredPropertyException("GetEndpointPlainArgs", "id");
            }
            return $;
        }
    }

}
