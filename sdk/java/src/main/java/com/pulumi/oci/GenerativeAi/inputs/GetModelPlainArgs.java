// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.GenerativeAi.inputs;

import com.pulumi.core.annotations.Import;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.String;
import java.util.Objects;


public final class GetModelPlainArgs extends com.pulumi.resources.InvokeArgs {

    public static final GetModelPlainArgs Empty = new GetModelPlainArgs();

    /**
     * The model OCID
     * 
     */
    @Import(name="modelId", required=true)
    private String modelId;

    /**
     * @return The model OCID
     * 
     */
    public String modelId() {
        return this.modelId;
    }

    private GetModelPlainArgs() {}

    private GetModelPlainArgs(GetModelPlainArgs $) {
        this.modelId = $.modelId;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(GetModelPlainArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private GetModelPlainArgs $;

        public Builder() {
            $ = new GetModelPlainArgs();
        }

        public Builder(GetModelPlainArgs defaults) {
            $ = new GetModelPlainArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param modelId The model OCID
         * 
         * @return builder
         * 
         */
        public Builder modelId(String modelId) {
            $.modelId = modelId;
            return this;
        }

        public GetModelPlainArgs build() {
            if ($.modelId == null) {
                throw new MissingRequiredPropertyException("GetModelPlainArgs", "modelId");
            }
            return $;
        }
    }

}
