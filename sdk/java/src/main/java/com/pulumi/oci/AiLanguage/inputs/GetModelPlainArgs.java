// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.AiLanguage.inputs;

import com.pulumi.core.annotations.Import;
import java.lang.String;
import java.util.Objects;


public final class GetModelPlainArgs extends com.pulumi.resources.InvokeArgs {

    public static final GetModelPlainArgs Empty = new GetModelPlainArgs();

    /**
     * Unique identifier model OCID of a model that is immutable on creation
     * 
     */
    @Import(name="id", required=true)
    private String id;

    /**
     * @return Unique identifier model OCID of a model that is immutable on creation
     * 
     */
    public String id() {
        return this.id;
    }

    private GetModelPlainArgs() {}

    private GetModelPlainArgs(GetModelPlainArgs $) {
        this.id = $.id;
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
         * @param id Unique identifier model OCID of a model that is immutable on creation
         * 
         * @return builder
         * 
         */
        public Builder id(String id) {
            $.id = id;
            return this;
        }

        public GetModelPlainArgs build() {
            $.id = Objects.requireNonNull($.id, "expected parameter 'id' to be non-null");
            return $;
        }
    }

}