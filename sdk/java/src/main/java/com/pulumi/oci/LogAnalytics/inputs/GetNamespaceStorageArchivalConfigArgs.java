// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.LogAnalytics.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.String;
import java.util.Objects;


public final class GetNamespaceStorageArchivalConfigArgs extends com.pulumi.resources.InvokeArgs {

    public static final GetNamespaceStorageArchivalConfigArgs Empty = new GetNamespaceStorageArchivalConfigArgs();

    /**
     * The Logging Analytics namespace used for the request.
     * 
     */
    @Import(name="namespace", required=true)
    private Output<String> namespace;

    /**
     * @return The Logging Analytics namespace used for the request.
     * 
     */
    public Output<String> namespace() {
        return this.namespace;
    }

    private GetNamespaceStorageArchivalConfigArgs() {}

    private GetNamespaceStorageArchivalConfigArgs(GetNamespaceStorageArchivalConfigArgs $) {
        this.namespace = $.namespace;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(GetNamespaceStorageArchivalConfigArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private GetNamespaceStorageArchivalConfigArgs $;

        public Builder() {
            $ = new GetNamespaceStorageArchivalConfigArgs();
        }

        public Builder(GetNamespaceStorageArchivalConfigArgs defaults) {
            $ = new GetNamespaceStorageArchivalConfigArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param namespace The Logging Analytics namespace used for the request.
         * 
         * @return builder
         * 
         */
        public Builder namespace(Output<String> namespace) {
            $.namespace = namespace;
            return this;
        }

        /**
         * @param namespace The Logging Analytics namespace used for the request.
         * 
         * @return builder
         * 
         */
        public Builder namespace(String namespace) {
            return namespace(Output.of(namespace));
        }

        public GetNamespaceStorageArchivalConfigArgs build() {
            if ($.namespace == null) {
                throw new MissingRequiredPropertyException("GetNamespaceStorageArchivalConfigArgs", "namespace");
            }
            return $;
        }
    }

}
