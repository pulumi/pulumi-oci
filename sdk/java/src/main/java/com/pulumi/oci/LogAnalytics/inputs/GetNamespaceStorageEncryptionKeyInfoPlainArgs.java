// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.LogAnalytics.inputs;

import com.pulumi.core.annotations.Import;
import java.lang.String;
import java.util.Objects;


public final class GetNamespaceStorageEncryptionKeyInfoPlainArgs extends com.pulumi.resources.InvokeArgs {

    public static final GetNamespaceStorageEncryptionKeyInfoPlainArgs Empty = new GetNamespaceStorageEncryptionKeyInfoPlainArgs();

    /**
     * The Logging Analytics namespace used for the request.
     * 
     */
    @Import(name="namespace", required=true)
    private String namespace;

    /**
     * @return The Logging Analytics namespace used for the request.
     * 
     */
    public String namespace() {
        return this.namespace;
    }

    private GetNamespaceStorageEncryptionKeyInfoPlainArgs() {}

    private GetNamespaceStorageEncryptionKeyInfoPlainArgs(GetNamespaceStorageEncryptionKeyInfoPlainArgs $) {
        this.namespace = $.namespace;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(GetNamespaceStorageEncryptionKeyInfoPlainArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private GetNamespaceStorageEncryptionKeyInfoPlainArgs $;

        public Builder() {
            $ = new GetNamespaceStorageEncryptionKeyInfoPlainArgs();
        }

        public Builder(GetNamespaceStorageEncryptionKeyInfoPlainArgs defaults) {
            $ = new GetNamespaceStorageEncryptionKeyInfoPlainArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param namespace The Logging Analytics namespace used for the request.
         * 
         * @return builder
         * 
         */
        public Builder namespace(String namespace) {
            $.namespace = namespace;
            return this;
        }

        public GetNamespaceStorageEncryptionKeyInfoPlainArgs build() {
            $.namespace = Objects.requireNonNull($.namespace, "expected parameter 'namespace' to be non-null");
            return $;
        }
    }

}