// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Identity.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import java.lang.String;
import java.util.Objects;


public final class DomainsGroupUrnietfparamsscimschemasoracleidcsextensionOciTagsDefinedTagArgs extends com.pulumi.resources.ResourceArgs {

    public static final DomainsGroupUrnietfparamsscimschemasoracleidcsextensionOciTagsDefinedTagArgs Empty = new DomainsGroupUrnietfparamsscimschemasoracleidcsextensionOciTagsDefinedTagArgs();

    /**
     * (Updatable) Oracle Cloud Infrastructure Tag key
     * 
     */
    @Import(name="key", required=true)
    private Output<String> key;

    /**
     * @return (Updatable) Oracle Cloud Infrastructure Tag key
     * 
     */
    public Output<String> key() {
        return this.key;
    }

    /**
     * (Updatable) Oracle Cloud Infrastructure Tag namespace
     * 
     */
    @Import(name="namespace", required=true)
    private Output<String> namespace;

    /**
     * @return (Updatable) Oracle Cloud Infrastructure Tag namespace
     * 
     */
    public Output<String> namespace() {
        return this.namespace;
    }

    /**
     * (Updatable) The ID of the App.
     * 
     */
    @Import(name="value", required=true)
    private Output<String> value;

    /**
     * @return (Updatable) The ID of the App.
     * 
     */
    public Output<String> value() {
        return this.value;
    }

    private DomainsGroupUrnietfparamsscimschemasoracleidcsextensionOciTagsDefinedTagArgs() {}

    private DomainsGroupUrnietfparamsscimschemasoracleidcsextensionOciTagsDefinedTagArgs(DomainsGroupUrnietfparamsscimschemasoracleidcsextensionOciTagsDefinedTagArgs $) {
        this.key = $.key;
        this.namespace = $.namespace;
        this.value = $.value;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(DomainsGroupUrnietfparamsscimschemasoracleidcsextensionOciTagsDefinedTagArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private DomainsGroupUrnietfparamsscimschemasoracleidcsextensionOciTagsDefinedTagArgs $;

        public Builder() {
            $ = new DomainsGroupUrnietfparamsscimschemasoracleidcsextensionOciTagsDefinedTagArgs();
        }

        public Builder(DomainsGroupUrnietfparamsscimschemasoracleidcsextensionOciTagsDefinedTagArgs defaults) {
            $ = new DomainsGroupUrnietfparamsscimschemasoracleidcsextensionOciTagsDefinedTagArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param key (Updatable) Oracle Cloud Infrastructure Tag key
         * 
         * @return builder
         * 
         */
        public Builder key(Output<String> key) {
            $.key = key;
            return this;
        }

        /**
         * @param key (Updatable) Oracle Cloud Infrastructure Tag key
         * 
         * @return builder
         * 
         */
        public Builder key(String key) {
            return key(Output.of(key));
        }

        /**
         * @param namespace (Updatable) Oracle Cloud Infrastructure Tag namespace
         * 
         * @return builder
         * 
         */
        public Builder namespace(Output<String> namespace) {
            $.namespace = namespace;
            return this;
        }

        /**
         * @param namespace (Updatable) Oracle Cloud Infrastructure Tag namespace
         * 
         * @return builder
         * 
         */
        public Builder namespace(String namespace) {
            return namespace(Output.of(namespace));
        }

        /**
         * @param value (Updatable) The ID of the App.
         * 
         * @return builder
         * 
         */
        public Builder value(Output<String> value) {
            $.value = value;
            return this;
        }

        /**
         * @param value (Updatable) The ID of the App.
         * 
         * @return builder
         * 
         */
        public Builder value(String value) {
            return value(Output.of(value));
        }

        public DomainsGroupUrnietfparamsscimschemasoracleidcsextensionOciTagsDefinedTagArgs build() {
            $.key = Objects.requireNonNull($.key, "expected parameter 'key' to be non-null");
            $.namespace = Objects.requireNonNull($.namespace, "expected parameter 'namespace' to be non-null");
            $.value = Objects.requireNonNull($.value, "expected parameter 'value' to be non-null");
            return $;
        }
    }

}