// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Identity.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import java.lang.String;
import java.util.Objects;


public final class DomainsMyCustomerSecretKeyTagArgs extends com.pulumi.resources.ResourceArgs {

    public static final DomainsMyCustomerSecretKeyTagArgs Empty = new DomainsMyCustomerSecretKeyTagArgs();

    /**
     * Key or name of the tag.
     * 
     */
    @Import(name="key", required=true)
    private Output<String> key;

    /**
     * @return Key or name of the tag.
     * 
     */
    public Output<String> key() {
        return this.key;
    }

    /**
     * User&#39;s id
     * 
     */
    @Import(name="value", required=true)
    private Output<String> value;

    /**
     * @return User&#39;s id
     * 
     */
    public Output<String> value() {
        return this.value;
    }

    private DomainsMyCustomerSecretKeyTagArgs() {}

    private DomainsMyCustomerSecretKeyTagArgs(DomainsMyCustomerSecretKeyTagArgs $) {
        this.key = $.key;
        this.value = $.value;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(DomainsMyCustomerSecretKeyTagArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private DomainsMyCustomerSecretKeyTagArgs $;

        public Builder() {
            $ = new DomainsMyCustomerSecretKeyTagArgs();
        }

        public Builder(DomainsMyCustomerSecretKeyTagArgs defaults) {
            $ = new DomainsMyCustomerSecretKeyTagArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param key Key or name of the tag.
         * 
         * @return builder
         * 
         */
        public Builder key(Output<String> key) {
            $.key = key;
            return this;
        }

        /**
         * @param key Key or name of the tag.
         * 
         * @return builder
         * 
         */
        public Builder key(String key) {
            return key(Output.of(key));
        }

        /**
         * @param value User&#39;s id
         * 
         * @return builder
         * 
         */
        public Builder value(Output<String> value) {
            $.value = value;
            return this;
        }

        /**
         * @param value User&#39;s id
         * 
         * @return builder
         * 
         */
        public Builder value(String value) {
            return value(Output.of(value));
        }

        public DomainsMyCustomerSecretKeyTagArgs build() {
            $.key = Objects.requireNonNull($.key, "expected parameter 'key' to be non-null");
            $.value = Objects.requireNonNull($.value, "expected parameter 'value' to be non-null");
            return $;
        }
    }

}