// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Identity.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import java.lang.String;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class DomainsMyApiKeyIdcsCreatedByArgs extends com.pulumi.resources.ResourceArgs {

    public static final DomainsMyApiKeyIdcsCreatedByArgs Empty = new DomainsMyApiKeyIdcsCreatedByArgs();

    /**
     * (Updatable) User display name
     * 
     */
    @Import(name="display")
    private @Nullable Output<String> display;

    /**
     * @return (Updatable) User display name
     * 
     */
    public Optional<Output<String>> display() {
        return Optional.ofNullable(this.display);
    }

    /**
     * User&#39;s ocid
     * 
     */
    @Import(name="ocid")
    private @Nullable Output<String> ocid;

    /**
     * @return User&#39;s ocid
     * 
     */
    public Optional<Output<String>> ocid() {
        return Optional.ofNullable(this.ocid);
    }

    /**
     * (Updatable) The URI that corresponds to the user linked to this credential
     * 
     */
    @Import(name="ref")
    private @Nullable Output<String> ref;

    /**
     * @return (Updatable) The URI that corresponds to the user linked to this credential
     * 
     */
    public Optional<Output<String>> ref() {
        return Optional.ofNullable(this.ref);
    }

    /**
     * The type of resource, User or App, that modified this Resource
     * 
     */
    @Import(name="type")
    private @Nullable Output<String> type;

    /**
     * @return The type of resource, User or App, that modified this Resource
     * 
     */
    public Optional<Output<String>> type() {
        return Optional.ofNullable(this.type);
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

    private DomainsMyApiKeyIdcsCreatedByArgs() {}

    private DomainsMyApiKeyIdcsCreatedByArgs(DomainsMyApiKeyIdcsCreatedByArgs $) {
        this.display = $.display;
        this.ocid = $.ocid;
        this.ref = $.ref;
        this.type = $.type;
        this.value = $.value;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(DomainsMyApiKeyIdcsCreatedByArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private DomainsMyApiKeyIdcsCreatedByArgs $;

        public Builder() {
            $ = new DomainsMyApiKeyIdcsCreatedByArgs();
        }

        public Builder(DomainsMyApiKeyIdcsCreatedByArgs defaults) {
            $ = new DomainsMyApiKeyIdcsCreatedByArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param display (Updatable) User display name
         * 
         * @return builder
         * 
         */
        public Builder display(@Nullable Output<String> display) {
            $.display = display;
            return this;
        }

        /**
         * @param display (Updatable) User display name
         * 
         * @return builder
         * 
         */
        public Builder display(String display) {
            return display(Output.of(display));
        }

        /**
         * @param ocid User&#39;s ocid
         * 
         * @return builder
         * 
         */
        public Builder ocid(@Nullable Output<String> ocid) {
            $.ocid = ocid;
            return this;
        }

        /**
         * @param ocid User&#39;s ocid
         * 
         * @return builder
         * 
         */
        public Builder ocid(String ocid) {
            return ocid(Output.of(ocid));
        }

        /**
         * @param ref (Updatable) The URI that corresponds to the user linked to this credential
         * 
         * @return builder
         * 
         */
        public Builder ref(@Nullable Output<String> ref) {
            $.ref = ref;
            return this;
        }

        /**
         * @param ref (Updatable) The URI that corresponds to the user linked to this credential
         * 
         * @return builder
         * 
         */
        public Builder ref(String ref) {
            return ref(Output.of(ref));
        }

        /**
         * @param type The type of resource, User or App, that modified this Resource
         * 
         * @return builder
         * 
         */
        public Builder type(@Nullable Output<String> type) {
            $.type = type;
            return this;
        }

        /**
         * @param type The type of resource, User or App, that modified this Resource
         * 
         * @return builder
         * 
         */
        public Builder type(String type) {
            return type(Output.of(type));
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

        public DomainsMyApiKeyIdcsCreatedByArgs build() {
            $.value = Objects.requireNonNull($.value, "expected parameter 'value' to be non-null");
            return $;
        }
    }

}