// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Dns.inputs;

import com.pulumi.core.annotations.Import;
import com.pulumi.oci.Dns.inputs.GetTsigKeysFilter;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class GetTsigKeysPlainArgs extends com.pulumi.resources.InvokeArgs {

    public static final GetTsigKeysPlainArgs Empty = new GetTsigKeysPlainArgs();

    /**
     * The OCID of the compartment the resource belongs to.
     * 
     */
    @Import(name="compartmentId", required=true)
    private String compartmentId;

    /**
     * @return The OCID of the compartment the resource belongs to.
     * 
     */
    public String compartmentId() {
        return this.compartmentId;
    }

    @Import(name="filters")
    private @Nullable List<GetTsigKeysFilter> filters;

    public Optional<List<GetTsigKeysFilter>> filters() {
        return Optional.ofNullable(this.filters);
    }

    /**
     * The OCID of a resource.
     * 
     */
    @Import(name="id")
    private @Nullable String id;

    /**
     * @return The OCID of a resource.
     * 
     */
    public Optional<String> id() {
        return Optional.ofNullable(this.id);
    }

    /**
     * The name of a resource.
     * 
     */
    @Import(name="name")
    private @Nullable String name;

    /**
     * @return The name of a resource.
     * 
     */
    public Optional<String> name() {
        return Optional.ofNullable(this.name);
    }

    /**
     * The state of a resource.
     * 
     */
    @Import(name="state")
    private @Nullable String state;

    /**
     * @return The state of a resource.
     * 
     */
    public Optional<String> state() {
        return Optional.ofNullable(this.state);
    }

    private GetTsigKeysPlainArgs() {}

    private GetTsigKeysPlainArgs(GetTsigKeysPlainArgs $) {
        this.compartmentId = $.compartmentId;
        this.filters = $.filters;
        this.id = $.id;
        this.name = $.name;
        this.state = $.state;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(GetTsigKeysPlainArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private GetTsigKeysPlainArgs $;

        public Builder() {
            $ = new GetTsigKeysPlainArgs();
        }

        public Builder(GetTsigKeysPlainArgs defaults) {
            $ = new GetTsigKeysPlainArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param compartmentId The OCID of the compartment the resource belongs to.
         * 
         * @return builder
         * 
         */
        public Builder compartmentId(String compartmentId) {
            $.compartmentId = compartmentId;
            return this;
        }

        public Builder filters(@Nullable List<GetTsigKeysFilter> filters) {
            $.filters = filters;
            return this;
        }

        public Builder filters(GetTsigKeysFilter... filters) {
            return filters(List.of(filters));
        }

        /**
         * @param id The OCID of a resource.
         * 
         * @return builder
         * 
         */
        public Builder id(@Nullable String id) {
            $.id = id;
            return this;
        }

        /**
         * @param name The name of a resource.
         * 
         * @return builder
         * 
         */
        public Builder name(@Nullable String name) {
            $.name = name;
            return this;
        }

        /**
         * @param state The state of a resource.
         * 
         * @return builder
         * 
         */
        public Builder state(@Nullable String state) {
            $.state = state;
            return this;
        }

        public GetTsigKeysPlainArgs build() {
            $.compartmentId = Objects.requireNonNull($.compartmentId, "expected parameter 'compartmentId' to be non-null");
            return $;
        }
    }

}