// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.ServiceMesh.inputs;

import com.pulumi.core.annotations.Import;
import com.pulumi.oci.ServiceMesh.inputs.GetVirtualServicesFilter;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class GetVirtualServicesPlainArgs extends com.pulumi.resources.InvokeArgs {

    public static final GetVirtualServicesPlainArgs Empty = new GetVirtualServicesPlainArgs();

    /**
     * The ID of the compartment in which to list resources.
     * 
     */
    @Import(name="compartmentId", required=true)
    private String compartmentId;

    /**
     * @return The ID of the compartment in which to list resources.
     * 
     */
    public String compartmentId() {
        return this.compartmentId;
    }

    @Import(name="filters")
    private @Nullable List<GetVirtualServicesFilter> filters;

    public Optional<List<GetVirtualServicesFilter>> filters() {
        return Optional.ofNullable(this.filters);
    }

    /**
     * Unique VirtualService identifier.
     * 
     */
    @Import(name="id")
    private @Nullable String id;

    /**
     * @return Unique VirtualService identifier.
     * 
     */
    public Optional<String> id() {
        return Optional.ofNullable(this.id);
    }

    /**
     * Unique Mesh identifier.
     * 
     */
    @Import(name="meshId")
    private @Nullable String meshId;

    /**
     * @return Unique Mesh identifier.
     * 
     */
    public Optional<String> meshId() {
        return Optional.ofNullable(this.meshId);
    }

    /**
     * A filter to return only resources that match the entire name given.
     * 
     */
    @Import(name="name")
    private @Nullable String name;

    /**
     * @return A filter to return only resources that match the entire name given.
     * 
     */
    public Optional<String> name() {
        return Optional.ofNullable(this.name);
    }

    /**
     * A filter to return only resources that match the life cycle state given.
     * 
     */
    @Import(name="state")
    private @Nullable String state;

    /**
     * @return A filter to return only resources that match the life cycle state given.
     * 
     */
    public Optional<String> state() {
        return Optional.ofNullable(this.state);
    }

    private GetVirtualServicesPlainArgs() {}

    private GetVirtualServicesPlainArgs(GetVirtualServicesPlainArgs $) {
        this.compartmentId = $.compartmentId;
        this.filters = $.filters;
        this.id = $.id;
        this.meshId = $.meshId;
        this.name = $.name;
        this.state = $.state;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(GetVirtualServicesPlainArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private GetVirtualServicesPlainArgs $;

        public Builder() {
            $ = new GetVirtualServicesPlainArgs();
        }

        public Builder(GetVirtualServicesPlainArgs defaults) {
            $ = new GetVirtualServicesPlainArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param compartmentId The ID of the compartment in which to list resources.
         * 
         * @return builder
         * 
         */
        public Builder compartmentId(String compartmentId) {
            $.compartmentId = compartmentId;
            return this;
        }

        public Builder filters(@Nullable List<GetVirtualServicesFilter> filters) {
            $.filters = filters;
            return this;
        }

        public Builder filters(GetVirtualServicesFilter... filters) {
            return filters(List.of(filters));
        }

        /**
         * @param id Unique VirtualService identifier.
         * 
         * @return builder
         * 
         */
        public Builder id(@Nullable String id) {
            $.id = id;
            return this;
        }

        /**
         * @param meshId Unique Mesh identifier.
         * 
         * @return builder
         * 
         */
        public Builder meshId(@Nullable String meshId) {
            $.meshId = meshId;
            return this;
        }

        /**
         * @param name A filter to return only resources that match the entire name given.
         * 
         * @return builder
         * 
         */
        public Builder name(@Nullable String name) {
            $.name = name;
            return this;
        }

        /**
         * @param state A filter to return only resources that match the life cycle state given.
         * 
         * @return builder
         * 
         */
        public Builder state(@Nullable String state) {
            $.state = state;
            return this;
        }

        public GetVirtualServicesPlainArgs build() {
            $.compartmentId = Objects.requireNonNull($.compartmentId, "expected parameter 'compartmentId' to be non-null");
            return $;
        }
    }

}