// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DatabaseManagement.inputs;

import com.pulumi.core.annotations.Import;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.DatabaseManagement.inputs.GetManagedDatabaseGroupsFilter;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class GetManagedDatabaseGroupsPlainArgs extends com.pulumi.resources.InvokeArgs {

    public static final GetManagedDatabaseGroupsPlainArgs Empty = new GetManagedDatabaseGroupsPlainArgs();

    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
     * 
     */
    @Import(name="compartmentId", required=true)
    private String compartmentId;

    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
     * 
     */
    public String compartmentId() {
        return this.compartmentId;
    }

    @Import(name="filters")
    private @Nullable List<GetManagedDatabaseGroupsFilter> filters;

    public Optional<List<GetManagedDatabaseGroupsFilter>> filters() {
        return Optional.ofNullable(this.filters);
    }

    /**
     * The identifier of the resource. Only one of the parameters, id or name should be provided.
     * 
     */
    @Import(name="id")
    private @Nullable String id;

    /**
     * @return The identifier of the resource. Only one of the parameters, id or name should be provided.
     * 
     */
    public Optional<String> id() {
        return Optional.ofNullable(this.id);
    }

    /**
     * A filter to return only resources that match the entire name. Only one of the parameters, id or name should be provided
     * 
     */
    @Import(name="name")
    private @Nullable String name;

    /**
     * @return A filter to return only resources that match the entire name. Only one of the parameters, id or name should be provided
     * 
     */
    public Optional<String> name() {
        return Optional.ofNullable(this.name);
    }

    /**
     * The lifecycle state of a resource.
     * 
     */
    @Import(name="state")
    private @Nullable String state;

    /**
     * @return The lifecycle state of a resource.
     * 
     */
    public Optional<String> state() {
        return Optional.ofNullable(this.state);
    }

    private GetManagedDatabaseGroupsPlainArgs() {}

    private GetManagedDatabaseGroupsPlainArgs(GetManagedDatabaseGroupsPlainArgs $) {
        this.compartmentId = $.compartmentId;
        this.filters = $.filters;
        this.id = $.id;
        this.name = $.name;
        this.state = $.state;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(GetManagedDatabaseGroupsPlainArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private GetManagedDatabaseGroupsPlainArgs $;

        public Builder() {
            $ = new GetManagedDatabaseGroupsPlainArgs();
        }

        public Builder(GetManagedDatabaseGroupsPlainArgs defaults) {
            $ = new GetManagedDatabaseGroupsPlainArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param compartmentId The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
         * 
         * @return builder
         * 
         */
        public Builder compartmentId(String compartmentId) {
            $.compartmentId = compartmentId;
            return this;
        }

        public Builder filters(@Nullable List<GetManagedDatabaseGroupsFilter> filters) {
            $.filters = filters;
            return this;
        }

        public Builder filters(GetManagedDatabaseGroupsFilter... filters) {
            return filters(List.of(filters));
        }

        /**
         * @param id The identifier of the resource. Only one of the parameters, id or name should be provided.
         * 
         * @return builder
         * 
         */
        public Builder id(@Nullable String id) {
            $.id = id;
            return this;
        }

        /**
         * @param name A filter to return only resources that match the entire name. Only one of the parameters, id or name should be provided
         * 
         * @return builder
         * 
         */
        public Builder name(@Nullable String name) {
            $.name = name;
            return this;
        }

        /**
         * @param state The lifecycle state of a resource.
         * 
         * @return builder
         * 
         */
        public Builder state(@Nullable String state) {
            $.state = state;
            return this;
        }

        public GetManagedDatabaseGroupsPlainArgs build() {
            if ($.compartmentId == null) {
                throw new MissingRequiredPropertyException("GetManagedDatabaseGroupsPlainArgs", "compartmentId");
            }
            return $;
        }
    }

}
