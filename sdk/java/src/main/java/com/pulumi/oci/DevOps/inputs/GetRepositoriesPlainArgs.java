// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DevOps.inputs;

import com.pulumi.core.annotations.Import;
import com.pulumi.oci.DevOps.inputs.GetRepositoriesFilter;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class GetRepositoriesPlainArgs extends com.pulumi.resources.InvokeArgs {

    public static final GetRepositoriesPlainArgs Empty = new GetRepositoriesPlainArgs();

    /**
     * The OCID of the compartment in which to list resources.
     * 
     */
    @Import(name="compartmentId")
    private @Nullable String compartmentId;

    /**
     * @return The OCID of the compartment in which to list resources.
     * 
     */
    public Optional<String> compartmentId() {
        return Optional.ofNullable(this.compartmentId);
    }

    @Import(name="filters")
    private @Nullable List<GetRepositoriesFilter> filters;

    public Optional<List<GetRepositoriesFilter>> filters() {
        return Optional.ofNullable(this.filters);
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
     * unique project identifier
     * 
     */
    @Import(name="projectId")
    private @Nullable String projectId;

    /**
     * @return unique project identifier
     * 
     */
    public Optional<String> projectId() {
        return Optional.ofNullable(this.projectId);
    }

    /**
     * Unique repository identifier.
     * 
     */
    @Import(name="repositoryId")
    private @Nullable String repositoryId;

    /**
     * @return Unique repository identifier.
     * 
     */
    public Optional<String> repositoryId() {
        return Optional.ofNullable(this.repositoryId);
    }

    /**
     * A filter to return only resources whose lifecycle state matches the given lifecycle state.
     * 
     */
    @Import(name="state")
    private @Nullable String state;

    /**
     * @return A filter to return only resources whose lifecycle state matches the given lifecycle state.
     * 
     */
    public Optional<String> state() {
        return Optional.ofNullable(this.state);
    }

    private GetRepositoriesPlainArgs() {}

    private GetRepositoriesPlainArgs(GetRepositoriesPlainArgs $) {
        this.compartmentId = $.compartmentId;
        this.filters = $.filters;
        this.name = $.name;
        this.projectId = $.projectId;
        this.repositoryId = $.repositoryId;
        this.state = $.state;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(GetRepositoriesPlainArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private GetRepositoriesPlainArgs $;

        public Builder() {
            $ = new GetRepositoriesPlainArgs();
        }

        public Builder(GetRepositoriesPlainArgs defaults) {
            $ = new GetRepositoriesPlainArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param compartmentId The OCID of the compartment in which to list resources.
         * 
         * @return builder
         * 
         */
        public Builder compartmentId(@Nullable String compartmentId) {
            $.compartmentId = compartmentId;
            return this;
        }

        public Builder filters(@Nullable List<GetRepositoriesFilter> filters) {
            $.filters = filters;
            return this;
        }

        public Builder filters(GetRepositoriesFilter... filters) {
            return filters(List.of(filters));
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
         * @param projectId unique project identifier
         * 
         * @return builder
         * 
         */
        public Builder projectId(@Nullable String projectId) {
            $.projectId = projectId;
            return this;
        }

        /**
         * @param repositoryId Unique repository identifier.
         * 
         * @return builder
         * 
         */
        public Builder repositoryId(@Nullable String repositoryId) {
            $.repositoryId = repositoryId;
            return this;
        }

        /**
         * @param state A filter to return only resources whose lifecycle state matches the given lifecycle state.
         * 
         * @return builder
         * 
         */
        public Builder state(@Nullable String state) {
            $.state = state;
            return this;
        }

        public GetRepositoriesPlainArgs build() {
            return $;
        }
    }

}