// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DevOps.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import com.pulumi.oci.DevOps.inputs.GetBuildRunsFilterArgs;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class GetBuildRunsArgs extends com.pulumi.resources.InvokeArgs {

    public static final GetBuildRunsArgs Empty = new GetBuildRunsArgs();

    /**
     * Unique build pipeline identifier.
     * 
     */
    @Import(name="buildPipelineId")
    private @Nullable Output<String> buildPipelineId;

    /**
     * @return Unique build pipeline identifier.
     * 
     */
    public Optional<Output<String>> buildPipelineId() {
        return Optional.ofNullable(this.buildPipelineId);
    }

    /**
     * The OCID of the compartment in which to list resources.
     * 
     */
    @Import(name="compartmentId")
    private @Nullable Output<String> compartmentId;

    /**
     * @return The OCID of the compartment in which to list resources.
     * 
     */
    public Optional<Output<String>> compartmentId() {
        return Optional.ofNullable(this.compartmentId);
    }

    /**
     * A filter to return only resources that match the entire display name given.
     * 
     */
    @Import(name="displayName")
    private @Nullable Output<String> displayName;

    /**
     * @return A filter to return only resources that match the entire display name given.
     * 
     */
    public Optional<Output<String>> displayName() {
        return Optional.ofNullable(this.displayName);
    }

    /**
     * The filters for the trigger.
     * 
     */
    @Import(name="filters")
    private @Nullable Output<List<GetBuildRunsFilterArgs>> filters;

    /**
     * @return The filters for the trigger.
     * 
     */
    public Optional<Output<List<GetBuildRunsFilterArgs>>> filters() {
        return Optional.ofNullable(this.filters);
    }

    /**
     * Unique identifier or OCID for listing a single resource by ID.
     * 
     */
    @Import(name="id")
    private @Nullable Output<String> id;

    /**
     * @return Unique identifier or OCID for listing a single resource by ID.
     * 
     */
    public Optional<Output<String>> id() {
        return Optional.ofNullable(this.id);
    }

    /**
     * unique project identifier
     * 
     */
    @Import(name="projectId")
    private @Nullable Output<String> projectId;

    /**
     * @return unique project identifier
     * 
     */
    public Optional<Output<String>> projectId() {
        return Optional.ofNullable(this.projectId);
    }

    /**
     * A filter to return only build runs that matches the given lifecycle state.
     * 
     */
    @Import(name="state")
    private @Nullable Output<String> state;

    /**
     * @return A filter to return only build runs that matches the given lifecycle state.
     * 
     */
    public Optional<Output<String>> state() {
        return Optional.ofNullable(this.state);
    }

    private GetBuildRunsArgs() {}

    private GetBuildRunsArgs(GetBuildRunsArgs $) {
        this.buildPipelineId = $.buildPipelineId;
        this.compartmentId = $.compartmentId;
        this.displayName = $.displayName;
        this.filters = $.filters;
        this.id = $.id;
        this.projectId = $.projectId;
        this.state = $.state;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(GetBuildRunsArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private GetBuildRunsArgs $;

        public Builder() {
            $ = new GetBuildRunsArgs();
        }

        public Builder(GetBuildRunsArgs defaults) {
            $ = new GetBuildRunsArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param buildPipelineId Unique build pipeline identifier.
         * 
         * @return builder
         * 
         */
        public Builder buildPipelineId(@Nullable Output<String> buildPipelineId) {
            $.buildPipelineId = buildPipelineId;
            return this;
        }

        /**
         * @param buildPipelineId Unique build pipeline identifier.
         * 
         * @return builder
         * 
         */
        public Builder buildPipelineId(String buildPipelineId) {
            return buildPipelineId(Output.of(buildPipelineId));
        }

        /**
         * @param compartmentId The OCID of the compartment in which to list resources.
         * 
         * @return builder
         * 
         */
        public Builder compartmentId(@Nullable Output<String> compartmentId) {
            $.compartmentId = compartmentId;
            return this;
        }

        /**
         * @param compartmentId The OCID of the compartment in which to list resources.
         * 
         * @return builder
         * 
         */
        public Builder compartmentId(String compartmentId) {
            return compartmentId(Output.of(compartmentId));
        }

        /**
         * @param displayName A filter to return only resources that match the entire display name given.
         * 
         * @return builder
         * 
         */
        public Builder displayName(@Nullable Output<String> displayName) {
            $.displayName = displayName;
            return this;
        }

        /**
         * @param displayName A filter to return only resources that match the entire display name given.
         * 
         * @return builder
         * 
         */
        public Builder displayName(String displayName) {
            return displayName(Output.of(displayName));
        }

        /**
         * @param filters The filters for the trigger.
         * 
         * @return builder
         * 
         */
        public Builder filters(@Nullable Output<List<GetBuildRunsFilterArgs>> filters) {
            $.filters = filters;
            return this;
        }

        /**
         * @param filters The filters for the trigger.
         * 
         * @return builder
         * 
         */
        public Builder filters(List<GetBuildRunsFilterArgs> filters) {
            return filters(Output.of(filters));
        }

        /**
         * @param filters The filters for the trigger.
         * 
         * @return builder
         * 
         */
        public Builder filters(GetBuildRunsFilterArgs... filters) {
            return filters(List.of(filters));
        }

        /**
         * @param id Unique identifier or OCID for listing a single resource by ID.
         * 
         * @return builder
         * 
         */
        public Builder id(@Nullable Output<String> id) {
            $.id = id;
            return this;
        }

        /**
         * @param id Unique identifier or OCID for listing a single resource by ID.
         * 
         * @return builder
         * 
         */
        public Builder id(String id) {
            return id(Output.of(id));
        }

        /**
         * @param projectId unique project identifier
         * 
         * @return builder
         * 
         */
        public Builder projectId(@Nullable Output<String> projectId) {
            $.projectId = projectId;
            return this;
        }

        /**
         * @param projectId unique project identifier
         * 
         * @return builder
         * 
         */
        public Builder projectId(String projectId) {
            return projectId(Output.of(projectId));
        }

        /**
         * @param state A filter to return only build runs that matches the given lifecycle state.
         * 
         * @return builder
         * 
         */
        public Builder state(@Nullable Output<String> state) {
            $.state = state;
            return this;
        }

        /**
         * @param state A filter to return only build runs that matches the given lifecycle state.
         * 
         * @return builder
         * 
         */
        public Builder state(String state) {
            return state(Output.of(state));
        }

        public GetBuildRunsArgs build() {
            return $;
        }
    }

}