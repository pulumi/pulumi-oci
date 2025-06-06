// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.AiLanguage.inputs;

import com.pulumi.core.annotations.Import;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.AiLanguage.inputs.GetEndpointsFilter;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class GetEndpointsPlainArgs extends com.pulumi.resources.InvokeArgs {

    public static final GetEndpointsPlainArgs Empty = new GetEndpointsPlainArgs();

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

    /**
     * A filter to return only resources that match the entire display name given.
     * 
     */
    @Import(name="displayName")
    private @Nullable String displayName;

    /**
     * @return A filter to return only resources that match the entire display name given.
     * 
     */
    public Optional<String> displayName() {
        return Optional.ofNullable(this.displayName);
    }

    @Import(name="filters")
    private @Nullable List<GetEndpointsFilter> filters;

    public Optional<List<GetEndpointsFilter>> filters() {
        return Optional.ofNullable(this.filters);
    }

    /**
     * Unique identifier endpoint OCID of an endpoint that is immutable on creation.
     * 
     */
    @Import(name="id")
    private @Nullable String id;

    /**
     * @return Unique identifier endpoint OCID of an endpoint that is immutable on creation.
     * 
     */
    public Optional<String> id() {
        return Optional.ofNullable(this.id);
    }

    /**
     * The ID of the trained model for which to list the endpoints.
     * 
     */
    @Import(name="modelId")
    private @Nullable String modelId;

    /**
     * @return The ID of the trained model for which to list the endpoints.
     * 
     */
    public Optional<String> modelId() {
        return Optional.ofNullable(this.modelId);
    }

    /**
     * The ID of the project for which to list the objects.
     * 
     */
    @Import(name="projectId")
    private @Nullable String projectId;

    /**
     * @return The ID of the project for which to list the objects.
     * 
     */
    public Optional<String> projectId() {
        return Optional.ofNullable(this.projectId);
    }

    /**
     * &lt;b&gt;Filter&lt;/b&gt; results by the specified lifecycle state. Must be a valid state for the resource type.
     * 
     */
    @Import(name="state")
    private @Nullable String state;

    /**
     * @return &lt;b&gt;Filter&lt;/b&gt; results by the specified lifecycle state. Must be a valid state for the resource type.
     * 
     */
    public Optional<String> state() {
        return Optional.ofNullable(this.state);
    }

    private GetEndpointsPlainArgs() {}

    private GetEndpointsPlainArgs(GetEndpointsPlainArgs $) {
        this.compartmentId = $.compartmentId;
        this.displayName = $.displayName;
        this.filters = $.filters;
        this.id = $.id;
        this.modelId = $.modelId;
        this.projectId = $.projectId;
        this.state = $.state;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(GetEndpointsPlainArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private GetEndpointsPlainArgs $;

        public Builder() {
            $ = new GetEndpointsPlainArgs();
        }

        public Builder(GetEndpointsPlainArgs defaults) {
            $ = new GetEndpointsPlainArgs(Objects.requireNonNull(defaults));
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

        /**
         * @param displayName A filter to return only resources that match the entire display name given.
         * 
         * @return builder
         * 
         */
        public Builder displayName(@Nullable String displayName) {
            $.displayName = displayName;
            return this;
        }

        public Builder filters(@Nullable List<GetEndpointsFilter> filters) {
            $.filters = filters;
            return this;
        }

        public Builder filters(GetEndpointsFilter... filters) {
            return filters(List.of(filters));
        }

        /**
         * @param id Unique identifier endpoint OCID of an endpoint that is immutable on creation.
         * 
         * @return builder
         * 
         */
        public Builder id(@Nullable String id) {
            $.id = id;
            return this;
        }

        /**
         * @param modelId The ID of the trained model for which to list the endpoints.
         * 
         * @return builder
         * 
         */
        public Builder modelId(@Nullable String modelId) {
            $.modelId = modelId;
            return this;
        }

        /**
         * @param projectId The ID of the project for which to list the objects.
         * 
         * @return builder
         * 
         */
        public Builder projectId(@Nullable String projectId) {
            $.projectId = projectId;
            return this;
        }

        /**
         * @param state &lt;b&gt;Filter&lt;/b&gt; results by the specified lifecycle state. Must be a valid state for the resource type.
         * 
         * @return builder
         * 
         */
        public Builder state(@Nullable String state) {
            $.state = state;
            return this;
        }

        public GetEndpointsPlainArgs build() {
            if ($.compartmentId == null) {
                throw new MissingRequiredPropertyException("GetEndpointsPlainArgs", "compartmentId");
            }
            return $;
        }
    }

}
