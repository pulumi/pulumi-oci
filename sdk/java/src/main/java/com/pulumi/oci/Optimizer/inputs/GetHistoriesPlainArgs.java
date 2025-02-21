// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Optimizer.inputs;

import com.pulumi.core.annotations.Import;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.Optimizer.inputs.GetHistoriesFilter;
import java.lang.Boolean;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class GetHistoriesPlainArgs extends com.pulumi.resources.InvokeArgs {

    public static final GetHistoriesPlainArgs Empty = new GetHistoriesPlainArgs();

    /**
     * The OCID of the compartment.
     * 
     */
    @Import(name="compartmentId", required=true)
    private String compartmentId;

    /**
     * @return The OCID of the compartment.
     * 
     */
    public String compartmentId() {
        return this.compartmentId;
    }

    /**
     * When set to true, the hierarchy of compartments is traversed and all compartments and subcompartments in the tenancy are returned depending on the the setting of `accessLevel`.
     * 
     * Can only be set to true when performing ListCompartments on the tenancy (root compartment).
     * 
     */
    @Import(name="compartmentIdInSubtree", required=true)
    private Boolean compartmentIdInSubtree;

    /**
     * @return When set to true, the hierarchy of compartments is traversed and all compartments and subcompartments in the tenancy are returned depending on the the setting of `accessLevel`.
     * 
     * Can only be set to true when performing ListCompartments on the tenancy (root compartment).
     * 
     */
    public Boolean compartmentIdInSubtree() {
        return this.compartmentIdInSubtree;
    }

    @Import(name="filters")
    private @Nullable List<GetHistoriesFilter> filters;

    public Optional<List<GetHistoriesFilter>> filters() {
        return Optional.ofNullable(this.filters);
    }

    /**
     * Supplement additional resource information in extended metadata response.
     * 
     */
    @Import(name="includeResourceMetadata")
    private @Nullable Boolean includeResourceMetadata;

    /**
     * @return Supplement additional resource information in extended metadata response.
     * 
     */
    public Optional<Boolean> includeResourceMetadata() {
        return Optional.ofNullable(this.includeResourceMetadata);
    }

    /**
     * Optional. A filter that returns results that match the name specified.
     * 
     */
    @Import(name="name")
    private @Nullable String name;

    /**
     * @return Optional. A filter that returns results that match the name specified.
     * 
     */
    public Optional<String> name() {
        return Optional.ofNullable(this.name);
    }

    /**
     * The unique OCID associated with the recommendation.
     * 
     */
    @Import(name="recommendationId")
    private @Nullable String recommendationId;

    /**
     * @return The unique OCID associated with the recommendation.
     * 
     */
    public Optional<String> recommendationId() {
        return Optional.ofNullable(this.recommendationId);
    }

    /**
     * Optional. A filter that returns results that match the recommendation name specified.
     * 
     */
    @Import(name="recommendationName")
    private @Nullable String recommendationName;

    /**
     * @return Optional. A filter that returns results that match the recommendation name specified.
     * 
     */
    public Optional<String> recommendationName() {
        return Optional.ofNullable(this.recommendationName);
    }

    /**
     * Optional. A filter that returns results that match the resource type specified.
     * 
     */
    @Import(name="resourceType")
    private @Nullable String resourceType;

    /**
     * @return Optional. A filter that returns results that match the resource type specified.
     * 
     */
    public Optional<String> resourceType() {
        return Optional.ofNullable(this.resourceType);
    }

    /**
     * A filter that returns results that match the lifecycle state specified.
     * 
     */
    @Import(name="state")
    private @Nullable String state;

    /**
     * @return A filter that returns results that match the lifecycle state specified.
     * 
     */
    public Optional<String> state() {
        return Optional.ofNullable(this.state);
    }

    /**
     * A filter that returns recommendations that match the status specified.
     * 
     */
    @Import(name="status")
    private @Nullable String status;

    /**
     * @return A filter that returns recommendations that match the status specified.
     * 
     */
    public Optional<String> status() {
        return Optional.ofNullable(this.status);
    }

    private GetHistoriesPlainArgs() {}

    private GetHistoriesPlainArgs(GetHistoriesPlainArgs $) {
        this.compartmentId = $.compartmentId;
        this.compartmentIdInSubtree = $.compartmentIdInSubtree;
        this.filters = $.filters;
        this.includeResourceMetadata = $.includeResourceMetadata;
        this.name = $.name;
        this.recommendationId = $.recommendationId;
        this.recommendationName = $.recommendationName;
        this.resourceType = $.resourceType;
        this.state = $.state;
        this.status = $.status;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(GetHistoriesPlainArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private GetHistoriesPlainArgs $;

        public Builder() {
            $ = new GetHistoriesPlainArgs();
        }

        public Builder(GetHistoriesPlainArgs defaults) {
            $ = new GetHistoriesPlainArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param compartmentId The OCID of the compartment.
         * 
         * @return builder
         * 
         */
        public Builder compartmentId(String compartmentId) {
            $.compartmentId = compartmentId;
            return this;
        }

        /**
         * @param compartmentIdInSubtree When set to true, the hierarchy of compartments is traversed and all compartments and subcompartments in the tenancy are returned depending on the the setting of `accessLevel`.
         * 
         * Can only be set to true when performing ListCompartments on the tenancy (root compartment).
         * 
         * @return builder
         * 
         */
        public Builder compartmentIdInSubtree(Boolean compartmentIdInSubtree) {
            $.compartmentIdInSubtree = compartmentIdInSubtree;
            return this;
        }

        public Builder filters(@Nullable List<GetHistoriesFilter> filters) {
            $.filters = filters;
            return this;
        }

        public Builder filters(GetHistoriesFilter... filters) {
            return filters(List.of(filters));
        }

        /**
         * @param includeResourceMetadata Supplement additional resource information in extended metadata response.
         * 
         * @return builder
         * 
         */
        public Builder includeResourceMetadata(@Nullable Boolean includeResourceMetadata) {
            $.includeResourceMetadata = includeResourceMetadata;
            return this;
        }

        /**
         * @param name Optional. A filter that returns results that match the name specified.
         * 
         * @return builder
         * 
         */
        public Builder name(@Nullable String name) {
            $.name = name;
            return this;
        }

        /**
         * @param recommendationId The unique OCID associated with the recommendation.
         * 
         * @return builder
         * 
         */
        public Builder recommendationId(@Nullable String recommendationId) {
            $.recommendationId = recommendationId;
            return this;
        }

        /**
         * @param recommendationName Optional. A filter that returns results that match the recommendation name specified.
         * 
         * @return builder
         * 
         */
        public Builder recommendationName(@Nullable String recommendationName) {
            $.recommendationName = recommendationName;
            return this;
        }

        /**
         * @param resourceType Optional. A filter that returns results that match the resource type specified.
         * 
         * @return builder
         * 
         */
        public Builder resourceType(@Nullable String resourceType) {
            $.resourceType = resourceType;
            return this;
        }

        /**
         * @param state A filter that returns results that match the lifecycle state specified.
         * 
         * @return builder
         * 
         */
        public Builder state(@Nullable String state) {
            $.state = state;
            return this;
        }

        /**
         * @param status A filter that returns recommendations that match the status specified.
         * 
         * @return builder
         * 
         */
        public Builder status(@Nullable String status) {
            $.status = status;
            return this;
        }

        public GetHistoriesPlainArgs build() {
            if ($.compartmentId == null) {
                throw new MissingRequiredPropertyException("GetHistoriesPlainArgs", "compartmentId");
            }
            if ($.compartmentIdInSubtree == null) {
                throw new MissingRequiredPropertyException("GetHistoriesPlainArgs", "compartmentIdInSubtree");
            }
            return $;
        }
    }

}
