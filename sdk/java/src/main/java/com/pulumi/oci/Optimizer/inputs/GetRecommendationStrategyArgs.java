// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Optimizer.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import java.lang.Boolean;
import java.lang.String;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class GetRecommendationStrategyArgs extends com.pulumi.resources.InvokeArgs {

    public static final GetRecommendationStrategyArgs Empty = new GetRecommendationStrategyArgs();

    /**
     * The OCID of the compartment.
     * 
     */
    @Import(name="compartmentId", required=true)
    private Output<String> compartmentId;

    /**
     * @return The OCID of the compartment.
     * 
     */
    public Output<String> compartmentId() {
        return this.compartmentId;
    }

    /**
     * When set to true, the hierarchy of compartments is traversed and all compartments and subcompartments in the tenancy are returned depending on the the setting of `accessLevel`.
     * 
     */
    @Import(name="compartmentIdInSubtree", required=true)
    private Output<Boolean> compartmentIdInSubtree;

    /**
     * @return When set to true, the hierarchy of compartments is traversed and all compartments and subcompartments in the tenancy are returned depending on the the setting of `accessLevel`.
     * 
     */
    public Output<Boolean> compartmentIdInSubtree() {
        return this.compartmentIdInSubtree;
    }

    /**
     * Optional. A filter that returns results that match the name specified.
     * 
     */
    @Import(name="name")
    private @Nullable Output<String> name;

    /**
     * @return Optional. A filter that returns results that match the name specified.
     * 
     */
    public Optional<Output<String>> name() {
        return Optional.ofNullable(this.name);
    }

    /**
     * Optional. A filter that returns results that match the recommendation name specified.
     * 
     */
    @Import(name="recommendationName")
    private @Nullable Output<String> recommendationName;

    /**
     * @return Optional. A filter that returns results that match the recommendation name specified.
     * 
     */
    public Optional<Output<String>> recommendationName() {
        return Optional.ofNullable(this.recommendationName);
    }

    private GetRecommendationStrategyArgs() {}

    private GetRecommendationStrategyArgs(GetRecommendationStrategyArgs $) {
        this.compartmentId = $.compartmentId;
        this.compartmentIdInSubtree = $.compartmentIdInSubtree;
        this.name = $.name;
        this.recommendationName = $.recommendationName;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(GetRecommendationStrategyArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private GetRecommendationStrategyArgs $;

        public Builder() {
            $ = new GetRecommendationStrategyArgs();
        }

        public Builder(GetRecommendationStrategyArgs defaults) {
            $ = new GetRecommendationStrategyArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param compartmentId The OCID of the compartment.
         * 
         * @return builder
         * 
         */
        public Builder compartmentId(Output<String> compartmentId) {
            $.compartmentId = compartmentId;
            return this;
        }

        /**
         * @param compartmentId The OCID of the compartment.
         * 
         * @return builder
         * 
         */
        public Builder compartmentId(String compartmentId) {
            return compartmentId(Output.of(compartmentId));
        }

        /**
         * @param compartmentIdInSubtree When set to true, the hierarchy of compartments is traversed and all compartments and subcompartments in the tenancy are returned depending on the the setting of `accessLevel`.
         * 
         * @return builder
         * 
         */
        public Builder compartmentIdInSubtree(Output<Boolean> compartmentIdInSubtree) {
            $.compartmentIdInSubtree = compartmentIdInSubtree;
            return this;
        }

        /**
         * @param compartmentIdInSubtree When set to true, the hierarchy of compartments is traversed and all compartments and subcompartments in the tenancy are returned depending on the the setting of `accessLevel`.
         * 
         * @return builder
         * 
         */
        public Builder compartmentIdInSubtree(Boolean compartmentIdInSubtree) {
            return compartmentIdInSubtree(Output.of(compartmentIdInSubtree));
        }

        /**
         * @param name Optional. A filter that returns results that match the name specified.
         * 
         * @return builder
         * 
         */
        public Builder name(@Nullable Output<String> name) {
            $.name = name;
            return this;
        }

        /**
         * @param name Optional. A filter that returns results that match the name specified.
         * 
         * @return builder
         * 
         */
        public Builder name(String name) {
            return name(Output.of(name));
        }

        /**
         * @param recommendationName Optional. A filter that returns results that match the recommendation name specified.
         * 
         * @return builder
         * 
         */
        public Builder recommendationName(@Nullable Output<String> recommendationName) {
            $.recommendationName = recommendationName;
            return this;
        }

        /**
         * @param recommendationName Optional. A filter that returns results that match the recommendation name specified.
         * 
         * @return builder
         * 
         */
        public Builder recommendationName(String recommendationName) {
            return recommendationName(Output.of(recommendationName));
        }

        public GetRecommendationStrategyArgs build() {
            $.compartmentId = Objects.requireNonNull($.compartmentId, "expected parameter 'compartmentId' to be non-null");
            $.compartmentIdInSubtree = Objects.requireNonNull($.compartmentIdInSubtree, "expected parameter 'compartmentIdInSubtree' to be non-null");
            return $;
        }
    }

}