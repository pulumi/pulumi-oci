// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Optimizer.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.oci.Optimizer.outputs.GetRecommendationStrategyItem;
import java.lang.Boolean;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;

@CustomType
public final class GetRecommendationStrategyResult {
    private String compartmentId;
    private Boolean compartmentIdInSubtree;
    /**
     * @return The provider-assigned unique ID for this managed resource.
     * 
     */
    private String id;
    /**
     * @return A collection of recommendation strategy summaries.
     * 
     */
    private List<GetRecommendationStrategyItem> items;
    /**
     * @return The name of the strategy parameter.
     * 
     */
    private @Nullable String name;
    private @Nullable String recommendationName;

    private GetRecommendationStrategyResult() {}
    public String compartmentId() {
        return this.compartmentId;
    }
    public Boolean compartmentIdInSubtree() {
        return this.compartmentIdInSubtree;
    }
    /**
     * @return The provider-assigned unique ID for this managed resource.
     * 
     */
    public String id() {
        return this.id;
    }
    /**
     * @return A collection of recommendation strategy summaries.
     * 
     */
    public List<GetRecommendationStrategyItem> items() {
        return this.items;
    }
    /**
     * @return The name of the strategy parameter.
     * 
     */
    public Optional<String> name() {
        return Optional.ofNullable(this.name);
    }
    public Optional<String> recommendationName() {
        return Optional.ofNullable(this.recommendationName);
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetRecommendationStrategyResult defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String compartmentId;
        private Boolean compartmentIdInSubtree;
        private String id;
        private List<GetRecommendationStrategyItem> items;
        private @Nullable String name;
        private @Nullable String recommendationName;
        public Builder() {}
        public Builder(GetRecommendationStrategyResult defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.compartmentId = defaults.compartmentId;
    	      this.compartmentIdInSubtree = defaults.compartmentIdInSubtree;
    	      this.id = defaults.id;
    	      this.items = defaults.items;
    	      this.name = defaults.name;
    	      this.recommendationName = defaults.recommendationName;
        }

        @CustomType.Setter
        public Builder compartmentId(String compartmentId) {
            this.compartmentId = Objects.requireNonNull(compartmentId);
            return this;
        }
        @CustomType.Setter
        public Builder compartmentIdInSubtree(Boolean compartmentIdInSubtree) {
            this.compartmentIdInSubtree = Objects.requireNonNull(compartmentIdInSubtree);
            return this;
        }
        @CustomType.Setter
        public Builder id(String id) {
            this.id = Objects.requireNonNull(id);
            return this;
        }
        @CustomType.Setter
        public Builder items(List<GetRecommendationStrategyItem> items) {
            this.items = Objects.requireNonNull(items);
            return this;
        }
        public Builder items(GetRecommendationStrategyItem... items) {
            return items(List.of(items));
        }
        @CustomType.Setter
        public Builder name(@Nullable String name) {
            this.name = name;
            return this;
        }
        @CustomType.Setter
        public Builder recommendationName(@Nullable String recommendationName) {
            this.recommendationName = recommendationName;
            return this;
        }
        public GetRecommendationStrategyResult build() {
            final var o = new GetRecommendationStrategyResult();
            o.compartmentId = compartmentId;
            o.compartmentIdInSubtree = compartmentIdInSubtree;
            o.id = id;
            o.items = items;
            o.name = name;
            o.recommendationName = recommendationName;
            return o;
        }
    }
}