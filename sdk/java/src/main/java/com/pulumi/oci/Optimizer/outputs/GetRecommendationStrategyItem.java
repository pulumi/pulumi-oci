// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Optimizer.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.oci.Optimizer.outputs.GetRecommendationStrategyItemStrategy;
import java.lang.String;
import java.util.List;
import java.util.Objects;

@CustomType
public final class GetRecommendationStrategyItem {
    /**
     * @return Optional. A filter that returns results that match the name specified.
     * 
     */
    private String name;
    /**
     * @return The list of strategies used.
     * 
     */
    private List<GetRecommendationStrategyItemStrategy> strategies;

    private GetRecommendationStrategyItem() {}
    /**
     * @return Optional. A filter that returns results that match the name specified.
     * 
     */
    public String name() {
        return this.name;
    }
    /**
     * @return The list of strategies used.
     * 
     */
    public List<GetRecommendationStrategyItemStrategy> strategies() {
        return this.strategies;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetRecommendationStrategyItem defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String name;
        private List<GetRecommendationStrategyItemStrategy> strategies;
        public Builder() {}
        public Builder(GetRecommendationStrategyItem defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.name = defaults.name;
    	      this.strategies = defaults.strategies;
        }

        @CustomType.Setter
        public Builder name(String name) {
            this.name = Objects.requireNonNull(name);
            return this;
        }
        @CustomType.Setter
        public Builder strategies(List<GetRecommendationStrategyItemStrategy> strategies) {
            this.strategies = Objects.requireNonNull(strategies);
            return this;
        }
        public Builder strategies(GetRecommendationStrategyItemStrategy... strategies) {
            return strategies(List.of(strategies));
        }
        public GetRecommendationStrategyItem build() {
            final var o = new GetRecommendationStrategyItem();
            o.name = name;
            o.strategies = strategies;
            return o;
        }
    }
}