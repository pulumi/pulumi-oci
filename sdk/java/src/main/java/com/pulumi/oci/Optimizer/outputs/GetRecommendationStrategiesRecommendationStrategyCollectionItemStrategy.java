// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Optimizer.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.oci.Optimizer.outputs.GetRecommendationStrategiesRecommendationStrategyCollectionItemStrategyParametersDefinition;
import java.lang.Boolean;
import java.lang.String;
import java.util.List;
import java.util.Objects;

@CustomType
public final class GetRecommendationStrategiesRecommendationStrategyCollectionItemStrategy {
    /**
     * @return Whether this is the default recommendation strategy.
     * 
     */
    private Boolean isDefault;
    /**
     * @return The list of strategies for the parameters.
     * 
     */
    private List<GetRecommendationStrategiesRecommendationStrategyCollectionItemStrategyParametersDefinition> parametersDefinitions;
    /**
     * @return The name of the strategy.
     * 
     */
    private String strategyName;

    private GetRecommendationStrategiesRecommendationStrategyCollectionItemStrategy() {}
    /**
     * @return Whether this is the default recommendation strategy.
     * 
     */
    public Boolean isDefault() {
        return this.isDefault;
    }
    /**
     * @return The list of strategies for the parameters.
     * 
     */
    public List<GetRecommendationStrategiesRecommendationStrategyCollectionItemStrategyParametersDefinition> parametersDefinitions() {
        return this.parametersDefinitions;
    }
    /**
     * @return The name of the strategy.
     * 
     */
    public String strategyName() {
        return this.strategyName;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetRecommendationStrategiesRecommendationStrategyCollectionItemStrategy defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private Boolean isDefault;
        private List<GetRecommendationStrategiesRecommendationStrategyCollectionItemStrategyParametersDefinition> parametersDefinitions;
        private String strategyName;
        public Builder() {}
        public Builder(GetRecommendationStrategiesRecommendationStrategyCollectionItemStrategy defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.isDefault = defaults.isDefault;
    	      this.parametersDefinitions = defaults.parametersDefinitions;
    	      this.strategyName = defaults.strategyName;
        }

        @CustomType.Setter
        public Builder isDefault(Boolean isDefault) {
            this.isDefault = Objects.requireNonNull(isDefault);
            return this;
        }
        @CustomType.Setter
        public Builder parametersDefinitions(List<GetRecommendationStrategiesRecommendationStrategyCollectionItemStrategyParametersDefinition> parametersDefinitions) {
            this.parametersDefinitions = Objects.requireNonNull(parametersDefinitions);
            return this;
        }
        public Builder parametersDefinitions(GetRecommendationStrategiesRecommendationStrategyCollectionItemStrategyParametersDefinition... parametersDefinitions) {
            return parametersDefinitions(List.of(parametersDefinitions));
        }
        @CustomType.Setter
        public Builder strategyName(String strategyName) {
            this.strategyName = Objects.requireNonNull(strategyName);
            return this;
        }
        public GetRecommendationStrategiesRecommendationStrategyCollectionItemStrategy build() {
            final var o = new GetRecommendationStrategiesRecommendationStrategyCollectionItemStrategy();
            o.isDefault = isDefault;
            o.parametersDefinitions = parametersDefinitions;
            o.strategyName = strategyName;
            return o;
        }
    }
}