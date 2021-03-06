// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Optimizer.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.oci.Optimizer.outputs.GetRecommendationsRecommendationCollectionItemSupportedLevelItem;
import java.util.List;
import java.util.Objects;

@CustomType
public final class GetRecommendationsRecommendationCollectionItemSupportedLevel {
    /**
     * @return The list of supported levels.
     * 
     */
    private final List<GetRecommendationsRecommendationCollectionItemSupportedLevelItem> items;

    @CustomType.Constructor
    private GetRecommendationsRecommendationCollectionItemSupportedLevel(@CustomType.Parameter("items") List<GetRecommendationsRecommendationCollectionItemSupportedLevelItem> items) {
        this.items = items;
    }

    /**
     * @return The list of supported levels.
     * 
     */
    public List<GetRecommendationsRecommendationCollectionItemSupportedLevelItem> items() {
        return this.items;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetRecommendationsRecommendationCollectionItemSupportedLevel defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private List<GetRecommendationsRecommendationCollectionItemSupportedLevelItem> items;

        public Builder() {
    	      // Empty
        }

        public Builder(GetRecommendationsRecommendationCollectionItemSupportedLevel defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.items = defaults.items;
        }

        public Builder items(List<GetRecommendationsRecommendationCollectionItemSupportedLevelItem> items) {
            this.items = Objects.requireNonNull(items);
            return this;
        }
        public Builder items(GetRecommendationsRecommendationCollectionItemSupportedLevelItem... items) {
            return items(List.of(items));
        }        public GetRecommendationsRecommendationCollectionItemSupportedLevel build() {
            return new GetRecommendationsRecommendationCollectionItemSupportedLevel(items);
        }
    }
}
