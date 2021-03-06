// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.CloudGuard.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.oci.CloudGuard.outputs.GetDetectorRecipesDetectorRecipeCollectionItem;
import java.util.List;
import java.util.Objects;

@CustomType
public final class GetDetectorRecipesDetectorRecipeCollection {
    private final List<GetDetectorRecipesDetectorRecipeCollectionItem> items;

    @CustomType.Constructor
    private GetDetectorRecipesDetectorRecipeCollection(@CustomType.Parameter("items") List<GetDetectorRecipesDetectorRecipeCollectionItem> items) {
        this.items = items;
    }

    public List<GetDetectorRecipesDetectorRecipeCollectionItem> items() {
        return this.items;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetDetectorRecipesDetectorRecipeCollection defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private List<GetDetectorRecipesDetectorRecipeCollectionItem> items;

        public Builder() {
    	      // Empty
        }

        public Builder(GetDetectorRecipesDetectorRecipeCollection defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.items = defaults.items;
        }

        public Builder items(List<GetDetectorRecipesDetectorRecipeCollectionItem> items) {
            this.items = Objects.requireNonNull(items);
            return this;
        }
        public Builder items(GetDetectorRecipesDetectorRecipeCollectionItem... items) {
            return items(List.of(items));
        }        public GetDetectorRecipesDetectorRecipeCollection build() {
            return new GetDetectorRecipesDetectorRecipeCollection(items);
        }
    }
}
