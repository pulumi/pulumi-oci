// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.CloudGuard.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.CloudGuard.outputs.GetResponderRecipesResponderRecipeCollectionItem;
import java.util.List;
import java.util.Objects;

@CustomType
public final class GetResponderRecipesResponderRecipeCollection {
    private List<GetResponderRecipesResponderRecipeCollectionItem> items;

    private GetResponderRecipesResponderRecipeCollection() {}
    public List<GetResponderRecipesResponderRecipeCollectionItem> items() {
        return this.items;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetResponderRecipesResponderRecipeCollection defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private List<GetResponderRecipesResponderRecipeCollectionItem> items;
        public Builder() {}
        public Builder(GetResponderRecipesResponderRecipeCollection defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.items = defaults.items;
        }

        @CustomType.Setter
        public Builder items(List<GetResponderRecipesResponderRecipeCollectionItem> items) {
            if (items == null) {
              throw new MissingRequiredPropertyException("GetResponderRecipesResponderRecipeCollection", "items");
            }
            this.items = items;
            return this;
        }
        public Builder items(GetResponderRecipesResponderRecipeCollectionItem... items) {
            return items(List.of(items));
        }
        public GetResponderRecipesResponderRecipeCollection build() {
            final var _resultValue = new GetResponderRecipesResponderRecipeCollection();
            _resultValue.items = items;
            return _resultValue;
        }
    }
}
