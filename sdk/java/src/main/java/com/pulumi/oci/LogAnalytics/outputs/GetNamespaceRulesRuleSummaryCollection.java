// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.LogAnalytics.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.LogAnalytics.outputs.GetNamespaceRulesRuleSummaryCollectionItem;
import java.util.List;
import java.util.Objects;

@CustomType
public final class GetNamespaceRulesRuleSummaryCollection {
    /**
     * @return An array of rule summary objects.
     * 
     */
    private List<GetNamespaceRulesRuleSummaryCollectionItem> items;

    private GetNamespaceRulesRuleSummaryCollection() {}
    /**
     * @return An array of rule summary objects.
     * 
     */
    public List<GetNamespaceRulesRuleSummaryCollectionItem> items() {
        return this.items;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetNamespaceRulesRuleSummaryCollection defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private List<GetNamespaceRulesRuleSummaryCollectionItem> items;
        public Builder() {}
        public Builder(GetNamespaceRulesRuleSummaryCollection defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.items = defaults.items;
        }

        @CustomType.Setter
        public Builder items(List<GetNamespaceRulesRuleSummaryCollectionItem> items) {
            if (items == null) {
              throw new MissingRequiredPropertyException("GetNamespaceRulesRuleSummaryCollection", "items");
            }
            this.items = items;
            return this;
        }
        public Builder items(GetNamespaceRulesRuleSummaryCollectionItem... items) {
            return items(List.of(items));
        }
        public GetNamespaceRulesRuleSummaryCollection build() {
            final var _resultValue = new GetNamespaceRulesRuleSummaryCollection();
            _resultValue.items = items;
            return _resultValue;
        }
    }
}
