// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.LogAnalytics.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.LogAnalytics.outputs.GetNamespaceIngestTimeRulesIngestTimeRuleSummaryCollectionItem;
import java.util.List;
import java.util.Objects;

@CustomType
public final class GetNamespaceIngestTimeRulesIngestTimeRuleSummaryCollection {
    private List<GetNamespaceIngestTimeRulesIngestTimeRuleSummaryCollectionItem> items;

    private GetNamespaceIngestTimeRulesIngestTimeRuleSummaryCollection() {}
    public List<GetNamespaceIngestTimeRulesIngestTimeRuleSummaryCollectionItem> items() {
        return this.items;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetNamespaceIngestTimeRulesIngestTimeRuleSummaryCollection defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private List<GetNamespaceIngestTimeRulesIngestTimeRuleSummaryCollectionItem> items;
        public Builder() {}
        public Builder(GetNamespaceIngestTimeRulesIngestTimeRuleSummaryCollection defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.items = defaults.items;
        }

        @CustomType.Setter
        public Builder items(List<GetNamespaceIngestTimeRulesIngestTimeRuleSummaryCollectionItem> items) {
            if (items == null) {
              throw new MissingRequiredPropertyException("GetNamespaceIngestTimeRulesIngestTimeRuleSummaryCollection", "items");
            }
            this.items = items;
            return this;
        }
        public Builder items(GetNamespaceIngestTimeRulesIngestTimeRuleSummaryCollectionItem... items) {
            return items(List.of(items));
        }
        public GetNamespaceIngestTimeRulesIngestTimeRuleSummaryCollection build() {
            final var _resultValue = new GetNamespaceIngestTimeRulesIngestTimeRuleSummaryCollection();
            _resultValue.items = items;
            return _resultValue;
        }
    }
}
