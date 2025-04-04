// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DataSafe.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.DataSafe.outputs.GetAlertPolicyRulesAlertPolicyRuleCollectionItem;
import java.util.List;
import java.util.Objects;

@CustomType
public final class GetAlertPolicyRulesAlertPolicyRuleCollection {
    private List<GetAlertPolicyRulesAlertPolicyRuleCollectionItem> items;

    private GetAlertPolicyRulesAlertPolicyRuleCollection() {}
    public List<GetAlertPolicyRulesAlertPolicyRuleCollectionItem> items() {
        return this.items;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetAlertPolicyRulesAlertPolicyRuleCollection defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private List<GetAlertPolicyRulesAlertPolicyRuleCollectionItem> items;
        public Builder() {}
        public Builder(GetAlertPolicyRulesAlertPolicyRuleCollection defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.items = defaults.items;
        }

        @CustomType.Setter
        public Builder items(List<GetAlertPolicyRulesAlertPolicyRuleCollectionItem> items) {
            if (items == null) {
              throw new MissingRequiredPropertyException("GetAlertPolicyRulesAlertPolicyRuleCollection", "items");
            }
            this.items = items;
            return this;
        }
        public Builder items(GetAlertPolicyRulesAlertPolicyRuleCollectionItem... items) {
            return items(List.of(items));
        }
        public GetAlertPolicyRulesAlertPolicyRuleCollection build() {
            final var _resultValue = new GetAlertPolicyRulesAlertPolicyRuleCollection();
            _resultValue.items = items;
            return _resultValue;
        }
    }
}
