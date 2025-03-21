// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DevOps.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.DevOps.outputs.RepositorySettingApprovalRulesItem;
import java.util.List;
import java.util.Objects;

@CustomType
public final class RepositorySettingApprovalRules {
    /**
     * @return (Updatable) List of approval rules.
     * 
     */
    private List<RepositorySettingApprovalRulesItem> items;

    private RepositorySettingApprovalRules() {}
    /**
     * @return (Updatable) List of approval rules.
     * 
     */
    public List<RepositorySettingApprovalRulesItem> items() {
        return this.items;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(RepositorySettingApprovalRules defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private List<RepositorySettingApprovalRulesItem> items;
        public Builder() {}
        public Builder(RepositorySettingApprovalRules defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.items = defaults.items;
        }

        @CustomType.Setter
        public Builder items(List<RepositorySettingApprovalRulesItem> items) {
            if (items == null) {
              throw new MissingRequiredPropertyException("RepositorySettingApprovalRules", "items");
            }
            this.items = items;
            return this;
        }
        public Builder items(RepositorySettingApprovalRulesItem... items) {
            return items(List.of(items));
        }
        public RepositorySettingApprovalRules build() {
            final var _resultValue = new RepositorySettingApprovalRules();
            _resultValue.items = items;
            return _resultValue;
        }
    }
}
