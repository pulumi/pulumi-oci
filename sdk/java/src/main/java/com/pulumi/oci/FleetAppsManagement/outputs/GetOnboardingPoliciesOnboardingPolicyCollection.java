// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.FleetAppsManagement.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.FleetAppsManagement.outputs.GetOnboardingPoliciesOnboardingPolicyCollectionItem;
import java.util.List;
import java.util.Objects;

@CustomType
public final class GetOnboardingPoliciesOnboardingPolicyCollection {
    /**
     * @return List of Fleet Application Management Onboard policies.
     * 
     */
    private List<GetOnboardingPoliciesOnboardingPolicyCollectionItem> items;

    private GetOnboardingPoliciesOnboardingPolicyCollection() {}
    /**
     * @return List of Fleet Application Management Onboard policies.
     * 
     */
    public List<GetOnboardingPoliciesOnboardingPolicyCollectionItem> items() {
        return this.items;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetOnboardingPoliciesOnboardingPolicyCollection defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private List<GetOnboardingPoliciesOnboardingPolicyCollectionItem> items;
        public Builder() {}
        public Builder(GetOnboardingPoliciesOnboardingPolicyCollection defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.items = defaults.items;
        }

        @CustomType.Setter
        public Builder items(List<GetOnboardingPoliciesOnboardingPolicyCollectionItem> items) {
            if (items == null) {
              throw new MissingRequiredPropertyException("GetOnboardingPoliciesOnboardingPolicyCollection", "items");
            }
            this.items = items;
            return this;
        }
        public Builder items(GetOnboardingPoliciesOnboardingPolicyCollectionItem... items) {
            return items(List.of(items));
        }
        public GetOnboardingPoliciesOnboardingPolicyCollection build() {
            final var _resultValue = new GetOnboardingPoliciesOnboardingPolicyCollection();
            _resultValue.items = items;
            return _resultValue;
        }
    }
}
