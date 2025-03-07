// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Waa.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.Waa.outputs.GetAppAccelerationPoliciesWebAppAccelerationPolicyCollectionItem;
import java.util.List;
import java.util.Objects;

@CustomType
public final class GetAppAccelerationPoliciesWebAppAccelerationPolicyCollection {
    private List<GetAppAccelerationPoliciesWebAppAccelerationPolicyCollectionItem> items;

    private GetAppAccelerationPoliciesWebAppAccelerationPolicyCollection() {}
    public List<GetAppAccelerationPoliciesWebAppAccelerationPolicyCollectionItem> items() {
        return this.items;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetAppAccelerationPoliciesWebAppAccelerationPolicyCollection defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private List<GetAppAccelerationPoliciesWebAppAccelerationPolicyCollectionItem> items;
        public Builder() {}
        public Builder(GetAppAccelerationPoliciesWebAppAccelerationPolicyCollection defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.items = defaults.items;
        }

        @CustomType.Setter
        public Builder items(List<GetAppAccelerationPoliciesWebAppAccelerationPolicyCollectionItem> items) {
            if (items == null) {
              throw new MissingRequiredPropertyException("GetAppAccelerationPoliciesWebAppAccelerationPolicyCollection", "items");
            }
            this.items = items;
            return this;
        }
        public Builder items(GetAppAccelerationPoliciesWebAppAccelerationPolicyCollectionItem... items) {
            return items(List.of(items));
        }
        public GetAppAccelerationPoliciesWebAppAccelerationPolicyCollection build() {
            final var _resultValue = new GetAppAccelerationPoliciesWebAppAccelerationPolicyCollection();
            _resultValue.items = items;
            return _resultValue;
        }
    }
}
