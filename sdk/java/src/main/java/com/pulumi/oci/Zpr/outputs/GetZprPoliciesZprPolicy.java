// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Zpr.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.Zpr.outputs.GetZprPoliciesZprPolicyItem;
import java.util.List;
import java.util.Objects;

@CustomType
public final class GetZprPoliciesZprPolicy {
    private List<GetZprPoliciesZprPolicyItem> items;

    private GetZprPoliciesZprPolicy() {}
    public List<GetZprPoliciesZprPolicyItem> items() {
        return this.items;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetZprPoliciesZprPolicy defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private List<GetZprPoliciesZprPolicyItem> items;
        public Builder() {}
        public Builder(GetZprPoliciesZprPolicy defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.items = defaults.items;
        }

        @CustomType.Setter
        public Builder items(List<GetZprPoliciesZprPolicyItem> items) {
            if (items == null) {
              throw new MissingRequiredPropertyException("GetZprPoliciesZprPolicy", "items");
            }
            this.items = items;
            return this;
        }
        public Builder items(GetZprPoliciesZprPolicyItem... items) {
            return items(List.of(items));
        }
        public GetZprPoliciesZprPolicy build() {
            final var _resultValue = new GetZprPoliciesZprPolicy();
            _resultValue.items = items;
            return _resultValue;
        }
    }
}
