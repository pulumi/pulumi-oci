// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DataSafe.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.oci.DataSafe.outputs.GetAuditPoliciesAuditPolicyCollectionItem;
import java.util.List;
import java.util.Objects;

@CustomType
public final class GetAuditPoliciesAuditPolicyCollection {
    private List<GetAuditPoliciesAuditPolicyCollectionItem> items;

    private GetAuditPoliciesAuditPolicyCollection() {}
    public List<GetAuditPoliciesAuditPolicyCollectionItem> items() {
        return this.items;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetAuditPoliciesAuditPolicyCollection defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private List<GetAuditPoliciesAuditPolicyCollectionItem> items;
        public Builder() {}
        public Builder(GetAuditPoliciesAuditPolicyCollection defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.items = defaults.items;
        }

        @CustomType.Setter
        public Builder items(List<GetAuditPoliciesAuditPolicyCollectionItem> items) {
            this.items = Objects.requireNonNull(items);
            return this;
        }
        public Builder items(GetAuditPoliciesAuditPolicyCollectionItem... items) {
            return items(List.of(items));
        }
        public GetAuditPoliciesAuditPolicyCollection build() {
            final var o = new GetAuditPoliciesAuditPolicyCollection();
            o.items = items;
            return o;
        }
    }
}