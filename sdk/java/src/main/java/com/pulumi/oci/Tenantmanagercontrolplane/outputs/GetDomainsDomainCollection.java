// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Tenantmanagercontrolplane.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.Tenantmanagercontrolplane.outputs.GetDomainsDomainCollectionItem;
import java.util.List;
import java.util.Objects;

@CustomType
public final class GetDomainsDomainCollection {
    private List<GetDomainsDomainCollectionItem> items;

    private GetDomainsDomainCollection() {}
    public List<GetDomainsDomainCollectionItem> items() {
        return this.items;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetDomainsDomainCollection defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private List<GetDomainsDomainCollectionItem> items;
        public Builder() {}
        public Builder(GetDomainsDomainCollection defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.items = defaults.items;
        }

        @CustomType.Setter
        public Builder items(List<GetDomainsDomainCollectionItem> items) {
            if (items == null) {
              throw new MissingRequiredPropertyException("GetDomainsDomainCollection", "items");
            }
            this.items = items;
            return this;
        }
        public Builder items(GetDomainsDomainCollectionItem... items) {
            return items(List.of(items));
        }
        public GetDomainsDomainCollection build() {
            final var _resultValue = new GetDomainsDomainCollection();
            _resultValue.items = items;
            return _resultValue;
        }
    }
}
