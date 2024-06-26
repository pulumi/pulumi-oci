// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.CertificatesManagement.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.CertificatesManagement.outputs.GetAssociationsAssociationCollectionItem;
import java.util.List;
import java.util.Objects;

@CustomType
public final class GetAssociationsAssociationCollection {
    private List<GetAssociationsAssociationCollectionItem> items;

    private GetAssociationsAssociationCollection() {}
    public List<GetAssociationsAssociationCollectionItem> items() {
        return this.items;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetAssociationsAssociationCollection defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private List<GetAssociationsAssociationCollectionItem> items;
        public Builder() {}
        public Builder(GetAssociationsAssociationCollection defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.items = defaults.items;
        }

        @CustomType.Setter
        public Builder items(List<GetAssociationsAssociationCollectionItem> items) {
            if (items == null) {
              throw new MissingRequiredPropertyException("GetAssociationsAssociationCollection", "items");
            }
            this.items = items;
            return this;
        }
        public Builder items(GetAssociationsAssociationCollectionItem... items) {
            return items(List.of(items));
        }
        public GetAssociationsAssociationCollection build() {
            final var _resultValue = new GetAssociationsAssociationCollection();
            _resultValue.items = items;
            return _resultValue;
        }
    }
}
