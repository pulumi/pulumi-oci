// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DataSafe.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.DataSafe.outputs.GetSensitiveDataModelSensitiveTypesSensitiveDataModelSensitiveTypeCollectionItem;
import java.util.List;
import java.util.Objects;

@CustomType
public final class GetSensitiveDataModelSensitiveTypesSensitiveDataModelSensitiveTypeCollection {
    /**
     * @return An array of sensitive types summary objects present in a sensitive data model.
     * 
     */
    private List<GetSensitiveDataModelSensitiveTypesSensitiveDataModelSensitiveTypeCollectionItem> items;

    private GetSensitiveDataModelSensitiveTypesSensitiveDataModelSensitiveTypeCollection() {}
    /**
     * @return An array of sensitive types summary objects present in a sensitive data model.
     * 
     */
    public List<GetSensitiveDataModelSensitiveTypesSensitiveDataModelSensitiveTypeCollectionItem> items() {
        return this.items;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetSensitiveDataModelSensitiveTypesSensitiveDataModelSensitiveTypeCollection defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private List<GetSensitiveDataModelSensitiveTypesSensitiveDataModelSensitiveTypeCollectionItem> items;
        public Builder() {}
        public Builder(GetSensitiveDataModelSensitiveTypesSensitiveDataModelSensitiveTypeCollection defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.items = defaults.items;
        }

        @CustomType.Setter
        public Builder items(List<GetSensitiveDataModelSensitiveTypesSensitiveDataModelSensitiveTypeCollectionItem> items) {
            if (items == null) {
              throw new MissingRequiredPropertyException("GetSensitiveDataModelSensitiveTypesSensitiveDataModelSensitiveTypeCollection", "items");
            }
            this.items = items;
            return this;
        }
        public Builder items(GetSensitiveDataModelSensitiveTypesSensitiveDataModelSensitiveTypeCollectionItem... items) {
            return items(List.of(items));
        }
        public GetSensitiveDataModelSensitiveTypesSensitiveDataModelSensitiveTypeCollection build() {
            final var _resultValue = new GetSensitiveDataModelSensitiveTypesSensitiveDataModelSensitiveTypeCollection();
            _resultValue.items = items;
            return _resultValue;
        }
    }
}
