// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DatabaseManagement.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.DatabaseManagement.outputs.GetExternalExadataStorageServersExternalExadataStorageServerCollectionItem;
import java.util.List;
import java.util.Objects;

@CustomType
public final class GetExternalExadataStorageServersExternalExadataStorageServerCollection {
    private List<GetExternalExadataStorageServersExternalExadataStorageServerCollectionItem> items;

    private GetExternalExadataStorageServersExternalExadataStorageServerCollection() {}
    public List<GetExternalExadataStorageServersExternalExadataStorageServerCollectionItem> items() {
        return this.items;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetExternalExadataStorageServersExternalExadataStorageServerCollection defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private List<GetExternalExadataStorageServersExternalExadataStorageServerCollectionItem> items;
        public Builder() {}
        public Builder(GetExternalExadataStorageServersExternalExadataStorageServerCollection defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.items = defaults.items;
        }

        @CustomType.Setter
        public Builder items(List<GetExternalExadataStorageServersExternalExadataStorageServerCollectionItem> items) {
            if (items == null) {
              throw new MissingRequiredPropertyException("GetExternalExadataStorageServersExternalExadataStorageServerCollection", "items");
            }
            this.items = items;
            return this;
        }
        public Builder items(GetExternalExadataStorageServersExternalExadataStorageServerCollectionItem... items) {
            return items(List.of(items));
        }
        public GetExternalExadataStorageServersExternalExadataStorageServerCollection build() {
            final var _resultValue = new GetExternalExadataStorageServersExternalExadataStorageServerCollection();
            _resultValue.items = items;
            return _resultValue;
        }
    }
}
