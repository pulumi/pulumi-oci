// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DatabaseManagement.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.DatabaseManagement.outputs.GetExternalExadataStorageConnectorsExternalExadataStorageConnectorCollectionItem;
import java.util.List;
import java.util.Objects;

@CustomType
public final class GetExternalExadataStorageConnectorsExternalExadataStorageConnectorCollection {
    private List<GetExternalExadataStorageConnectorsExternalExadataStorageConnectorCollectionItem> items;

    private GetExternalExadataStorageConnectorsExternalExadataStorageConnectorCollection() {}
    public List<GetExternalExadataStorageConnectorsExternalExadataStorageConnectorCollectionItem> items() {
        return this.items;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetExternalExadataStorageConnectorsExternalExadataStorageConnectorCollection defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private List<GetExternalExadataStorageConnectorsExternalExadataStorageConnectorCollectionItem> items;
        public Builder() {}
        public Builder(GetExternalExadataStorageConnectorsExternalExadataStorageConnectorCollection defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.items = defaults.items;
        }

        @CustomType.Setter
        public Builder items(List<GetExternalExadataStorageConnectorsExternalExadataStorageConnectorCollectionItem> items) {
            if (items == null) {
              throw new MissingRequiredPropertyException("GetExternalExadataStorageConnectorsExternalExadataStorageConnectorCollection", "items");
            }
            this.items = items;
            return this;
        }
        public Builder items(GetExternalExadataStorageConnectorsExternalExadataStorageConnectorCollectionItem... items) {
            return items(List.of(items));
        }
        public GetExternalExadataStorageConnectorsExternalExadataStorageConnectorCollection build() {
            final var _resultValue = new GetExternalExadataStorageConnectorsExternalExadataStorageConnectorCollection();
            _resultValue.items = items;
            return _resultValue;
        }
    }
}
