// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.oci.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.oci.outputs.GetDbmulticloudOracleDbAzureBlobMountsOracleDbAzureBlobMountSummaryCollectionItem;
import java.util.List;
import java.util.Objects;

@CustomType
public final class GetDbmulticloudOracleDbAzureBlobMountsOracleDbAzureBlobMountSummaryCollection {
    private List<GetDbmulticloudOracleDbAzureBlobMountsOracleDbAzureBlobMountSummaryCollectionItem> items;

    private GetDbmulticloudOracleDbAzureBlobMountsOracleDbAzureBlobMountSummaryCollection() {}
    public List<GetDbmulticloudOracleDbAzureBlobMountsOracleDbAzureBlobMountSummaryCollectionItem> items() {
        return this.items;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetDbmulticloudOracleDbAzureBlobMountsOracleDbAzureBlobMountSummaryCollection defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private List<GetDbmulticloudOracleDbAzureBlobMountsOracleDbAzureBlobMountSummaryCollectionItem> items;
        public Builder() {}
        public Builder(GetDbmulticloudOracleDbAzureBlobMountsOracleDbAzureBlobMountSummaryCollection defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.items = defaults.items;
        }

        @CustomType.Setter
        public Builder items(List<GetDbmulticloudOracleDbAzureBlobMountsOracleDbAzureBlobMountSummaryCollectionItem> items) {
            if (items == null) {
              throw new MissingRequiredPropertyException("GetDbmulticloudOracleDbAzureBlobMountsOracleDbAzureBlobMountSummaryCollection", "items");
            }
            this.items = items;
            return this;
        }
        public Builder items(GetDbmulticloudOracleDbAzureBlobMountsOracleDbAzureBlobMountSummaryCollectionItem... items) {
            return items(List.of(items));
        }
        public GetDbmulticloudOracleDbAzureBlobMountsOracleDbAzureBlobMountSummaryCollection build() {
            final var _resultValue = new GetDbmulticloudOracleDbAzureBlobMountsOracleDbAzureBlobMountSummaryCollection();
            _resultValue.items = items;
            return _resultValue;
        }
    }
}
