// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.oci.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.oci.outputs.GetDbmulticloudOracleDbAzureVaultsOracleDbAzureVaultSummaryCollectionItem;
import java.util.List;
import java.util.Objects;

@CustomType
public final class GetDbmulticloudOracleDbAzureVaultsOracleDbAzureVaultSummaryCollection {
    private List<GetDbmulticloudOracleDbAzureVaultsOracleDbAzureVaultSummaryCollectionItem> items;

    private GetDbmulticloudOracleDbAzureVaultsOracleDbAzureVaultSummaryCollection() {}
    public List<GetDbmulticloudOracleDbAzureVaultsOracleDbAzureVaultSummaryCollectionItem> items() {
        return this.items;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetDbmulticloudOracleDbAzureVaultsOracleDbAzureVaultSummaryCollection defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private List<GetDbmulticloudOracleDbAzureVaultsOracleDbAzureVaultSummaryCollectionItem> items;
        public Builder() {}
        public Builder(GetDbmulticloudOracleDbAzureVaultsOracleDbAzureVaultSummaryCollection defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.items = defaults.items;
        }

        @CustomType.Setter
        public Builder items(List<GetDbmulticloudOracleDbAzureVaultsOracleDbAzureVaultSummaryCollectionItem> items) {
            if (items == null) {
              throw new MissingRequiredPropertyException("GetDbmulticloudOracleDbAzureVaultsOracleDbAzureVaultSummaryCollection", "items");
            }
            this.items = items;
            return this;
        }
        public Builder items(GetDbmulticloudOracleDbAzureVaultsOracleDbAzureVaultSummaryCollectionItem... items) {
            return items(List.of(items));
        }
        public GetDbmulticloudOracleDbAzureVaultsOracleDbAzureVaultSummaryCollection build() {
            final var _resultValue = new GetDbmulticloudOracleDbAzureVaultsOracleDbAzureVaultSummaryCollection();
            _resultValue.items = items;
            return _resultValue;
        }
    }
}
