// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.oci.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.oci.outputs.GetWlmsManagedInstanceScanResultsScanResultCollectionItem;
import java.util.List;
import java.util.Objects;

@CustomType
public final class GetWlmsManagedInstanceScanResultsScanResultCollection {
    /**
     * @return List of scan results.
     * 
     */
    private List<GetWlmsManagedInstanceScanResultsScanResultCollectionItem> items;

    private GetWlmsManagedInstanceScanResultsScanResultCollection() {}
    /**
     * @return List of scan results.
     * 
     */
    public List<GetWlmsManagedInstanceScanResultsScanResultCollectionItem> items() {
        return this.items;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetWlmsManagedInstanceScanResultsScanResultCollection defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private List<GetWlmsManagedInstanceScanResultsScanResultCollectionItem> items;
        public Builder() {}
        public Builder(GetWlmsManagedInstanceScanResultsScanResultCollection defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.items = defaults.items;
        }

        @CustomType.Setter
        public Builder items(List<GetWlmsManagedInstanceScanResultsScanResultCollectionItem> items) {
            if (items == null) {
              throw new MissingRequiredPropertyException("GetWlmsManagedInstanceScanResultsScanResultCollection", "items");
            }
            this.items = items;
            return this;
        }
        public Builder items(GetWlmsManagedInstanceScanResultsScanResultCollectionItem... items) {
            return items(List.of(items));
        }
        public GetWlmsManagedInstanceScanResultsScanResultCollection build() {
            final var _resultValue = new GetWlmsManagedInstanceScanResultsScanResultCollection();
            _resultValue.items = items;
            return _resultValue;
        }
    }
}
