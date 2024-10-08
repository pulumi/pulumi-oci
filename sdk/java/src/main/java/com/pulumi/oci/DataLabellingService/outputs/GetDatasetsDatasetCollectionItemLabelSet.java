// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DataLabellingService.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.DataLabellingService.outputs.GetDatasetsDatasetCollectionItemLabelSetItem;
import java.util.List;
import java.util.Objects;

@CustomType
public final class GetDatasetsDatasetCollectionItemLabelSet {
    /**
     * @return An ordered collection of labels that are unique by name.
     * 
     */
    private List<GetDatasetsDatasetCollectionItemLabelSetItem> items;

    private GetDatasetsDatasetCollectionItemLabelSet() {}
    /**
     * @return An ordered collection of labels that are unique by name.
     * 
     */
    public List<GetDatasetsDatasetCollectionItemLabelSetItem> items() {
        return this.items;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetDatasetsDatasetCollectionItemLabelSet defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private List<GetDatasetsDatasetCollectionItemLabelSetItem> items;
        public Builder() {}
        public Builder(GetDatasetsDatasetCollectionItemLabelSet defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.items = defaults.items;
        }

        @CustomType.Setter
        public Builder items(List<GetDatasetsDatasetCollectionItemLabelSetItem> items) {
            if (items == null) {
              throw new MissingRequiredPropertyException("GetDatasetsDatasetCollectionItemLabelSet", "items");
            }
            this.items = items;
            return this;
        }
        public Builder items(GetDatasetsDatasetCollectionItemLabelSetItem... items) {
            return items(List.of(items));
        }
        public GetDatasetsDatasetCollectionItemLabelSet build() {
            final var _resultValue = new GetDatasetsDatasetCollectionItemLabelSet();
            _resultValue.items = items;
            return _resultValue;
        }
    }
}
