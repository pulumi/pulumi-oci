// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.AiAnomalyDetection.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.AiAnomalyDetection.outputs.GetDetectionModelsModelCollectionItem;
import java.util.List;
import java.util.Objects;

@CustomType
public final class GetDetectionModelsModelCollection {
    private List<GetDetectionModelsModelCollectionItem> items;

    private GetDetectionModelsModelCollection() {}
    public List<GetDetectionModelsModelCollectionItem> items() {
        return this.items;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetDetectionModelsModelCollection defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private List<GetDetectionModelsModelCollectionItem> items;
        public Builder() {}
        public Builder(GetDetectionModelsModelCollection defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.items = defaults.items;
        }

        @CustomType.Setter
        public Builder items(List<GetDetectionModelsModelCollectionItem> items) {
            if (items == null) {
              throw new MissingRequiredPropertyException("GetDetectionModelsModelCollection", "items");
            }
            this.items = items;
            return this;
        }
        public Builder items(GetDetectionModelsModelCollectionItem... items) {
            return items(List.of(items));
        }
        public GetDetectionModelsModelCollection build() {
            final var _resultValue = new GetDetectionModelsModelCollection();
            _resultValue.items = items;
            return _resultValue;
        }
    }
}
