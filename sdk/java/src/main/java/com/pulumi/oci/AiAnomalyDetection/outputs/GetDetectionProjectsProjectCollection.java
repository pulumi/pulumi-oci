// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.AiAnomalyDetection.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.AiAnomalyDetection.outputs.GetDetectionProjectsProjectCollectionItem;
import java.util.List;
import java.util.Objects;

@CustomType
public final class GetDetectionProjectsProjectCollection {
    private List<GetDetectionProjectsProjectCollectionItem> items;

    private GetDetectionProjectsProjectCollection() {}
    public List<GetDetectionProjectsProjectCollectionItem> items() {
        return this.items;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetDetectionProjectsProjectCollection defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private List<GetDetectionProjectsProjectCollectionItem> items;
        public Builder() {}
        public Builder(GetDetectionProjectsProjectCollection defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.items = defaults.items;
        }

        @CustomType.Setter
        public Builder items(List<GetDetectionProjectsProjectCollectionItem> items) {
            if (items == null) {
              throw new MissingRequiredPropertyException("GetDetectionProjectsProjectCollection", "items");
            }
            this.items = items;
            return this;
        }
        public Builder items(GetDetectionProjectsProjectCollectionItem... items) {
            return items(List.of(items));
        }
        public GetDetectionProjectsProjectCollection build() {
            final var _resultValue = new GetDetectionProjectsProjectCollection();
            _resultValue.items = items;
            return _resultValue;
        }
    }
}
