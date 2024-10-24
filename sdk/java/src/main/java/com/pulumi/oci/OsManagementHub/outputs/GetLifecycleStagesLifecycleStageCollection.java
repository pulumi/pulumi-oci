// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.OsManagementHub.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.OsManagementHub.outputs.GetLifecycleStagesLifecycleStageCollectionItem;
import java.util.List;
import java.util.Objects;

@CustomType
public final class GetLifecycleStagesLifecycleStageCollection {
    private List<GetLifecycleStagesLifecycleStageCollectionItem> items;

    private GetLifecycleStagesLifecycleStageCollection() {}
    public List<GetLifecycleStagesLifecycleStageCollectionItem> items() {
        return this.items;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetLifecycleStagesLifecycleStageCollection defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private List<GetLifecycleStagesLifecycleStageCollectionItem> items;
        public Builder() {}
        public Builder(GetLifecycleStagesLifecycleStageCollection defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.items = defaults.items;
        }

        @CustomType.Setter
        public Builder items(List<GetLifecycleStagesLifecycleStageCollectionItem> items) {
            if (items == null) {
              throw new MissingRequiredPropertyException("GetLifecycleStagesLifecycleStageCollection", "items");
            }
            this.items = items;
            return this;
        }
        public Builder items(GetLifecycleStagesLifecycleStageCollectionItem... items) {
            return items(List.of(items));
        }
        public GetLifecycleStagesLifecycleStageCollection build() {
            final var _resultValue = new GetLifecycleStagesLifecycleStageCollection();
            _resultValue.items = items;
            return _resultValue;
        }
    }
}
