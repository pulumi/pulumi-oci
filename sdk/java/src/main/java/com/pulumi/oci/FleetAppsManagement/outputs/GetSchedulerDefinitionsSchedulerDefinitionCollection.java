// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.FleetAppsManagement.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.FleetAppsManagement.outputs.GetSchedulerDefinitionsSchedulerDefinitionCollectionItem;
import java.util.List;
import java.util.Objects;

@CustomType
public final class GetSchedulerDefinitionsSchedulerDefinitionCollection {
    private List<GetSchedulerDefinitionsSchedulerDefinitionCollectionItem> items;

    private GetSchedulerDefinitionsSchedulerDefinitionCollection() {}
    public List<GetSchedulerDefinitionsSchedulerDefinitionCollectionItem> items() {
        return this.items;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetSchedulerDefinitionsSchedulerDefinitionCollection defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private List<GetSchedulerDefinitionsSchedulerDefinitionCollectionItem> items;
        public Builder() {}
        public Builder(GetSchedulerDefinitionsSchedulerDefinitionCollection defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.items = defaults.items;
        }

        @CustomType.Setter
        public Builder items(List<GetSchedulerDefinitionsSchedulerDefinitionCollectionItem> items) {
            if (items == null) {
              throw new MissingRequiredPropertyException("GetSchedulerDefinitionsSchedulerDefinitionCollection", "items");
            }
            this.items = items;
            return this;
        }
        public Builder items(GetSchedulerDefinitionsSchedulerDefinitionCollectionItem... items) {
            return items(List.of(items));
        }
        public GetSchedulerDefinitionsSchedulerDefinitionCollection build() {
            final var _resultValue = new GetSchedulerDefinitionsSchedulerDefinitionCollection();
            _resultValue.items = items;
            return _resultValue;
        }
    }
}
