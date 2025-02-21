// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.FleetAppsManagement.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.FleetAppsManagement.outputs.GetSchedulerDefinitionScheduledFleetsScheduledFleetCollectionItem;
import java.util.List;
import java.util.Objects;

@CustomType
public final class GetSchedulerDefinitionScheduledFleetsScheduledFleetCollection {
    /**
     * @return List of ScheduledFleets.
     * 
     */
    private List<GetSchedulerDefinitionScheduledFleetsScheduledFleetCollectionItem> items;

    private GetSchedulerDefinitionScheduledFleetsScheduledFleetCollection() {}
    /**
     * @return List of ScheduledFleets.
     * 
     */
    public List<GetSchedulerDefinitionScheduledFleetsScheduledFleetCollectionItem> items() {
        return this.items;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetSchedulerDefinitionScheduledFleetsScheduledFleetCollection defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private List<GetSchedulerDefinitionScheduledFleetsScheduledFleetCollectionItem> items;
        public Builder() {}
        public Builder(GetSchedulerDefinitionScheduledFleetsScheduledFleetCollection defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.items = defaults.items;
        }

        @CustomType.Setter
        public Builder items(List<GetSchedulerDefinitionScheduledFleetsScheduledFleetCollectionItem> items) {
            if (items == null) {
              throw new MissingRequiredPropertyException("GetSchedulerDefinitionScheduledFleetsScheduledFleetCollection", "items");
            }
            this.items = items;
            return this;
        }
        public Builder items(GetSchedulerDefinitionScheduledFleetsScheduledFleetCollectionItem... items) {
            return items(List.of(items));
        }
        public GetSchedulerDefinitionScheduledFleetsScheduledFleetCollection build() {
            final var _resultValue = new GetSchedulerDefinitionScheduledFleetsScheduledFleetCollection();
            _resultValue.items = items;
            return _resultValue;
        }
    }
}
