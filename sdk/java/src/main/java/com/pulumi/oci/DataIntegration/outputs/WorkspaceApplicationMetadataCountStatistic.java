// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DataIntegration.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.oci.DataIntegration.outputs.WorkspaceApplicationMetadataCountStatisticObjectTypeCountList;
import java.util.List;
import java.util.Objects;
import javax.annotation.Nullable;

@CustomType
public final class WorkspaceApplicationMetadataCountStatistic {
    /**
     * @return The array of statistics.
     * 
     */
    private @Nullable List<WorkspaceApplicationMetadataCountStatisticObjectTypeCountList> objectTypeCountLists;

    private WorkspaceApplicationMetadataCountStatistic() {}
    /**
     * @return The array of statistics.
     * 
     */
    public List<WorkspaceApplicationMetadataCountStatisticObjectTypeCountList> objectTypeCountLists() {
        return this.objectTypeCountLists == null ? List.of() : this.objectTypeCountLists;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(WorkspaceApplicationMetadataCountStatistic defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private @Nullable List<WorkspaceApplicationMetadataCountStatisticObjectTypeCountList> objectTypeCountLists;
        public Builder() {}
        public Builder(WorkspaceApplicationMetadataCountStatistic defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.objectTypeCountLists = defaults.objectTypeCountLists;
        }

        @CustomType.Setter
        public Builder objectTypeCountLists(@Nullable List<WorkspaceApplicationMetadataCountStatisticObjectTypeCountList> objectTypeCountLists) {

            this.objectTypeCountLists = objectTypeCountLists;
            return this;
        }
        public Builder objectTypeCountLists(WorkspaceApplicationMetadataCountStatisticObjectTypeCountList... objectTypeCountLists) {
            return objectTypeCountLists(List.of(objectTypeCountLists));
        }
        public WorkspaceApplicationMetadataCountStatistic build() {
            final var _resultValue = new WorkspaceApplicationMetadataCountStatistic();
            _resultValue.objectTypeCountLists = objectTypeCountLists;
            return _resultValue;
        }
    }
}
