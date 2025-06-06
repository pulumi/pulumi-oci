// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.MeteringComputation.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.MeteringComputation.outputs.GetScheduledRunsFilter;
import com.pulumi.oci.MeteringComputation.outputs.GetScheduledRunsScheduledRunCollection;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import javax.annotation.Nullable;

@CustomType
public final class GetScheduledRunsResult {
    private @Nullable List<GetScheduledRunsFilter> filters;
    /**
     * @return The provider-assigned unique ID for this managed resource.
     * 
     */
    private String id;
    /**
     * @return The OCID representing a unique shedule.
     * 
     */
    private String scheduleId;
    /**
     * @return The list of scheduled_run_collection.
     * 
     */
    private List<GetScheduledRunsScheduledRunCollection> scheduledRunCollections;

    private GetScheduledRunsResult() {}
    public List<GetScheduledRunsFilter> filters() {
        return this.filters == null ? List.of() : this.filters;
    }
    /**
     * @return The provider-assigned unique ID for this managed resource.
     * 
     */
    public String id() {
        return this.id;
    }
    /**
     * @return The OCID representing a unique shedule.
     * 
     */
    public String scheduleId() {
        return this.scheduleId;
    }
    /**
     * @return The list of scheduled_run_collection.
     * 
     */
    public List<GetScheduledRunsScheduledRunCollection> scheduledRunCollections() {
        return this.scheduledRunCollections;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetScheduledRunsResult defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private @Nullable List<GetScheduledRunsFilter> filters;
        private String id;
        private String scheduleId;
        private List<GetScheduledRunsScheduledRunCollection> scheduledRunCollections;
        public Builder() {}
        public Builder(GetScheduledRunsResult defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.filters = defaults.filters;
    	      this.id = defaults.id;
    	      this.scheduleId = defaults.scheduleId;
    	      this.scheduledRunCollections = defaults.scheduledRunCollections;
        }

        @CustomType.Setter
        public Builder filters(@Nullable List<GetScheduledRunsFilter> filters) {

            this.filters = filters;
            return this;
        }
        public Builder filters(GetScheduledRunsFilter... filters) {
            return filters(List.of(filters));
        }
        @CustomType.Setter
        public Builder id(String id) {
            if (id == null) {
              throw new MissingRequiredPropertyException("GetScheduledRunsResult", "id");
            }
            this.id = id;
            return this;
        }
        @CustomType.Setter
        public Builder scheduleId(String scheduleId) {
            if (scheduleId == null) {
              throw new MissingRequiredPropertyException("GetScheduledRunsResult", "scheduleId");
            }
            this.scheduleId = scheduleId;
            return this;
        }
        @CustomType.Setter
        public Builder scheduledRunCollections(List<GetScheduledRunsScheduledRunCollection> scheduledRunCollections) {
            if (scheduledRunCollections == null) {
              throw new MissingRequiredPropertyException("GetScheduledRunsResult", "scheduledRunCollections");
            }
            this.scheduledRunCollections = scheduledRunCollections;
            return this;
        }
        public Builder scheduledRunCollections(GetScheduledRunsScheduledRunCollection... scheduledRunCollections) {
            return scheduledRunCollections(List.of(scheduledRunCollections));
        }
        public GetScheduledRunsResult build() {
            final var _resultValue = new GetScheduledRunsResult();
            _resultValue.filters = filters;
            _resultValue.id = id;
            _resultValue.scheduleId = scheduleId;
            _resultValue.scheduledRunCollections = scheduledRunCollections;
            return _resultValue;
        }
    }
}
