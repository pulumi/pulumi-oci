// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Jms.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.Jms.outputs.GetFleetPerformanceTuningAnalysisResultsFilter;
import com.pulumi.oci.Jms.outputs.GetFleetPerformanceTuningAnalysisResultsPerformanceTuningAnalysisResultCollection;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;

@CustomType
public final class GetFleetPerformanceTuningAnalysisResultsResult {
    /**
     * @return The OCID of the application for which the report has been generated.
     * 
     */
    private @Nullable String applicationId;
    /**
     * @return The name of the application for which the report has been generated.
     * 
     */
    private @Nullable String applicationName;
    private @Nullable List<GetFleetPerformanceTuningAnalysisResultsFilter> filters;
    /**
     * @return The fleet OCID.
     * 
     */
    private String fleetId;
    /**
     * @return The hostname of the managed instance.
     * 
     */
    private @Nullable String hostName;
    /**
     * @return The provider-assigned unique ID for this managed resource.
     * 
     */
    private String id;
    /**
     * @return The managed instance OCID.
     * 
     */
    private @Nullable String managedInstanceId;
    /**
     * @return The list of performance_tuning_analysis_result_collection.
     * 
     */
    private List<GetFleetPerformanceTuningAnalysisResultsPerformanceTuningAnalysisResultCollection> performanceTuningAnalysisResultCollections;
    private @Nullable String timeEnd;
    private @Nullable String timeStart;

    private GetFleetPerformanceTuningAnalysisResultsResult() {}
    /**
     * @return The OCID of the application for which the report has been generated.
     * 
     */
    public Optional<String> applicationId() {
        return Optional.ofNullable(this.applicationId);
    }
    /**
     * @return The name of the application for which the report has been generated.
     * 
     */
    public Optional<String> applicationName() {
        return Optional.ofNullable(this.applicationName);
    }
    public List<GetFleetPerformanceTuningAnalysisResultsFilter> filters() {
        return this.filters == null ? List.of() : this.filters;
    }
    /**
     * @return The fleet OCID.
     * 
     */
    public String fleetId() {
        return this.fleetId;
    }
    /**
     * @return The hostname of the managed instance.
     * 
     */
    public Optional<String> hostName() {
        return Optional.ofNullable(this.hostName);
    }
    /**
     * @return The provider-assigned unique ID for this managed resource.
     * 
     */
    public String id() {
        return this.id;
    }
    /**
     * @return The managed instance OCID.
     * 
     */
    public Optional<String> managedInstanceId() {
        return Optional.ofNullable(this.managedInstanceId);
    }
    /**
     * @return The list of performance_tuning_analysis_result_collection.
     * 
     */
    public List<GetFleetPerformanceTuningAnalysisResultsPerformanceTuningAnalysisResultCollection> performanceTuningAnalysisResultCollections() {
        return this.performanceTuningAnalysisResultCollections;
    }
    public Optional<String> timeEnd() {
        return Optional.ofNullable(this.timeEnd);
    }
    public Optional<String> timeStart() {
        return Optional.ofNullable(this.timeStart);
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetFleetPerformanceTuningAnalysisResultsResult defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private @Nullable String applicationId;
        private @Nullable String applicationName;
        private @Nullable List<GetFleetPerformanceTuningAnalysisResultsFilter> filters;
        private String fleetId;
        private @Nullable String hostName;
        private String id;
        private @Nullable String managedInstanceId;
        private List<GetFleetPerformanceTuningAnalysisResultsPerformanceTuningAnalysisResultCollection> performanceTuningAnalysisResultCollections;
        private @Nullable String timeEnd;
        private @Nullable String timeStart;
        public Builder() {}
        public Builder(GetFleetPerformanceTuningAnalysisResultsResult defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.applicationId = defaults.applicationId;
    	      this.applicationName = defaults.applicationName;
    	      this.filters = defaults.filters;
    	      this.fleetId = defaults.fleetId;
    	      this.hostName = defaults.hostName;
    	      this.id = defaults.id;
    	      this.managedInstanceId = defaults.managedInstanceId;
    	      this.performanceTuningAnalysisResultCollections = defaults.performanceTuningAnalysisResultCollections;
    	      this.timeEnd = defaults.timeEnd;
    	      this.timeStart = defaults.timeStart;
        }

        @CustomType.Setter
        public Builder applicationId(@Nullable String applicationId) {

            this.applicationId = applicationId;
            return this;
        }
        @CustomType.Setter
        public Builder applicationName(@Nullable String applicationName) {

            this.applicationName = applicationName;
            return this;
        }
        @CustomType.Setter
        public Builder filters(@Nullable List<GetFleetPerformanceTuningAnalysisResultsFilter> filters) {

            this.filters = filters;
            return this;
        }
        public Builder filters(GetFleetPerformanceTuningAnalysisResultsFilter... filters) {
            return filters(List.of(filters));
        }
        @CustomType.Setter
        public Builder fleetId(String fleetId) {
            if (fleetId == null) {
              throw new MissingRequiredPropertyException("GetFleetPerformanceTuningAnalysisResultsResult", "fleetId");
            }
            this.fleetId = fleetId;
            return this;
        }
        @CustomType.Setter
        public Builder hostName(@Nullable String hostName) {

            this.hostName = hostName;
            return this;
        }
        @CustomType.Setter
        public Builder id(String id) {
            if (id == null) {
              throw new MissingRequiredPropertyException("GetFleetPerformanceTuningAnalysisResultsResult", "id");
            }
            this.id = id;
            return this;
        }
        @CustomType.Setter
        public Builder managedInstanceId(@Nullable String managedInstanceId) {

            this.managedInstanceId = managedInstanceId;
            return this;
        }
        @CustomType.Setter
        public Builder performanceTuningAnalysisResultCollections(List<GetFleetPerformanceTuningAnalysisResultsPerformanceTuningAnalysisResultCollection> performanceTuningAnalysisResultCollections) {
            if (performanceTuningAnalysisResultCollections == null) {
              throw new MissingRequiredPropertyException("GetFleetPerformanceTuningAnalysisResultsResult", "performanceTuningAnalysisResultCollections");
            }
            this.performanceTuningAnalysisResultCollections = performanceTuningAnalysisResultCollections;
            return this;
        }
        public Builder performanceTuningAnalysisResultCollections(GetFleetPerformanceTuningAnalysisResultsPerformanceTuningAnalysisResultCollection... performanceTuningAnalysisResultCollections) {
            return performanceTuningAnalysisResultCollections(List.of(performanceTuningAnalysisResultCollections));
        }
        @CustomType.Setter
        public Builder timeEnd(@Nullable String timeEnd) {

            this.timeEnd = timeEnd;
            return this;
        }
        @CustomType.Setter
        public Builder timeStart(@Nullable String timeStart) {

            this.timeStart = timeStart;
            return this;
        }
        public GetFleetPerformanceTuningAnalysisResultsResult build() {
            final var _resultValue = new GetFleetPerformanceTuningAnalysisResultsResult();
            _resultValue.applicationId = applicationId;
            _resultValue.applicationName = applicationName;
            _resultValue.filters = filters;
            _resultValue.fleetId = fleetId;
            _resultValue.hostName = hostName;
            _resultValue.id = id;
            _resultValue.managedInstanceId = managedInstanceId;
            _resultValue.performanceTuningAnalysisResultCollections = performanceTuningAnalysisResultCollections;
            _resultValue.timeEnd = timeEnd;
            _resultValue.timeStart = timeStart;
            return _resultValue;
        }
    }
}
