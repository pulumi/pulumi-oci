// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Functions.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.Functions.outputs.GetFusionEnvironmentScheduledActivitiesFilter;
import com.pulumi.oci.Functions.outputs.GetFusionEnvironmentScheduledActivitiesScheduledActivityCollection;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;

@CustomType
public final class GetFusionEnvironmentScheduledActivitiesResult {
    /**
     * @return scheduled activity display name, can be renamed.
     * 
     */
    private @Nullable String displayName;
    private @Nullable List<GetFusionEnvironmentScheduledActivitiesFilter> filters;
    /**
     * @return FAaaS Environment Identifier.
     * 
     */
    private String fusionEnvironmentId;
    /**
     * @return The provider-assigned unique ID for this managed resource.
     * 
     */
    private String id;
    /**
     * @return run cadence.
     * 
     */
    private @Nullable String runCycle;
    /**
     * @return The list of scheduled_activity_collection.
     * 
     */
    private List<GetFusionEnvironmentScheduledActivitiesScheduledActivityCollection> scheduledActivityCollections;
    /**
     * @return The current state of the scheduledActivity.
     * 
     */
    private @Nullable String state;
    private @Nullable String timeExpectedFinishLessThanOrEqualTo;
    private @Nullable String timeScheduledStartGreaterThanOrEqualTo;

    private GetFusionEnvironmentScheduledActivitiesResult() {}
    /**
     * @return scheduled activity display name, can be renamed.
     * 
     */
    public Optional<String> displayName() {
        return Optional.ofNullable(this.displayName);
    }
    public List<GetFusionEnvironmentScheduledActivitiesFilter> filters() {
        return this.filters == null ? List.of() : this.filters;
    }
    /**
     * @return FAaaS Environment Identifier.
     * 
     */
    public String fusionEnvironmentId() {
        return this.fusionEnvironmentId;
    }
    /**
     * @return The provider-assigned unique ID for this managed resource.
     * 
     */
    public String id() {
        return this.id;
    }
    /**
     * @return run cadence.
     * 
     */
    public Optional<String> runCycle() {
        return Optional.ofNullable(this.runCycle);
    }
    /**
     * @return The list of scheduled_activity_collection.
     * 
     */
    public List<GetFusionEnvironmentScheduledActivitiesScheduledActivityCollection> scheduledActivityCollections() {
        return this.scheduledActivityCollections;
    }
    /**
     * @return The current state of the scheduledActivity.
     * 
     */
    public Optional<String> state() {
        return Optional.ofNullable(this.state);
    }
    public Optional<String> timeExpectedFinishLessThanOrEqualTo() {
        return Optional.ofNullable(this.timeExpectedFinishLessThanOrEqualTo);
    }
    public Optional<String> timeScheduledStartGreaterThanOrEqualTo() {
        return Optional.ofNullable(this.timeScheduledStartGreaterThanOrEqualTo);
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetFusionEnvironmentScheduledActivitiesResult defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private @Nullable String displayName;
        private @Nullable List<GetFusionEnvironmentScheduledActivitiesFilter> filters;
        private String fusionEnvironmentId;
        private String id;
        private @Nullable String runCycle;
        private List<GetFusionEnvironmentScheduledActivitiesScheduledActivityCollection> scheduledActivityCollections;
        private @Nullable String state;
        private @Nullable String timeExpectedFinishLessThanOrEqualTo;
        private @Nullable String timeScheduledStartGreaterThanOrEqualTo;
        public Builder() {}
        public Builder(GetFusionEnvironmentScheduledActivitiesResult defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.displayName = defaults.displayName;
    	      this.filters = defaults.filters;
    	      this.fusionEnvironmentId = defaults.fusionEnvironmentId;
    	      this.id = defaults.id;
    	      this.runCycle = defaults.runCycle;
    	      this.scheduledActivityCollections = defaults.scheduledActivityCollections;
    	      this.state = defaults.state;
    	      this.timeExpectedFinishLessThanOrEqualTo = defaults.timeExpectedFinishLessThanOrEqualTo;
    	      this.timeScheduledStartGreaterThanOrEqualTo = defaults.timeScheduledStartGreaterThanOrEqualTo;
        }

        @CustomType.Setter
        public Builder displayName(@Nullable String displayName) {

            this.displayName = displayName;
            return this;
        }
        @CustomType.Setter
        public Builder filters(@Nullable List<GetFusionEnvironmentScheduledActivitiesFilter> filters) {

            this.filters = filters;
            return this;
        }
        public Builder filters(GetFusionEnvironmentScheduledActivitiesFilter... filters) {
            return filters(List.of(filters));
        }
        @CustomType.Setter
        public Builder fusionEnvironmentId(String fusionEnvironmentId) {
            if (fusionEnvironmentId == null) {
              throw new MissingRequiredPropertyException("GetFusionEnvironmentScheduledActivitiesResult", "fusionEnvironmentId");
            }
            this.fusionEnvironmentId = fusionEnvironmentId;
            return this;
        }
        @CustomType.Setter
        public Builder id(String id) {
            if (id == null) {
              throw new MissingRequiredPropertyException("GetFusionEnvironmentScheduledActivitiesResult", "id");
            }
            this.id = id;
            return this;
        }
        @CustomType.Setter
        public Builder runCycle(@Nullable String runCycle) {

            this.runCycle = runCycle;
            return this;
        }
        @CustomType.Setter
        public Builder scheduledActivityCollections(List<GetFusionEnvironmentScheduledActivitiesScheduledActivityCollection> scheduledActivityCollections) {
            if (scheduledActivityCollections == null) {
              throw new MissingRequiredPropertyException("GetFusionEnvironmentScheduledActivitiesResult", "scheduledActivityCollections");
            }
            this.scheduledActivityCollections = scheduledActivityCollections;
            return this;
        }
        public Builder scheduledActivityCollections(GetFusionEnvironmentScheduledActivitiesScheduledActivityCollection... scheduledActivityCollections) {
            return scheduledActivityCollections(List.of(scheduledActivityCollections));
        }
        @CustomType.Setter
        public Builder state(@Nullable String state) {

            this.state = state;
            return this;
        }
        @CustomType.Setter
        public Builder timeExpectedFinishLessThanOrEqualTo(@Nullable String timeExpectedFinishLessThanOrEqualTo) {

            this.timeExpectedFinishLessThanOrEqualTo = timeExpectedFinishLessThanOrEqualTo;
            return this;
        }
        @CustomType.Setter
        public Builder timeScheduledStartGreaterThanOrEqualTo(@Nullable String timeScheduledStartGreaterThanOrEqualTo) {

            this.timeScheduledStartGreaterThanOrEqualTo = timeScheduledStartGreaterThanOrEqualTo;
            return this;
        }
        public GetFusionEnvironmentScheduledActivitiesResult build() {
            final var _resultValue = new GetFusionEnvironmentScheduledActivitiesResult();
            _resultValue.displayName = displayName;
            _resultValue.filters = filters;
            _resultValue.fusionEnvironmentId = fusionEnvironmentId;
            _resultValue.id = id;
            _resultValue.runCycle = runCycle;
            _resultValue.scheduledActivityCollections = scheduledActivityCollections;
            _resultValue.state = state;
            _resultValue.timeExpectedFinishLessThanOrEqualTo = timeExpectedFinishLessThanOrEqualTo;
            _resultValue.timeScheduledStartGreaterThanOrEqualTo = timeScheduledStartGreaterThanOrEqualTo;
            return _resultValue;
        }
    }
}
