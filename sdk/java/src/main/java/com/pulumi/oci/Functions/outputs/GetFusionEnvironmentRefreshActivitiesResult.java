// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Functions.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.Functions.outputs.GetFusionEnvironmentRefreshActivitiesFilter;
import com.pulumi.oci.Functions.outputs.GetFusionEnvironmentRefreshActivitiesRefreshActivityCollection;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;

@CustomType
public final class GetFusionEnvironmentRefreshActivitiesResult {
    /**
     * @return A friendly name for the refresh activity. Can be changed later.
     * 
     */
    private @Nullable String displayName;
    private @Nullable List<GetFusionEnvironmentRefreshActivitiesFilter> filters;
    private String fusionEnvironmentId;
    /**
     * @return The provider-assigned unique ID for this managed resource.
     * 
     */
    private String id;
    /**
     * @return The list of refresh_activity_collection.
     * 
     */
    private List<GetFusionEnvironmentRefreshActivitiesRefreshActivityCollection> refreshActivityCollections;
    /**
     * @return The current state of the refreshActivity.
     * 
     */
    private @Nullable String state;
    private @Nullable String timeExpectedFinishLessThanOrEqualTo;
    private @Nullable String timeScheduledStartGreaterThanOrEqualTo;

    private GetFusionEnvironmentRefreshActivitiesResult() {}
    /**
     * @return A friendly name for the refresh activity. Can be changed later.
     * 
     */
    public Optional<String> displayName() {
        return Optional.ofNullable(this.displayName);
    }
    public List<GetFusionEnvironmentRefreshActivitiesFilter> filters() {
        return this.filters == null ? List.of() : this.filters;
    }
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
     * @return The list of refresh_activity_collection.
     * 
     */
    public List<GetFusionEnvironmentRefreshActivitiesRefreshActivityCollection> refreshActivityCollections() {
        return this.refreshActivityCollections;
    }
    /**
     * @return The current state of the refreshActivity.
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

    public static Builder builder(GetFusionEnvironmentRefreshActivitiesResult defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private @Nullable String displayName;
        private @Nullable List<GetFusionEnvironmentRefreshActivitiesFilter> filters;
        private String fusionEnvironmentId;
        private String id;
        private List<GetFusionEnvironmentRefreshActivitiesRefreshActivityCollection> refreshActivityCollections;
        private @Nullable String state;
        private @Nullable String timeExpectedFinishLessThanOrEqualTo;
        private @Nullable String timeScheduledStartGreaterThanOrEqualTo;
        public Builder() {}
        public Builder(GetFusionEnvironmentRefreshActivitiesResult defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.displayName = defaults.displayName;
    	      this.filters = defaults.filters;
    	      this.fusionEnvironmentId = defaults.fusionEnvironmentId;
    	      this.id = defaults.id;
    	      this.refreshActivityCollections = defaults.refreshActivityCollections;
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
        public Builder filters(@Nullable List<GetFusionEnvironmentRefreshActivitiesFilter> filters) {

            this.filters = filters;
            return this;
        }
        public Builder filters(GetFusionEnvironmentRefreshActivitiesFilter... filters) {
            return filters(List.of(filters));
        }
        @CustomType.Setter
        public Builder fusionEnvironmentId(String fusionEnvironmentId) {
            if (fusionEnvironmentId == null) {
              throw new MissingRequiredPropertyException("GetFusionEnvironmentRefreshActivitiesResult", "fusionEnvironmentId");
            }
            this.fusionEnvironmentId = fusionEnvironmentId;
            return this;
        }
        @CustomType.Setter
        public Builder id(String id) {
            if (id == null) {
              throw new MissingRequiredPropertyException("GetFusionEnvironmentRefreshActivitiesResult", "id");
            }
            this.id = id;
            return this;
        }
        @CustomType.Setter
        public Builder refreshActivityCollections(List<GetFusionEnvironmentRefreshActivitiesRefreshActivityCollection> refreshActivityCollections) {
            if (refreshActivityCollections == null) {
              throw new MissingRequiredPropertyException("GetFusionEnvironmentRefreshActivitiesResult", "refreshActivityCollections");
            }
            this.refreshActivityCollections = refreshActivityCollections;
            return this;
        }
        public Builder refreshActivityCollections(GetFusionEnvironmentRefreshActivitiesRefreshActivityCollection... refreshActivityCollections) {
            return refreshActivityCollections(List.of(refreshActivityCollections));
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
        public GetFusionEnvironmentRefreshActivitiesResult build() {
            final var _resultValue = new GetFusionEnvironmentRefreshActivitiesResult();
            _resultValue.displayName = displayName;
            _resultValue.filters = filters;
            _resultValue.fusionEnvironmentId = fusionEnvironmentId;
            _resultValue.id = id;
            _resultValue.refreshActivityCollections = refreshActivityCollections;
            _resultValue.state = state;
            _resultValue.timeExpectedFinishLessThanOrEqualTo = timeExpectedFinishLessThanOrEqualTo;
            _resultValue.timeScheduledStartGreaterThanOrEqualTo = timeScheduledStartGreaterThanOrEqualTo;
            return _resultValue;
        }
    }
}
