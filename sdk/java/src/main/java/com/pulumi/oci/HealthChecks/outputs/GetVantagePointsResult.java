// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.HealthChecks.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.oci.HealthChecks.outputs.GetVantagePointsFilter;
import com.pulumi.oci.HealthChecks.outputs.GetVantagePointsHealthChecksVantagePoint;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;

@CustomType
public final class GetVantagePointsResult {
    /**
     * @return The display name for the vantage point. Display names are determined by the best information available and may change over time.
     * 
     */
    private @Nullable String displayName;
    private @Nullable List<GetVantagePointsFilter> filters;
    /**
     * @return The list of health_checks_vantage_points.
     * 
     */
    private List<GetVantagePointsHealthChecksVantagePoint> healthChecksVantagePoints;
    /**
     * @return The provider-assigned unique ID for this managed resource.
     * 
     */
    private String id;
    /**
     * @return The unique, permanent name for the vantage point.
     * 
     */
    private @Nullable String name;

    private GetVantagePointsResult() {}
    /**
     * @return The display name for the vantage point. Display names are determined by the best information available and may change over time.
     * 
     */
    public Optional<String> displayName() {
        return Optional.ofNullable(this.displayName);
    }
    public List<GetVantagePointsFilter> filters() {
        return this.filters == null ? List.of() : this.filters;
    }
    /**
     * @return The list of health_checks_vantage_points.
     * 
     */
    public List<GetVantagePointsHealthChecksVantagePoint> healthChecksVantagePoints() {
        return this.healthChecksVantagePoints;
    }
    /**
     * @return The provider-assigned unique ID for this managed resource.
     * 
     */
    public String id() {
        return this.id;
    }
    /**
     * @return The unique, permanent name for the vantage point.
     * 
     */
    public Optional<String> name() {
        return Optional.ofNullable(this.name);
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetVantagePointsResult defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private @Nullable String displayName;
        private @Nullable List<GetVantagePointsFilter> filters;
        private List<GetVantagePointsHealthChecksVantagePoint> healthChecksVantagePoints;
        private String id;
        private @Nullable String name;
        public Builder() {}
        public Builder(GetVantagePointsResult defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.displayName = defaults.displayName;
    	      this.filters = defaults.filters;
    	      this.healthChecksVantagePoints = defaults.healthChecksVantagePoints;
    	      this.id = defaults.id;
    	      this.name = defaults.name;
        }

        @CustomType.Setter
        public Builder displayName(@Nullable String displayName) {
            this.displayName = displayName;
            return this;
        }
        @CustomType.Setter
        public Builder filters(@Nullable List<GetVantagePointsFilter> filters) {
            this.filters = filters;
            return this;
        }
        public Builder filters(GetVantagePointsFilter... filters) {
            return filters(List.of(filters));
        }
        @CustomType.Setter
        public Builder healthChecksVantagePoints(List<GetVantagePointsHealthChecksVantagePoint> healthChecksVantagePoints) {
            this.healthChecksVantagePoints = Objects.requireNonNull(healthChecksVantagePoints);
            return this;
        }
        public Builder healthChecksVantagePoints(GetVantagePointsHealthChecksVantagePoint... healthChecksVantagePoints) {
            return healthChecksVantagePoints(List.of(healthChecksVantagePoints));
        }
        @CustomType.Setter
        public Builder id(String id) {
            this.id = Objects.requireNonNull(id);
            return this;
        }
        @CustomType.Setter
        public Builder name(@Nullable String name) {
            this.name = name;
            return this;
        }
        public GetVantagePointsResult build() {
            final var o = new GetVantagePointsResult();
            o.displayName = displayName;
            o.filters = filters;
            o.healthChecksVantagePoints = healthChecksVantagePoints;
            o.id = id;
            o.name = name;
            return o;
        }
    }
}