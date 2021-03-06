// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.HealthChecks.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.oci.HealthChecks.outputs.GetPingProbeResultsFilter;
import com.pulumi.oci.HealthChecks.outputs.GetPingProbeResultsPingProbeResult;
import java.lang.Double;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;

@CustomType
public final class GetPingProbeResultsResult {
    private final @Nullable List<GetPingProbeResultsFilter> filters;
    /**
     * @return The provider-assigned unique ID for this managed resource.
     * 
     */
    private final String id;
    /**
     * @return The list of ping_probe_results.
     * 
     */
    private final List<GetPingProbeResultsPingProbeResult> pingProbeResults;
    /**
     * @return The OCID of the monitor or on-demand probe responsible for creating this result.
     * 
     */
    private final String probeConfigurationId;
    private final @Nullable Double startTimeGreaterThanOrEqualTo;
    private final @Nullable Double startTimeLessThanOrEqualTo;
    /**
     * @return The target hostname or IP address of the probe.
     * 
     */
    private final @Nullable String target;

    @CustomType.Constructor
    private GetPingProbeResultsResult(
        @CustomType.Parameter("filters") @Nullable List<GetPingProbeResultsFilter> filters,
        @CustomType.Parameter("id") String id,
        @CustomType.Parameter("pingProbeResults") List<GetPingProbeResultsPingProbeResult> pingProbeResults,
        @CustomType.Parameter("probeConfigurationId") String probeConfigurationId,
        @CustomType.Parameter("startTimeGreaterThanOrEqualTo") @Nullable Double startTimeGreaterThanOrEqualTo,
        @CustomType.Parameter("startTimeLessThanOrEqualTo") @Nullable Double startTimeLessThanOrEqualTo,
        @CustomType.Parameter("target") @Nullable String target) {
        this.filters = filters;
        this.id = id;
        this.pingProbeResults = pingProbeResults;
        this.probeConfigurationId = probeConfigurationId;
        this.startTimeGreaterThanOrEqualTo = startTimeGreaterThanOrEqualTo;
        this.startTimeLessThanOrEqualTo = startTimeLessThanOrEqualTo;
        this.target = target;
    }

    public List<GetPingProbeResultsFilter> filters() {
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
     * @return The list of ping_probe_results.
     * 
     */
    public List<GetPingProbeResultsPingProbeResult> pingProbeResults() {
        return this.pingProbeResults;
    }
    /**
     * @return The OCID of the monitor or on-demand probe responsible for creating this result.
     * 
     */
    public String probeConfigurationId() {
        return this.probeConfigurationId;
    }
    public Optional<Double> startTimeGreaterThanOrEqualTo() {
        return Optional.ofNullable(this.startTimeGreaterThanOrEqualTo);
    }
    public Optional<Double> startTimeLessThanOrEqualTo() {
        return Optional.ofNullable(this.startTimeLessThanOrEqualTo);
    }
    /**
     * @return The target hostname or IP address of the probe.
     * 
     */
    public Optional<String> target() {
        return Optional.ofNullable(this.target);
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetPingProbeResultsResult defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private @Nullable List<GetPingProbeResultsFilter> filters;
        private String id;
        private List<GetPingProbeResultsPingProbeResult> pingProbeResults;
        private String probeConfigurationId;
        private @Nullable Double startTimeGreaterThanOrEqualTo;
        private @Nullable Double startTimeLessThanOrEqualTo;
        private @Nullable String target;

        public Builder() {
    	      // Empty
        }

        public Builder(GetPingProbeResultsResult defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.filters = defaults.filters;
    	      this.id = defaults.id;
    	      this.pingProbeResults = defaults.pingProbeResults;
    	      this.probeConfigurationId = defaults.probeConfigurationId;
    	      this.startTimeGreaterThanOrEqualTo = defaults.startTimeGreaterThanOrEqualTo;
    	      this.startTimeLessThanOrEqualTo = defaults.startTimeLessThanOrEqualTo;
    	      this.target = defaults.target;
        }

        public Builder filters(@Nullable List<GetPingProbeResultsFilter> filters) {
            this.filters = filters;
            return this;
        }
        public Builder filters(GetPingProbeResultsFilter... filters) {
            return filters(List.of(filters));
        }
        public Builder id(String id) {
            this.id = Objects.requireNonNull(id);
            return this;
        }
        public Builder pingProbeResults(List<GetPingProbeResultsPingProbeResult> pingProbeResults) {
            this.pingProbeResults = Objects.requireNonNull(pingProbeResults);
            return this;
        }
        public Builder pingProbeResults(GetPingProbeResultsPingProbeResult... pingProbeResults) {
            return pingProbeResults(List.of(pingProbeResults));
        }
        public Builder probeConfigurationId(String probeConfigurationId) {
            this.probeConfigurationId = Objects.requireNonNull(probeConfigurationId);
            return this;
        }
        public Builder startTimeGreaterThanOrEqualTo(@Nullable Double startTimeGreaterThanOrEqualTo) {
            this.startTimeGreaterThanOrEqualTo = startTimeGreaterThanOrEqualTo;
            return this;
        }
        public Builder startTimeLessThanOrEqualTo(@Nullable Double startTimeLessThanOrEqualTo) {
            this.startTimeLessThanOrEqualTo = startTimeLessThanOrEqualTo;
            return this;
        }
        public Builder target(@Nullable String target) {
            this.target = target;
            return this;
        }        public GetPingProbeResultsResult build() {
            return new GetPingProbeResultsResult(filters, id, pingProbeResults, probeConfigurationId, startTimeGreaterThanOrEqualTo, startTimeLessThanOrEqualTo, target);
        }
    }
}
