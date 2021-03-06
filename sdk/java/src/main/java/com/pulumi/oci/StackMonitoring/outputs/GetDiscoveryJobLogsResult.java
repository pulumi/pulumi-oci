// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.StackMonitoring.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.oci.StackMonitoring.outputs.GetDiscoveryJobLogsDiscoveryJobLogCollection;
import com.pulumi.oci.StackMonitoring.outputs.GetDiscoveryJobLogsFilter;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;

@CustomType
public final class GetDiscoveryJobLogsResult {
    private final String discoveryJobId;
    /**
     * @return The list of discovery_job_log_collection.
     * 
     */
    private final List<GetDiscoveryJobLogsDiscoveryJobLogCollection> discoveryJobLogCollections;
    private final @Nullable List<GetDiscoveryJobLogsFilter> filters;
    /**
     * @return The provider-assigned unique ID for this managed resource.
     * 
     */
    private final String id;
    /**
     * @return Type of log (INFO, WARNING, ERROR or SUCCESS)
     * 
     */
    private final @Nullable String logType;

    @CustomType.Constructor
    private GetDiscoveryJobLogsResult(
        @CustomType.Parameter("discoveryJobId") String discoveryJobId,
        @CustomType.Parameter("discoveryJobLogCollections") List<GetDiscoveryJobLogsDiscoveryJobLogCollection> discoveryJobLogCollections,
        @CustomType.Parameter("filters") @Nullable List<GetDiscoveryJobLogsFilter> filters,
        @CustomType.Parameter("id") String id,
        @CustomType.Parameter("logType") @Nullable String logType) {
        this.discoveryJobId = discoveryJobId;
        this.discoveryJobLogCollections = discoveryJobLogCollections;
        this.filters = filters;
        this.id = id;
        this.logType = logType;
    }

    public String discoveryJobId() {
        return this.discoveryJobId;
    }
    /**
     * @return The list of discovery_job_log_collection.
     * 
     */
    public List<GetDiscoveryJobLogsDiscoveryJobLogCollection> discoveryJobLogCollections() {
        return this.discoveryJobLogCollections;
    }
    public List<GetDiscoveryJobLogsFilter> filters() {
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
     * @return Type of log (INFO, WARNING, ERROR or SUCCESS)
     * 
     */
    public Optional<String> logType() {
        return Optional.ofNullable(this.logType);
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetDiscoveryJobLogsResult defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private String discoveryJobId;
        private List<GetDiscoveryJobLogsDiscoveryJobLogCollection> discoveryJobLogCollections;
        private @Nullable List<GetDiscoveryJobLogsFilter> filters;
        private String id;
        private @Nullable String logType;

        public Builder() {
    	      // Empty
        }

        public Builder(GetDiscoveryJobLogsResult defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.discoveryJobId = defaults.discoveryJobId;
    	      this.discoveryJobLogCollections = defaults.discoveryJobLogCollections;
    	      this.filters = defaults.filters;
    	      this.id = defaults.id;
    	      this.logType = defaults.logType;
        }

        public Builder discoveryJobId(String discoveryJobId) {
            this.discoveryJobId = Objects.requireNonNull(discoveryJobId);
            return this;
        }
        public Builder discoveryJobLogCollections(List<GetDiscoveryJobLogsDiscoveryJobLogCollection> discoveryJobLogCollections) {
            this.discoveryJobLogCollections = Objects.requireNonNull(discoveryJobLogCollections);
            return this;
        }
        public Builder discoveryJobLogCollections(GetDiscoveryJobLogsDiscoveryJobLogCollection... discoveryJobLogCollections) {
            return discoveryJobLogCollections(List.of(discoveryJobLogCollections));
        }
        public Builder filters(@Nullable List<GetDiscoveryJobLogsFilter> filters) {
            this.filters = filters;
            return this;
        }
        public Builder filters(GetDiscoveryJobLogsFilter... filters) {
            return filters(List.of(filters));
        }
        public Builder id(String id) {
            this.id = Objects.requireNonNull(id);
            return this;
        }
        public Builder logType(@Nullable String logType) {
            this.logType = logType;
            return this;
        }        public GetDiscoveryJobLogsResult build() {
            return new GetDiscoveryJobLogsResult(discoveryJobId, discoveryJobLogCollections, filters, id, logType);
        }
    }
}
