// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.HealthChecks.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.oci.HealthChecks.outputs.GetHttpMonitorsFilter;
import com.pulumi.oci.HealthChecks.outputs.GetHttpMonitorsHttpMonitor;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;

@CustomType
public final class GetHttpMonitorsResult {
    /**
     * @return The OCID of the compartment.
     * 
     */
    private final String compartmentId;
    /**
     * @return A user-friendly and mutable name suitable for display in a user interface.
     * 
     */
    private final @Nullable String displayName;
    private final @Nullable List<GetHttpMonitorsFilter> filters;
    /**
     * @return The region where updates must be made and where results must be fetched from.
     * 
     */
    private final @Nullable String homeRegion;
    /**
     * @return The list of http_monitors.
     * 
     */
    private final List<GetHttpMonitorsHttpMonitor> httpMonitors;
    /**
     * @return The provider-assigned unique ID for this managed resource.
     * 
     */
    private final String id;

    @CustomType.Constructor
    private GetHttpMonitorsResult(
        @CustomType.Parameter("compartmentId") String compartmentId,
        @CustomType.Parameter("displayName") @Nullable String displayName,
        @CustomType.Parameter("filters") @Nullable List<GetHttpMonitorsFilter> filters,
        @CustomType.Parameter("homeRegion") @Nullable String homeRegion,
        @CustomType.Parameter("httpMonitors") List<GetHttpMonitorsHttpMonitor> httpMonitors,
        @CustomType.Parameter("id") String id) {
        this.compartmentId = compartmentId;
        this.displayName = displayName;
        this.filters = filters;
        this.homeRegion = homeRegion;
        this.httpMonitors = httpMonitors;
        this.id = id;
    }

    /**
     * @return The OCID of the compartment.
     * 
     */
    public String compartmentId() {
        return this.compartmentId;
    }
    /**
     * @return A user-friendly and mutable name suitable for display in a user interface.
     * 
     */
    public Optional<String> displayName() {
        return Optional.ofNullable(this.displayName);
    }
    public List<GetHttpMonitorsFilter> filters() {
        return this.filters == null ? List.of() : this.filters;
    }
    /**
     * @return The region where updates must be made and where results must be fetched from.
     * 
     */
    public Optional<String> homeRegion() {
        return Optional.ofNullable(this.homeRegion);
    }
    /**
     * @return The list of http_monitors.
     * 
     */
    public List<GetHttpMonitorsHttpMonitor> httpMonitors() {
        return this.httpMonitors;
    }
    /**
     * @return The provider-assigned unique ID for this managed resource.
     * 
     */
    public String id() {
        return this.id;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetHttpMonitorsResult defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private String compartmentId;
        private @Nullable String displayName;
        private @Nullable List<GetHttpMonitorsFilter> filters;
        private @Nullable String homeRegion;
        private List<GetHttpMonitorsHttpMonitor> httpMonitors;
        private String id;

        public Builder() {
    	      // Empty
        }

        public Builder(GetHttpMonitorsResult defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.compartmentId = defaults.compartmentId;
    	      this.displayName = defaults.displayName;
    	      this.filters = defaults.filters;
    	      this.homeRegion = defaults.homeRegion;
    	      this.httpMonitors = defaults.httpMonitors;
    	      this.id = defaults.id;
        }

        public Builder compartmentId(String compartmentId) {
            this.compartmentId = Objects.requireNonNull(compartmentId);
            return this;
        }
        public Builder displayName(@Nullable String displayName) {
            this.displayName = displayName;
            return this;
        }
        public Builder filters(@Nullable List<GetHttpMonitorsFilter> filters) {
            this.filters = filters;
            return this;
        }
        public Builder filters(GetHttpMonitorsFilter... filters) {
            return filters(List.of(filters));
        }
        public Builder homeRegion(@Nullable String homeRegion) {
            this.homeRegion = homeRegion;
            return this;
        }
        public Builder httpMonitors(List<GetHttpMonitorsHttpMonitor> httpMonitors) {
            this.httpMonitors = Objects.requireNonNull(httpMonitors);
            return this;
        }
        public Builder httpMonitors(GetHttpMonitorsHttpMonitor... httpMonitors) {
            return httpMonitors(List.of(httpMonitors));
        }
        public Builder id(String id) {
            this.id = Objects.requireNonNull(id);
            return this;
        }        public GetHttpMonitorsResult build() {
            return new GetHttpMonitorsResult(compartmentId, displayName, filters, homeRegion, httpMonitors, id);
        }
    }
}
