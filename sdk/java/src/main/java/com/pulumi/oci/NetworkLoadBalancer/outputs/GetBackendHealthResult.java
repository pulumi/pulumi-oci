// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.NetworkLoadBalancer.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.oci.NetworkLoadBalancer.outputs.GetBackendHealthHealthCheckResult;
import java.lang.String;
import java.util.List;
import java.util.Objects;

@CustomType
public final class GetBackendHealthResult {
    private final String backendName;
    private final String backendSetName;
    /**
     * @return A list of the most recent health check results returned for the specified backend server.
     * 
     */
    private final List<GetBackendHealthHealthCheckResult> healthCheckResults;
    /**
     * @return The provider-assigned unique ID for this managed resource.
     * 
     */
    private final String id;
    private final String networkLoadBalancerId;
    /**
     * @return The general health status of the specified backend server.
     * *   **OK:**  All health check probes return `OK`
     * *   **WARNING:** At least one of the health check probes does not return `OK`
     * *   **CRITICAL:** None of the health check probes return `OK`. *
     * *   **UNKNOWN:** One of the health checks probes return `UNKNOWN`,
     * *   or the system is unable to retrieve metrics at this time.
     * 
     */
    private final String status;

    @CustomType.Constructor
    private GetBackendHealthResult(
        @CustomType.Parameter("backendName") String backendName,
        @CustomType.Parameter("backendSetName") String backendSetName,
        @CustomType.Parameter("healthCheckResults") List<GetBackendHealthHealthCheckResult> healthCheckResults,
        @CustomType.Parameter("id") String id,
        @CustomType.Parameter("networkLoadBalancerId") String networkLoadBalancerId,
        @CustomType.Parameter("status") String status) {
        this.backendName = backendName;
        this.backendSetName = backendSetName;
        this.healthCheckResults = healthCheckResults;
        this.id = id;
        this.networkLoadBalancerId = networkLoadBalancerId;
        this.status = status;
    }

    public String backendName() {
        return this.backendName;
    }
    public String backendSetName() {
        return this.backendSetName;
    }
    /**
     * @return A list of the most recent health check results returned for the specified backend server.
     * 
     */
    public List<GetBackendHealthHealthCheckResult> healthCheckResults() {
        return this.healthCheckResults;
    }
    /**
     * @return The provider-assigned unique ID for this managed resource.
     * 
     */
    public String id() {
        return this.id;
    }
    public String networkLoadBalancerId() {
        return this.networkLoadBalancerId;
    }
    /**
     * @return The general health status of the specified backend server.
     * *   **OK:**  All health check probes return `OK`
     * *   **WARNING:** At least one of the health check probes does not return `OK`
     * *   **CRITICAL:** None of the health check probes return `OK`. *
     * *   **UNKNOWN:** One of the health checks probes return `UNKNOWN`,
     * *   or the system is unable to retrieve metrics at this time.
     * 
     */
    public String status() {
        return this.status;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetBackendHealthResult defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private String backendName;
        private String backendSetName;
        private List<GetBackendHealthHealthCheckResult> healthCheckResults;
        private String id;
        private String networkLoadBalancerId;
        private String status;

        public Builder() {
    	      // Empty
        }

        public Builder(GetBackendHealthResult defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.backendName = defaults.backendName;
    	      this.backendSetName = defaults.backendSetName;
    	      this.healthCheckResults = defaults.healthCheckResults;
    	      this.id = defaults.id;
    	      this.networkLoadBalancerId = defaults.networkLoadBalancerId;
    	      this.status = defaults.status;
        }

        public Builder backendName(String backendName) {
            this.backendName = Objects.requireNonNull(backendName);
            return this;
        }
        public Builder backendSetName(String backendSetName) {
            this.backendSetName = Objects.requireNonNull(backendSetName);
            return this;
        }
        public Builder healthCheckResults(List<GetBackendHealthHealthCheckResult> healthCheckResults) {
            this.healthCheckResults = Objects.requireNonNull(healthCheckResults);
            return this;
        }
        public Builder healthCheckResults(GetBackendHealthHealthCheckResult... healthCheckResults) {
            return healthCheckResults(List.of(healthCheckResults));
        }
        public Builder id(String id) {
            this.id = Objects.requireNonNull(id);
            return this;
        }
        public Builder networkLoadBalancerId(String networkLoadBalancerId) {
            this.networkLoadBalancerId = Objects.requireNonNull(networkLoadBalancerId);
            return this;
        }
        public Builder status(String status) {
            this.status = Objects.requireNonNull(status);
            return this;
        }        public GetBackendHealthResult build() {
            return new GetBackendHealthResult(backendName, backendSetName, healthCheckResults, id, networkLoadBalancerId, status);
        }
    }
}
