// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.NetworkLoadBalancer.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.String;
import java.util.Objects;

@CustomType
public final class GetBackendHealthHealthCheckResult {
    /**
     * @return The result of the most recent health check.
     * 
     */
    private String healthCheckStatus;
    /**
     * @return The date and time the data was retrieved, in the format defined by RFC3339.  Example: `2020-05-01T18:28:11+00:00`
     * 
     */
    private String timestamp;

    private GetBackendHealthHealthCheckResult() {}
    /**
     * @return The result of the most recent health check.
     * 
     */
    public String healthCheckStatus() {
        return this.healthCheckStatus;
    }
    /**
     * @return The date and time the data was retrieved, in the format defined by RFC3339.  Example: `2020-05-01T18:28:11+00:00`
     * 
     */
    public String timestamp() {
        return this.timestamp;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetBackendHealthHealthCheckResult defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String healthCheckStatus;
        private String timestamp;
        public Builder() {}
        public Builder(GetBackendHealthHealthCheckResult defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.healthCheckStatus = defaults.healthCheckStatus;
    	      this.timestamp = defaults.timestamp;
        }

        @CustomType.Setter
        public Builder healthCheckStatus(String healthCheckStatus) {
            if (healthCheckStatus == null) {
              throw new MissingRequiredPropertyException("GetBackendHealthHealthCheckResult", "healthCheckStatus");
            }
            this.healthCheckStatus = healthCheckStatus;
            return this;
        }
        @CustomType.Setter
        public Builder timestamp(String timestamp) {
            if (timestamp == null) {
              throw new MissingRequiredPropertyException("GetBackendHealthHealthCheckResult", "timestamp");
            }
            this.timestamp = timestamp;
            return this;
        }
        public GetBackendHealthHealthCheckResult build() {
            final var _resultValue = new GetBackendHealthHealthCheckResult();
            _resultValue.healthCheckStatus = healthCheckStatus;
            _resultValue.timestamp = timestamp;
            return _resultValue;
        }
    }
}
