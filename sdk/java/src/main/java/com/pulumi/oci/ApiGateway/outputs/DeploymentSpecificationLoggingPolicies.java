// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.ApiGateway.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.oci.ApiGateway.outputs.DeploymentSpecificationLoggingPoliciesAccessLog;
import com.pulumi.oci.ApiGateway.outputs.DeploymentSpecificationLoggingPoliciesExecutionLog;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;

@CustomType
public final class DeploymentSpecificationLoggingPolicies {
    /**
     * @return (Updatable) Configures the logging policies for the access logs of an API Deployment.
     * 
     */
    private @Nullable DeploymentSpecificationLoggingPoliciesAccessLog accessLog;
    /**
     * @return (Updatable) Configures the logging policies for the execution logs of an API Deployment.
     * 
     */
    private @Nullable DeploymentSpecificationLoggingPoliciesExecutionLog executionLog;

    private DeploymentSpecificationLoggingPolicies() {}
    /**
     * @return (Updatable) Configures the logging policies for the access logs of an API Deployment.
     * 
     */
    public Optional<DeploymentSpecificationLoggingPoliciesAccessLog> accessLog() {
        return Optional.ofNullable(this.accessLog);
    }
    /**
     * @return (Updatable) Configures the logging policies for the execution logs of an API Deployment.
     * 
     */
    public Optional<DeploymentSpecificationLoggingPoliciesExecutionLog> executionLog() {
        return Optional.ofNullable(this.executionLog);
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(DeploymentSpecificationLoggingPolicies defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private @Nullable DeploymentSpecificationLoggingPoliciesAccessLog accessLog;
        private @Nullable DeploymentSpecificationLoggingPoliciesExecutionLog executionLog;
        public Builder() {}
        public Builder(DeploymentSpecificationLoggingPolicies defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.accessLog = defaults.accessLog;
    	      this.executionLog = defaults.executionLog;
        }

        @CustomType.Setter
        public Builder accessLog(@Nullable DeploymentSpecificationLoggingPoliciesAccessLog accessLog) {

            this.accessLog = accessLog;
            return this;
        }
        @CustomType.Setter
        public Builder executionLog(@Nullable DeploymentSpecificationLoggingPoliciesExecutionLog executionLog) {

            this.executionLog = executionLog;
            return this;
        }
        public DeploymentSpecificationLoggingPolicies build() {
            final var _resultValue = new DeploymentSpecificationLoggingPolicies();
            _resultValue.accessLog = accessLog;
            _resultValue.executionLog = executionLog;
            return _resultValue;
        }
    }
}
