// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.ApiGateway.outputs;

import com.pulumi.core.annotations.CustomType;
import java.lang.Boolean;
import java.lang.String;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;

@CustomType
public final class DeploymentSpecificationLoggingPoliciesExecutionLog {
    /**
     * @return (Updatable) Enables pushing of execution logs to the legacy Oracle Cloud Infrastructure Object Storage log archival bucket.
     * 
     * Oracle recommends using the Oracle Cloud Infrastructure Logging service to enable, retrieve, and query execution logs for an API Deployment. If there is an active log object for the API Deployment and its category is set to &#39;execution&#39; in Oracle Cloud Infrastructure Logging service, the logs will not be uploaded to the legacy Oracle Cloud Infrastructure Object Storage log archival bucket.
     * 
     * Please note that the functionality to push to the legacy Oracle Cloud Infrastructure Object Storage log archival bucket has been deprecated and will be removed in the future.
     * 
     */
    private @Nullable Boolean isEnabled;
    /**
     * @return (Updatable) Specifies the log level used to control logging output of execution logs. Enabling logging at a given level also enables logging at all higher levels.
     * 
     */
    private @Nullable String logLevel;

    private DeploymentSpecificationLoggingPoliciesExecutionLog() {}
    /**
     * @return (Updatable) Enables pushing of execution logs to the legacy Oracle Cloud Infrastructure Object Storage log archival bucket.
     * 
     * Oracle recommends using the Oracle Cloud Infrastructure Logging service to enable, retrieve, and query execution logs for an API Deployment. If there is an active log object for the API Deployment and its category is set to &#39;execution&#39; in Oracle Cloud Infrastructure Logging service, the logs will not be uploaded to the legacy Oracle Cloud Infrastructure Object Storage log archival bucket.
     * 
     * Please note that the functionality to push to the legacy Oracle Cloud Infrastructure Object Storage log archival bucket has been deprecated and will be removed in the future.
     * 
     */
    public Optional<Boolean> isEnabled() {
        return Optional.ofNullable(this.isEnabled);
    }
    /**
     * @return (Updatable) Specifies the log level used to control logging output of execution logs. Enabling logging at a given level also enables logging at all higher levels.
     * 
     */
    public Optional<String> logLevel() {
        return Optional.ofNullable(this.logLevel);
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(DeploymentSpecificationLoggingPoliciesExecutionLog defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private @Nullable Boolean isEnabled;
        private @Nullable String logLevel;
        public Builder() {}
        public Builder(DeploymentSpecificationLoggingPoliciesExecutionLog defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.isEnabled = defaults.isEnabled;
    	      this.logLevel = defaults.logLevel;
        }

        @CustomType.Setter
        public Builder isEnabled(@Nullable Boolean isEnabled) {

            this.isEnabled = isEnabled;
            return this;
        }
        @CustomType.Setter
        public Builder logLevel(@Nullable String logLevel) {

            this.logLevel = logLevel;
            return this;
        }
        public DeploymentSpecificationLoggingPoliciesExecutionLog build() {
            final var _resultValue = new DeploymentSpecificationLoggingPoliciesExecutionLog();
            _resultValue.isEnabled = isEnabled;
            _resultValue.logLevel = logLevel;
            return _resultValue;
        }
    }
}
