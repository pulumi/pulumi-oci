// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DataScience.outputs;

import com.pulumi.core.annotations.CustomType;
import java.lang.Boolean;
import java.lang.String;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;

@CustomType
public final class PipelineLogConfigurationDetails {
    /**
     * @return (Updatable) If automatic on-behalf-of log object creation is enabled for pipeline runs.
     * 
     */
    private @Nullable Boolean enableAutoLogCreation;
    /**
     * @return (Updatable) If customer logging is enabled for pipeline.
     * 
     */
    private @Nullable Boolean enableLogging;
    /**
     * @return (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the log group.
     * 
     */
    private @Nullable String logGroupId;
    /**
     * @return (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the log.
     * 
     */
    private @Nullable String logId;

    private PipelineLogConfigurationDetails() {}
    /**
     * @return (Updatable) If automatic on-behalf-of log object creation is enabled for pipeline runs.
     * 
     */
    public Optional<Boolean> enableAutoLogCreation() {
        return Optional.ofNullable(this.enableAutoLogCreation);
    }
    /**
     * @return (Updatable) If customer logging is enabled for pipeline.
     * 
     */
    public Optional<Boolean> enableLogging() {
        return Optional.ofNullable(this.enableLogging);
    }
    /**
     * @return (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the log group.
     * 
     */
    public Optional<String> logGroupId() {
        return Optional.ofNullable(this.logGroupId);
    }
    /**
     * @return (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the log.
     * 
     */
    public Optional<String> logId() {
        return Optional.ofNullable(this.logId);
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(PipelineLogConfigurationDetails defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private @Nullable Boolean enableAutoLogCreation;
        private @Nullable Boolean enableLogging;
        private @Nullable String logGroupId;
        private @Nullable String logId;
        public Builder() {}
        public Builder(PipelineLogConfigurationDetails defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.enableAutoLogCreation = defaults.enableAutoLogCreation;
    	      this.enableLogging = defaults.enableLogging;
    	      this.logGroupId = defaults.logGroupId;
    	      this.logId = defaults.logId;
        }

        @CustomType.Setter
        public Builder enableAutoLogCreation(@Nullable Boolean enableAutoLogCreation) {
            this.enableAutoLogCreation = enableAutoLogCreation;
            return this;
        }
        @CustomType.Setter
        public Builder enableLogging(@Nullable Boolean enableLogging) {
            this.enableLogging = enableLogging;
            return this;
        }
        @CustomType.Setter
        public Builder logGroupId(@Nullable String logGroupId) {
            this.logGroupId = logGroupId;
            return this;
        }
        @CustomType.Setter
        public Builder logId(@Nullable String logId) {
            this.logId = logId;
            return this;
        }
        public PipelineLogConfigurationDetails build() {
            final var o = new PipelineLogConfigurationDetails();
            o.enableAutoLogCreation = enableAutoLogCreation;
            o.enableLogging = enableLogging;
            o.logGroupId = logGroupId;
            o.logId = logId;
            return o;
        }
    }
}