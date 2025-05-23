// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DataScience.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.Boolean;
import java.lang.String;
import java.util.Objects;

@CustomType
public final class GetScheduleActionActionDetailCreatePipelineRunDetailLogConfigurationOverrideDetail {
    /**
     * @return If automatic on-behalf-of log object creation is enabled for pipeline runs.
     * 
     */
    private Boolean enableAutoLogCreation;
    /**
     * @return If customer logging is enabled for pipeline.
     * 
     */
    private Boolean enableLogging;
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the log group.
     * 
     */
    private String logGroupId;
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the custom log to be used for Schedule logging.
     * 
     */
    private String logId;

    private GetScheduleActionActionDetailCreatePipelineRunDetailLogConfigurationOverrideDetail() {}
    /**
     * @return If automatic on-behalf-of log object creation is enabled for pipeline runs.
     * 
     */
    public Boolean enableAutoLogCreation() {
        return this.enableAutoLogCreation;
    }
    /**
     * @return If customer logging is enabled for pipeline.
     * 
     */
    public Boolean enableLogging() {
        return this.enableLogging;
    }
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the log group.
     * 
     */
    public String logGroupId() {
        return this.logGroupId;
    }
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the custom log to be used for Schedule logging.
     * 
     */
    public String logId() {
        return this.logId;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetScheduleActionActionDetailCreatePipelineRunDetailLogConfigurationOverrideDetail defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private Boolean enableAutoLogCreation;
        private Boolean enableLogging;
        private String logGroupId;
        private String logId;
        public Builder() {}
        public Builder(GetScheduleActionActionDetailCreatePipelineRunDetailLogConfigurationOverrideDetail defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.enableAutoLogCreation = defaults.enableAutoLogCreation;
    	      this.enableLogging = defaults.enableLogging;
    	      this.logGroupId = defaults.logGroupId;
    	      this.logId = defaults.logId;
        }

        @CustomType.Setter
        public Builder enableAutoLogCreation(Boolean enableAutoLogCreation) {
            if (enableAutoLogCreation == null) {
              throw new MissingRequiredPropertyException("GetScheduleActionActionDetailCreatePipelineRunDetailLogConfigurationOverrideDetail", "enableAutoLogCreation");
            }
            this.enableAutoLogCreation = enableAutoLogCreation;
            return this;
        }
        @CustomType.Setter
        public Builder enableLogging(Boolean enableLogging) {
            if (enableLogging == null) {
              throw new MissingRequiredPropertyException("GetScheduleActionActionDetailCreatePipelineRunDetailLogConfigurationOverrideDetail", "enableLogging");
            }
            this.enableLogging = enableLogging;
            return this;
        }
        @CustomType.Setter
        public Builder logGroupId(String logGroupId) {
            if (logGroupId == null) {
              throw new MissingRequiredPropertyException("GetScheduleActionActionDetailCreatePipelineRunDetailLogConfigurationOverrideDetail", "logGroupId");
            }
            this.logGroupId = logGroupId;
            return this;
        }
        @CustomType.Setter
        public Builder logId(String logId) {
            if (logId == null) {
              throw new MissingRequiredPropertyException("GetScheduleActionActionDetailCreatePipelineRunDetailLogConfigurationOverrideDetail", "logId");
            }
            this.logId = logId;
            return this;
        }
        public GetScheduleActionActionDetailCreatePipelineRunDetailLogConfigurationOverrideDetail build() {
            final var _resultValue = new GetScheduleActionActionDetailCreatePipelineRunDetailLogConfigurationOverrideDetail();
            _resultValue.enableAutoLogCreation = enableAutoLogCreation;
            _resultValue.enableLogging = enableLogging;
            _resultValue.logGroupId = logGroupId;
            _resultValue.logId = logId;
            return _resultValue;
        }
    }
}
