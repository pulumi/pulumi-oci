// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DataScience.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.DataScience.outputs.GetMlApplicationImplementationLoggingAggregatedInstanceViewLog;
import com.pulumi.oci.DataScience.outputs.GetMlApplicationImplementationLoggingImplementationLog;
import com.pulumi.oci.DataScience.outputs.GetMlApplicationImplementationLoggingTriggerLog;
import java.util.List;
import java.util.Objects;

@CustomType
public final class GetMlApplicationImplementationLogging {
    /**
     * @return Log configuration details for particular areas of ML Application Implementation.
     * 
     */
    private List<GetMlApplicationImplementationLoggingAggregatedInstanceViewLog> aggregatedInstanceViewLogs;
    /**
     * @return Log configuration details for particular areas of ML Application Implementation.
     * 
     */
    private List<GetMlApplicationImplementationLoggingImplementationLog> implementationLogs;
    /**
     * @return Log configuration details for particular areas of ML Application Implementation.
     * 
     */
    private List<GetMlApplicationImplementationLoggingTriggerLog> triggerLogs;

    private GetMlApplicationImplementationLogging() {}
    /**
     * @return Log configuration details for particular areas of ML Application Implementation.
     * 
     */
    public List<GetMlApplicationImplementationLoggingAggregatedInstanceViewLog> aggregatedInstanceViewLogs() {
        return this.aggregatedInstanceViewLogs;
    }
    /**
     * @return Log configuration details for particular areas of ML Application Implementation.
     * 
     */
    public List<GetMlApplicationImplementationLoggingImplementationLog> implementationLogs() {
        return this.implementationLogs;
    }
    /**
     * @return Log configuration details for particular areas of ML Application Implementation.
     * 
     */
    public List<GetMlApplicationImplementationLoggingTriggerLog> triggerLogs() {
        return this.triggerLogs;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetMlApplicationImplementationLogging defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private List<GetMlApplicationImplementationLoggingAggregatedInstanceViewLog> aggregatedInstanceViewLogs;
        private List<GetMlApplicationImplementationLoggingImplementationLog> implementationLogs;
        private List<GetMlApplicationImplementationLoggingTriggerLog> triggerLogs;
        public Builder() {}
        public Builder(GetMlApplicationImplementationLogging defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.aggregatedInstanceViewLogs = defaults.aggregatedInstanceViewLogs;
    	      this.implementationLogs = defaults.implementationLogs;
    	      this.triggerLogs = defaults.triggerLogs;
        }

        @CustomType.Setter
        public Builder aggregatedInstanceViewLogs(List<GetMlApplicationImplementationLoggingAggregatedInstanceViewLog> aggregatedInstanceViewLogs) {
            if (aggregatedInstanceViewLogs == null) {
              throw new MissingRequiredPropertyException("GetMlApplicationImplementationLogging", "aggregatedInstanceViewLogs");
            }
            this.aggregatedInstanceViewLogs = aggregatedInstanceViewLogs;
            return this;
        }
        public Builder aggregatedInstanceViewLogs(GetMlApplicationImplementationLoggingAggregatedInstanceViewLog... aggregatedInstanceViewLogs) {
            return aggregatedInstanceViewLogs(List.of(aggregatedInstanceViewLogs));
        }
        @CustomType.Setter
        public Builder implementationLogs(List<GetMlApplicationImplementationLoggingImplementationLog> implementationLogs) {
            if (implementationLogs == null) {
              throw new MissingRequiredPropertyException("GetMlApplicationImplementationLogging", "implementationLogs");
            }
            this.implementationLogs = implementationLogs;
            return this;
        }
        public Builder implementationLogs(GetMlApplicationImplementationLoggingImplementationLog... implementationLogs) {
            return implementationLogs(List.of(implementationLogs));
        }
        @CustomType.Setter
        public Builder triggerLogs(List<GetMlApplicationImplementationLoggingTriggerLog> triggerLogs) {
            if (triggerLogs == null) {
              throw new MissingRequiredPropertyException("GetMlApplicationImplementationLogging", "triggerLogs");
            }
            this.triggerLogs = triggerLogs;
            return this;
        }
        public Builder triggerLogs(GetMlApplicationImplementationLoggingTriggerLog... triggerLogs) {
            return triggerLogs(List.of(triggerLogs));
        }
        public GetMlApplicationImplementationLogging build() {
            final var _resultValue = new GetMlApplicationImplementationLogging();
            _resultValue.aggregatedInstanceViewLogs = aggregatedInstanceViewLogs;
            _resultValue.implementationLogs = implementationLogs;
            _resultValue.triggerLogs = triggerLogs;
            return _resultValue;
        }
    }
}
