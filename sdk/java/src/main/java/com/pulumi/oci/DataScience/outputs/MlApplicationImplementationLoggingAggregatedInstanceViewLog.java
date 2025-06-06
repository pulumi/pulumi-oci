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
public final class MlApplicationImplementationLoggingAggregatedInstanceViewLog {
    /**
     * @return (Updatable) If logging is enabled.
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

    private MlApplicationImplementationLoggingAggregatedInstanceViewLog() {}
    /**
     * @return (Updatable) If logging is enabled.
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

    public static Builder builder(MlApplicationImplementationLoggingAggregatedInstanceViewLog defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private @Nullable Boolean enableLogging;
        private @Nullable String logGroupId;
        private @Nullable String logId;
        public Builder() {}
        public Builder(MlApplicationImplementationLoggingAggregatedInstanceViewLog defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.enableLogging = defaults.enableLogging;
    	      this.logGroupId = defaults.logGroupId;
    	      this.logId = defaults.logId;
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
        public MlApplicationImplementationLoggingAggregatedInstanceViewLog build() {
            final var _resultValue = new MlApplicationImplementationLoggingAggregatedInstanceViewLog();
            _resultValue.enableLogging = enableLogging;
            _resultValue.logGroupId = logGroupId;
            _resultValue.logId = logId;
            return _resultValue;
        }
    }
}
