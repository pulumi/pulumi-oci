// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.FleetAppsManagement.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.FleetAppsManagement.outputs.RunbookRunbookVersionGroupPropertiesRunOnPreviousTaskInstanceDetail;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;

@CustomType
public final class RunbookRunbookVersionGroupPropertiesRunOn {
    /**
     * @return Build control flow conditions that determine the relevance of the task execution.
     * 
     */
    private @Nullable String condition;
    /**
     * @return OCID of the self hosted instance.
     * 
     */
    private @Nullable String host;
    /**
     * @return Run on based On.
     * 
     */
    private String kind;
    /**
     * @return Previous Task Instance Details
     * 
     */
    private @Nullable List<RunbookRunbookVersionGroupPropertiesRunOnPreviousTaskInstanceDetail> previousTaskInstanceDetails;

    private RunbookRunbookVersionGroupPropertiesRunOn() {}
    /**
     * @return Build control flow conditions that determine the relevance of the task execution.
     * 
     */
    public Optional<String> condition() {
        return Optional.ofNullable(this.condition);
    }
    /**
     * @return OCID of the self hosted instance.
     * 
     */
    public Optional<String> host() {
        return Optional.ofNullable(this.host);
    }
    /**
     * @return Run on based On.
     * 
     */
    public String kind() {
        return this.kind;
    }
    /**
     * @return Previous Task Instance Details
     * 
     */
    public List<RunbookRunbookVersionGroupPropertiesRunOnPreviousTaskInstanceDetail> previousTaskInstanceDetails() {
        return this.previousTaskInstanceDetails == null ? List.of() : this.previousTaskInstanceDetails;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(RunbookRunbookVersionGroupPropertiesRunOn defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private @Nullable String condition;
        private @Nullable String host;
        private String kind;
        private @Nullable List<RunbookRunbookVersionGroupPropertiesRunOnPreviousTaskInstanceDetail> previousTaskInstanceDetails;
        public Builder() {}
        public Builder(RunbookRunbookVersionGroupPropertiesRunOn defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.condition = defaults.condition;
    	      this.host = defaults.host;
    	      this.kind = defaults.kind;
    	      this.previousTaskInstanceDetails = defaults.previousTaskInstanceDetails;
        }

        @CustomType.Setter
        public Builder condition(@Nullable String condition) {

            this.condition = condition;
            return this;
        }
        @CustomType.Setter
        public Builder host(@Nullable String host) {

            this.host = host;
            return this;
        }
        @CustomType.Setter
        public Builder kind(String kind) {
            if (kind == null) {
              throw new MissingRequiredPropertyException("RunbookRunbookVersionGroupPropertiesRunOn", "kind");
            }
            this.kind = kind;
            return this;
        }
        @CustomType.Setter
        public Builder previousTaskInstanceDetails(@Nullable List<RunbookRunbookVersionGroupPropertiesRunOnPreviousTaskInstanceDetail> previousTaskInstanceDetails) {

            this.previousTaskInstanceDetails = previousTaskInstanceDetails;
            return this;
        }
        public Builder previousTaskInstanceDetails(RunbookRunbookVersionGroupPropertiesRunOnPreviousTaskInstanceDetail... previousTaskInstanceDetails) {
            return previousTaskInstanceDetails(List.of(previousTaskInstanceDetails));
        }
        public RunbookRunbookVersionGroupPropertiesRunOn build() {
            final var _resultValue = new RunbookRunbookVersionGroupPropertiesRunOn();
            _resultValue.condition = condition;
            _resultValue.host = host;
            _resultValue.kind = kind;
            _resultValue.previousTaskInstanceDetails = previousTaskInstanceDetails;
            return _resultValue;
        }
    }
}
