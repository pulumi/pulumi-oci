// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DisasterRecovery.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.oci.DisasterRecovery.outputs.DrPlanPlanGroupStepUserDefinedStep;
import java.lang.Boolean;
import java.lang.Integer;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;

@CustomType
public final class DrPlanPlanGroupStep {
    /**
     * @return (Updatable) The display name of the DR Plan being created.  Example: `EBS Switchover PHX to IAD`
     * 
     */
    private @Nullable String displayName;
    /**
     * @return The error mode for this step.
     * 
     */
    private @Nullable String errorMode;
    /**
     * @return The unique id of the group to which this step belongs. Must not be modified by user.  Example: `sgid1.group..examplegroupsgid`
     * 
     */
    private @Nullable String groupId;
    /**
     * @return The unique id of this step. Must not be modified by the user.  Example: `sgid1.step..examplestepsgid`
     * 
     */
    private @Nullable String id;
    /**
     * @return A flag indicating whether this step should be enabled for execution.  Example: `true`
     * 
     */
    private @Nullable Boolean isEnabled;
    /**
     * @return The OCID of the member associated with this step.  Example: `ocid1.database.oc1.phx.exampleocid1`
     * 
     */
    private @Nullable String memberId;
    /**
     * @return The timeout in seconds for executing this step.  Example: `600`
     * 
     */
    private @Nullable Integer timeout;
    /**
     * @return The type of DR Plan to be created.
     * 
     */
    private @Nullable String type;
    /**
     * @return The details for a user-defined step in a DR Plan.
     * 
     */
    private @Nullable List<DrPlanPlanGroupStepUserDefinedStep> userDefinedSteps;

    private DrPlanPlanGroupStep() {}
    /**
     * @return (Updatable) The display name of the DR Plan being created.  Example: `EBS Switchover PHX to IAD`
     * 
     */
    public Optional<String> displayName() {
        return Optional.ofNullable(this.displayName);
    }
    /**
     * @return The error mode for this step.
     * 
     */
    public Optional<String> errorMode() {
        return Optional.ofNullable(this.errorMode);
    }
    /**
     * @return The unique id of the group to which this step belongs. Must not be modified by user.  Example: `sgid1.group..examplegroupsgid`
     * 
     */
    public Optional<String> groupId() {
        return Optional.ofNullable(this.groupId);
    }
    /**
     * @return The unique id of this step. Must not be modified by the user.  Example: `sgid1.step..examplestepsgid`
     * 
     */
    public Optional<String> id() {
        return Optional.ofNullable(this.id);
    }
    /**
     * @return A flag indicating whether this step should be enabled for execution.  Example: `true`
     * 
     */
    public Optional<Boolean> isEnabled() {
        return Optional.ofNullable(this.isEnabled);
    }
    /**
     * @return The OCID of the member associated with this step.  Example: `ocid1.database.oc1.phx.exampleocid1`
     * 
     */
    public Optional<String> memberId() {
        return Optional.ofNullable(this.memberId);
    }
    /**
     * @return The timeout in seconds for executing this step.  Example: `600`
     * 
     */
    public Optional<Integer> timeout() {
        return Optional.ofNullable(this.timeout);
    }
    /**
     * @return The type of DR Plan to be created.
     * 
     */
    public Optional<String> type() {
        return Optional.ofNullable(this.type);
    }
    /**
     * @return The details for a user-defined step in a DR Plan.
     * 
     */
    public List<DrPlanPlanGroupStepUserDefinedStep> userDefinedSteps() {
        return this.userDefinedSteps == null ? List.of() : this.userDefinedSteps;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(DrPlanPlanGroupStep defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private @Nullable String displayName;
        private @Nullable String errorMode;
        private @Nullable String groupId;
        private @Nullable String id;
        private @Nullable Boolean isEnabled;
        private @Nullable String memberId;
        private @Nullable Integer timeout;
        private @Nullable String type;
        private @Nullable List<DrPlanPlanGroupStepUserDefinedStep> userDefinedSteps;
        public Builder() {}
        public Builder(DrPlanPlanGroupStep defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.displayName = defaults.displayName;
    	      this.errorMode = defaults.errorMode;
    	      this.groupId = defaults.groupId;
    	      this.id = defaults.id;
    	      this.isEnabled = defaults.isEnabled;
    	      this.memberId = defaults.memberId;
    	      this.timeout = defaults.timeout;
    	      this.type = defaults.type;
    	      this.userDefinedSteps = defaults.userDefinedSteps;
        }

        @CustomType.Setter
        public Builder displayName(@Nullable String displayName) {
            this.displayName = displayName;
            return this;
        }
        @CustomType.Setter
        public Builder errorMode(@Nullable String errorMode) {
            this.errorMode = errorMode;
            return this;
        }
        @CustomType.Setter
        public Builder groupId(@Nullable String groupId) {
            this.groupId = groupId;
            return this;
        }
        @CustomType.Setter
        public Builder id(@Nullable String id) {
            this.id = id;
            return this;
        }
        @CustomType.Setter
        public Builder isEnabled(@Nullable Boolean isEnabled) {
            this.isEnabled = isEnabled;
            return this;
        }
        @CustomType.Setter
        public Builder memberId(@Nullable String memberId) {
            this.memberId = memberId;
            return this;
        }
        @CustomType.Setter
        public Builder timeout(@Nullable Integer timeout) {
            this.timeout = timeout;
            return this;
        }
        @CustomType.Setter
        public Builder type(@Nullable String type) {
            this.type = type;
            return this;
        }
        @CustomType.Setter
        public Builder userDefinedSteps(@Nullable List<DrPlanPlanGroupStepUserDefinedStep> userDefinedSteps) {
            this.userDefinedSteps = userDefinedSteps;
            return this;
        }
        public Builder userDefinedSteps(DrPlanPlanGroupStepUserDefinedStep... userDefinedSteps) {
            return userDefinedSteps(List.of(userDefinedSteps));
        }
        public DrPlanPlanGroupStep build() {
            final var o = new DrPlanPlanGroupStep();
            o.displayName = displayName;
            o.errorMode = errorMode;
            o.groupId = groupId;
            o.id = id;
            o.isEnabled = isEnabled;
            o.memberId = memberId;
            o.timeout = timeout;
            o.type = type;
            o.userDefinedSteps = userDefinedSteps;
            return o;
        }
    }
}