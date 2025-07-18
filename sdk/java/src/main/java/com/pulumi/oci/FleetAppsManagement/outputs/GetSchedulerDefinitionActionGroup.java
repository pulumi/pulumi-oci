// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.FleetAppsManagement.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.Integer;
import java.lang.String;
import java.util.Objects;

@CustomType
public final class GetSchedulerDefinitionActionGroup {
    /**
     * @return A user-friendly name. Does not have to be unique, and it&#39;s changeable. Avoid entering confidential information.  Example: `My new resource`
     * 
     */
    private String displayName;
    /**
     * @return ID of the fleet
     * 
     */
    private String fleetId;
    /**
     * @return Task argument kind
     * 
     */
    private String kind;
    /**
     * @return The ID of the Runbook
     * 
     */
    private String runbookId;
    /**
     * @return The runbook version name
     * 
     */
    private String runbookVersionName;
    /**
     * @return Sequence of the Action Group. Action groups will be executed in a seuential order. All Action Groups having the same sequence will be executed parallely. If no value is provided a default value of 1 will be given.
     * 
     */
    private Integer sequence;

    private GetSchedulerDefinitionActionGroup() {}
    /**
     * @return A user-friendly name. Does not have to be unique, and it&#39;s changeable. Avoid entering confidential information.  Example: `My new resource`
     * 
     */
    public String displayName() {
        return this.displayName;
    }
    /**
     * @return ID of the fleet
     * 
     */
    public String fleetId() {
        return this.fleetId;
    }
    /**
     * @return Task argument kind
     * 
     */
    public String kind() {
        return this.kind;
    }
    /**
     * @return The ID of the Runbook
     * 
     */
    public String runbookId() {
        return this.runbookId;
    }
    /**
     * @return The runbook version name
     * 
     */
    public String runbookVersionName() {
        return this.runbookVersionName;
    }
    /**
     * @return Sequence of the Action Group. Action groups will be executed in a seuential order. All Action Groups having the same sequence will be executed parallely. If no value is provided a default value of 1 will be given.
     * 
     */
    public Integer sequence() {
        return this.sequence;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetSchedulerDefinitionActionGroup defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String displayName;
        private String fleetId;
        private String kind;
        private String runbookId;
        private String runbookVersionName;
        private Integer sequence;
        public Builder() {}
        public Builder(GetSchedulerDefinitionActionGroup defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.displayName = defaults.displayName;
    	      this.fleetId = defaults.fleetId;
    	      this.kind = defaults.kind;
    	      this.runbookId = defaults.runbookId;
    	      this.runbookVersionName = defaults.runbookVersionName;
    	      this.sequence = defaults.sequence;
        }

        @CustomType.Setter
        public Builder displayName(String displayName) {
            if (displayName == null) {
              throw new MissingRequiredPropertyException("GetSchedulerDefinitionActionGroup", "displayName");
            }
            this.displayName = displayName;
            return this;
        }
        @CustomType.Setter
        public Builder fleetId(String fleetId) {
            if (fleetId == null) {
              throw new MissingRequiredPropertyException("GetSchedulerDefinitionActionGroup", "fleetId");
            }
            this.fleetId = fleetId;
            return this;
        }
        @CustomType.Setter
        public Builder kind(String kind) {
            if (kind == null) {
              throw new MissingRequiredPropertyException("GetSchedulerDefinitionActionGroup", "kind");
            }
            this.kind = kind;
            return this;
        }
        @CustomType.Setter
        public Builder runbookId(String runbookId) {
            if (runbookId == null) {
              throw new MissingRequiredPropertyException("GetSchedulerDefinitionActionGroup", "runbookId");
            }
            this.runbookId = runbookId;
            return this;
        }
        @CustomType.Setter
        public Builder runbookVersionName(String runbookVersionName) {
            if (runbookVersionName == null) {
              throw new MissingRequiredPropertyException("GetSchedulerDefinitionActionGroup", "runbookVersionName");
            }
            this.runbookVersionName = runbookVersionName;
            return this;
        }
        @CustomType.Setter
        public Builder sequence(Integer sequence) {
            if (sequence == null) {
              throw new MissingRequiredPropertyException("GetSchedulerDefinitionActionGroup", "sequence");
            }
            this.sequence = sequence;
            return this;
        }
        public GetSchedulerDefinitionActionGroup build() {
            final var _resultValue = new GetSchedulerDefinitionActionGroup();
            _resultValue.displayName = displayName;
            _resultValue.fleetId = fleetId;
            _resultValue.kind = kind;
            _resultValue.runbookId = runbookId;
            _resultValue.runbookVersionName = runbookVersionName;
            _resultValue.sequence = sequence;
            return _resultValue;
        }
    }
}
