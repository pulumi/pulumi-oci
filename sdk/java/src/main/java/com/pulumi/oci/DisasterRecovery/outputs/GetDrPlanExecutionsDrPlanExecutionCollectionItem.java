// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DisasterRecovery.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.oci.DisasterRecovery.outputs.GetDrPlanExecutionsDrPlanExecutionCollectionItemExecutionOption;
import com.pulumi.oci.DisasterRecovery.outputs.GetDrPlanExecutionsDrPlanExecutionCollectionItemGroupExecution;
import com.pulumi.oci.DisasterRecovery.outputs.GetDrPlanExecutionsDrPlanExecutionCollectionItemLogLocation;
import java.lang.Integer;
import java.lang.Object;
import java.lang.String;
import java.util.List;
import java.util.Map;
import java.util.Objects;

@CustomType
public final class GetDrPlanExecutionsDrPlanExecutionCollectionItem {
    /**
     * @return The OCID of the compartment containing this DR Plan Execution.  Example: `ocid1.compartment.oc1..exampleocid1`
     * 
     */
    private String compartmentId;
    /**
     * @return Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{&#34;Operations.CostCenter&#34;: &#34;42&#34;}`
     * 
     */
    private Map<String,Object> definedTags;
    /**
     * @return A filter to return only resources that match the entire display name given.  Example: `MY UNIQUE DISPLAY NAME`
     * 
     */
    private String displayName;
    /**
     * @return The OCID of the DR Protection Group. Mandatory query param.  Example: `ocid1.drprotectiongroup.oc1.phx.exampleocid`
     * 
     */
    private String drProtectionGroupId;
    /**
     * @return The total duration in seconds taken to complete step execution.  Example: `35`
     * 
     */
    private Integer executionDurationInSec;
    /**
     * @return The options for a plan execution.
     * 
     */
    private List<GetDrPlanExecutionsDrPlanExecutionCollectionItemExecutionOption> executionOptions;
    /**
     * @return Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{&#34;Department&#34;: &#34;Finance&#34;}`
     * 
     */
    private Map<String,Object> freeformTags;
    /**
     * @return A list of groups executed in this DR Plan Execution.
     * 
     */
    private List<GetDrPlanExecutionsDrPlanExecutionCollectionItemGroupExecution> groupExecutions;
    /**
     * @return The OCID of the DR Plan Execution.  Example: `ocid1.drplanexecution.oc1.iad.exampleocid2`
     * 
     */
    private String id;
    /**
     * @return A message describing the DR Plan Execution&#39;s current state in more detail.  Example: `The DR Plan Execution [Execution - EBS Switchover PHX to IAD] is currently in progress`
     * 
     */
    private String lifeCycleDetails;
    /**
     * @return Information about an Object Storage log location for a DR Protection Group.
     * 
     */
    private List<GetDrPlanExecutionsDrPlanExecutionCollectionItemLogLocation> logLocations;
    /**
     * @return The OCID of peer (remote) DR Protection Group associated with this plan&#39;s DR Protection Group.  Example: `ocid1.drprotectiongroup.oc1.phx.exampleocid1`
     * 
     */
    private String peerDrProtectionGroupId;
    /**
     * @return The region of the peer (remote) DR Protection Group.  Example: `us-ashburn-1`
     * 
     */
    private String peerRegion;
    /**
     * @return The type of the DR Plan executed.
     * 
     */
    private String planExecutionType;
    /**
     * @return The OCID of the DR Plan.  Example: `ocid1.drplan.oc1.iad.exampleocid2`
     * 
     */
    private String planId;
    /**
     * @return A filter to return only DR Plan Executions that match the given lifecycleState.
     * 
     */
    private String state;
    /**
     * @return Usage of system tag keys. These predefined keys are scoped to namespaces. Example: `{&#34;orcl-cloud.free-tier-retained&#34;: &#34;true&#34;}`
     * 
     */
    private Map<String,Object> systemTags;
    /**
     * @return The date and time at which DR Plan Execution was created. An RFC3339 formatted datetime string.  Example: `2019-03-29T09:36:42Z`
     * 
     */
    private String timeCreated;
    /**
     * @return The date and time at which DR Plan Execution succeeded, failed, was paused, or was canceled. An RFC3339 formatted datetime string.  Example: `2019-03-29T09:36:42Z`
     * 
     */
    private String timeEnded;
    /**
     * @return The date and time at which DR Plan Execution began. An RFC3339 formatted datetime string.  Example: `2019-03-29T09:36:42Z`
     * 
     */
    private String timeStarted;
    /**
     * @return The time at which DR Plan Execution was last updated. An RFC3339 formatted datetime string.  Example: `2019-03-29T09:36:42Z`
     * 
     */
    private String timeUpdated;

    private GetDrPlanExecutionsDrPlanExecutionCollectionItem() {}
    /**
     * @return The OCID of the compartment containing this DR Plan Execution.  Example: `ocid1.compartment.oc1..exampleocid1`
     * 
     */
    public String compartmentId() {
        return this.compartmentId;
    }
    /**
     * @return Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{&#34;Operations.CostCenter&#34;: &#34;42&#34;}`
     * 
     */
    public Map<String,Object> definedTags() {
        return this.definedTags;
    }
    /**
     * @return A filter to return only resources that match the entire display name given.  Example: `MY UNIQUE DISPLAY NAME`
     * 
     */
    public String displayName() {
        return this.displayName;
    }
    /**
     * @return The OCID of the DR Protection Group. Mandatory query param.  Example: `ocid1.drprotectiongroup.oc1.phx.exampleocid`
     * 
     */
    public String drProtectionGroupId() {
        return this.drProtectionGroupId;
    }
    /**
     * @return The total duration in seconds taken to complete step execution.  Example: `35`
     * 
     */
    public Integer executionDurationInSec() {
        return this.executionDurationInSec;
    }
    /**
     * @return The options for a plan execution.
     * 
     */
    public List<GetDrPlanExecutionsDrPlanExecutionCollectionItemExecutionOption> executionOptions() {
        return this.executionOptions;
    }
    /**
     * @return Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{&#34;Department&#34;: &#34;Finance&#34;}`
     * 
     */
    public Map<String,Object> freeformTags() {
        return this.freeformTags;
    }
    /**
     * @return A list of groups executed in this DR Plan Execution.
     * 
     */
    public List<GetDrPlanExecutionsDrPlanExecutionCollectionItemGroupExecution> groupExecutions() {
        return this.groupExecutions;
    }
    /**
     * @return The OCID of the DR Plan Execution.  Example: `ocid1.drplanexecution.oc1.iad.exampleocid2`
     * 
     */
    public String id() {
        return this.id;
    }
    /**
     * @return A message describing the DR Plan Execution&#39;s current state in more detail.  Example: `The DR Plan Execution [Execution - EBS Switchover PHX to IAD] is currently in progress`
     * 
     */
    public String lifeCycleDetails() {
        return this.lifeCycleDetails;
    }
    /**
     * @return Information about an Object Storage log location for a DR Protection Group.
     * 
     */
    public List<GetDrPlanExecutionsDrPlanExecutionCollectionItemLogLocation> logLocations() {
        return this.logLocations;
    }
    /**
     * @return The OCID of peer (remote) DR Protection Group associated with this plan&#39;s DR Protection Group.  Example: `ocid1.drprotectiongroup.oc1.phx.exampleocid1`
     * 
     */
    public String peerDrProtectionGroupId() {
        return this.peerDrProtectionGroupId;
    }
    /**
     * @return The region of the peer (remote) DR Protection Group.  Example: `us-ashburn-1`
     * 
     */
    public String peerRegion() {
        return this.peerRegion;
    }
    /**
     * @return The type of the DR Plan executed.
     * 
     */
    public String planExecutionType() {
        return this.planExecutionType;
    }
    /**
     * @return The OCID of the DR Plan.  Example: `ocid1.drplan.oc1.iad.exampleocid2`
     * 
     */
    public String planId() {
        return this.planId;
    }
    /**
     * @return A filter to return only DR Plan Executions that match the given lifecycleState.
     * 
     */
    public String state() {
        return this.state;
    }
    /**
     * @return Usage of system tag keys. These predefined keys are scoped to namespaces. Example: `{&#34;orcl-cloud.free-tier-retained&#34;: &#34;true&#34;}`
     * 
     */
    public Map<String,Object> systemTags() {
        return this.systemTags;
    }
    /**
     * @return The date and time at which DR Plan Execution was created. An RFC3339 formatted datetime string.  Example: `2019-03-29T09:36:42Z`
     * 
     */
    public String timeCreated() {
        return this.timeCreated;
    }
    /**
     * @return The date and time at which DR Plan Execution succeeded, failed, was paused, or was canceled. An RFC3339 formatted datetime string.  Example: `2019-03-29T09:36:42Z`
     * 
     */
    public String timeEnded() {
        return this.timeEnded;
    }
    /**
     * @return The date and time at which DR Plan Execution began. An RFC3339 formatted datetime string.  Example: `2019-03-29T09:36:42Z`
     * 
     */
    public String timeStarted() {
        return this.timeStarted;
    }
    /**
     * @return The time at which DR Plan Execution was last updated. An RFC3339 formatted datetime string.  Example: `2019-03-29T09:36:42Z`
     * 
     */
    public String timeUpdated() {
        return this.timeUpdated;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetDrPlanExecutionsDrPlanExecutionCollectionItem defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String compartmentId;
        private Map<String,Object> definedTags;
        private String displayName;
        private String drProtectionGroupId;
        private Integer executionDurationInSec;
        private List<GetDrPlanExecutionsDrPlanExecutionCollectionItemExecutionOption> executionOptions;
        private Map<String,Object> freeformTags;
        private List<GetDrPlanExecutionsDrPlanExecutionCollectionItemGroupExecution> groupExecutions;
        private String id;
        private String lifeCycleDetails;
        private List<GetDrPlanExecutionsDrPlanExecutionCollectionItemLogLocation> logLocations;
        private String peerDrProtectionGroupId;
        private String peerRegion;
        private String planExecutionType;
        private String planId;
        private String state;
        private Map<String,Object> systemTags;
        private String timeCreated;
        private String timeEnded;
        private String timeStarted;
        private String timeUpdated;
        public Builder() {}
        public Builder(GetDrPlanExecutionsDrPlanExecutionCollectionItem defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.compartmentId = defaults.compartmentId;
    	      this.definedTags = defaults.definedTags;
    	      this.displayName = defaults.displayName;
    	      this.drProtectionGroupId = defaults.drProtectionGroupId;
    	      this.executionDurationInSec = defaults.executionDurationInSec;
    	      this.executionOptions = defaults.executionOptions;
    	      this.freeformTags = defaults.freeformTags;
    	      this.groupExecutions = defaults.groupExecutions;
    	      this.id = defaults.id;
    	      this.lifeCycleDetails = defaults.lifeCycleDetails;
    	      this.logLocations = defaults.logLocations;
    	      this.peerDrProtectionGroupId = defaults.peerDrProtectionGroupId;
    	      this.peerRegion = defaults.peerRegion;
    	      this.planExecutionType = defaults.planExecutionType;
    	      this.planId = defaults.planId;
    	      this.state = defaults.state;
    	      this.systemTags = defaults.systemTags;
    	      this.timeCreated = defaults.timeCreated;
    	      this.timeEnded = defaults.timeEnded;
    	      this.timeStarted = defaults.timeStarted;
    	      this.timeUpdated = defaults.timeUpdated;
        }

        @CustomType.Setter
        public Builder compartmentId(String compartmentId) {
            this.compartmentId = Objects.requireNonNull(compartmentId);
            return this;
        }
        @CustomType.Setter
        public Builder definedTags(Map<String,Object> definedTags) {
            this.definedTags = Objects.requireNonNull(definedTags);
            return this;
        }
        @CustomType.Setter
        public Builder displayName(String displayName) {
            this.displayName = Objects.requireNonNull(displayName);
            return this;
        }
        @CustomType.Setter
        public Builder drProtectionGroupId(String drProtectionGroupId) {
            this.drProtectionGroupId = Objects.requireNonNull(drProtectionGroupId);
            return this;
        }
        @CustomType.Setter
        public Builder executionDurationInSec(Integer executionDurationInSec) {
            this.executionDurationInSec = Objects.requireNonNull(executionDurationInSec);
            return this;
        }
        @CustomType.Setter
        public Builder executionOptions(List<GetDrPlanExecutionsDrPlanExecutionCollectionItemExecutionOption> executionOptions) {
            this.executionOptions = Objects.requireNonNull(executionOptions);
            return this;
        }
        public Builder executionOptions(GetDrPlanExecutionsDrPlanExecutionCollectionItemExecutionOption... executionOptions) {
            return executionOptions(List.of(executionOptions));
        }
        @CustomType.Setter
        public Builder freeformTags(Map<String,Object> freeformTags) {
            this.freeformTags = Objects.requireNonNull(freeformTags);
            return this;
        }
        @CustomType.Setter
        public Builder groupExecutions(List<GetDrPlanExecutionsDrPlanExecutionCollectionItemGroupExecution> groupExecutions) {
            this.groupExecutions = Objects.requireNonNull(groupExecutions);
            return this;
        }
        public Builder groupExecutions(GetDrPlanExecutionsDrPlanExecutionCollectionItemGroupExecution... groupExecutions) {
            return groupExecutions(List.of(groupExecutions));
        }
        @CustomType.Setter
        public Builder id(String id) {
            this.id = Objects.requireNonNull(id);
            return this;
        }
        @CustomType.Setter
        public Builder lifeCycleDetails(String lifeCycleDetails) {
            this.lifeCycleDetails = Objects.requireNonNull(lifeCycleDetails);
            return this;
        }
        @CustomType.Setter
        public Builder logLocations(List<GetDrPlanExecutionsDrPlanExecutionCollectionItemLogLocation> logLocations) {
            this.logLocations = Objects.requireNonNull(logLocations);
            return this;
        }
        public Builder logLocations(GetDrPlanExecutionsDrPlanExecutionCollectionItemLogLocation... logLocations) {
            return logLocations(List.of(logLocations));
        }
        @CustomType.Setter
        public Builder peerDrProtectionGroupId(String peerDrProtectionGroupId) {
            this.peerDrProtectionGroupId = Objects.requireNonNull(peerDrProtectionGroupId);
            return this;
        }
        @CustomType.Setter
        public Builder peerRegion(String peerRegion) {
            this.peerRegion = Objects.requireNonNull(peerRegion);
            return this;
        }
        @CustomType.Setter
        public Builder planExecutionType(String planExecutionType) {
            this.planExecutionType = Objects.requireNonNull(planExecutionType);
            return this;
        }
        @CustomType.Setter
        public Builder planId(String planId) {
            this.planId = Objects.requireNonNull(planId);
            return this;
        }
        @CustomType.Setter
        public Builder state(String state) {
            this.state = Objects.requireNonNull(state);
            return this;
        }
        @CustomType.Setter
        public Builder systemTags(Map<String,Object> systemTags) {
            this.systemTags = Objects.requireNonNull(systemTags);
            return this;
        }
        @CustomType.Setter
        public Builder timeCreated(String timeCreated) {
            this.timeCreated = Objects.requireNonNull(timeCreated);
            return this;
        }
        @CustomType.Setter
        public Builder timeEnded(String timeEnded) {
            this.timeEnded = Objects.requireNonNull(timeEnded);
            return this;
        }
        @CustomType.Setter
        public Builder timeStarted(String timeStarted) {
            this.timeStarted = Objects.requireNonNull(timeStarted);
            return this;
        }
        @CustomType.Setter
        public Builder timeUpdated(String timeUpdated) {
            this.timeUpdated = Objects.requireNonNull(timeUpdated);
            return this;
        }
        public GetDrPlanExecutionsDrPlanExecutionCollectionItem build() {
            final var o = new GetDrPlanExecutionsDrPlanExecutionCollectionItem();
            o.compartmentId = compartmentId;
            o.definedTags = definedTags;
            o.displayName = displayName;
            o.drProtectionGroupId = drProtectionGroupId;
            o.executionDurationInSec = executionDurationInSec;
            o.executionOptions = executionOptions;
            o.freeformTags = freeformTags;
            o.groupExecutions = groupExecutions;
            o.id = id;
            o.lifeCycleDetails = lifeCycleDetails;
            o.logLocations = logLocations;
            o.peerDrProtectionGroupId = peerDrProtectionGroupId;
            o.peerRegion = peerRegion;
            o.planExecutionType = planExecutionType;
            o.planId = planId;
            o.state = state;
            o.systemTags = systemTags;
            o.timeCreated = timeCreated;
            o.timeEnded = timeEnded;
            o.timeStarted = timeStarted;
            o.timeUpdated = timeUpdated;
            return o;
        }
    }
}