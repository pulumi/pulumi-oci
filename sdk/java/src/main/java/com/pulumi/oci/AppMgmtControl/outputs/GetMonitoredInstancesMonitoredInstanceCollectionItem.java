// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.AppMgmtControl.outputs;

import com.pulumi.core.annotations.CustomType;
import java.lang.String;
import java.util.Objects;

@CustomType
public final class GetMonitoredInstancesMonitoredInstanceCollectionItem {
    /**
     * @return The ID of the compartment in which to list resources.
     * 
     */
    private final String compartmentId;
    /**
     * @return A filter to return only resources that match the entire display name given.
     * 
     */
    private final String displayName;
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of monitored instance.
     * 
     */
    private final String instanceId;
    /**
     * @return A message describing the current state in more detail. For example, can be used to provide actionable information for a resource in Failed state.
     * 
     */
    private final String lifecycleDetails;
    /**
     * @return Management Agent Identifier [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm). Used to invoke manage operations on Management Agent Cloud Service.
     * 
     */
    private final String managementAgentId;
    /**
     * @return Monitoring status. Can be either enabled or disabled.
     * 
     */
    private final String monitoringState;
    /**
     * @return The current state of the monitored instance.
     * 
     */
    private final String state;
    /**
     * @return The time the MonitoredInstance was created. An RFC3339 formatted datetime string
     * 
     */
    private final String timeCreated;
    /**
     * @return The time the MonitoredInstance was updated. An RFC3339 formatted datetime string
     * 
     */
    private final String timeUpdated;

    @CustomType.Constructor
    private GetMonitoredInstancesMonitoredInstanceCollectionItem(
        @CustomType.Parameter("compartmentId") String compartmentId,
        @CustomType.Parameter("displayName") String displayName,
        @CustomType.Parameter("instanceId") String instanceId,
        @CustomType.Parameter("lifecycleDetails") String lifecycleDetails,
        @CustomType.Parameter("managementAgentId") String managementAgentId,
        @CustomType.Parameter("monitoringState") String monitoringState,
        @CustomType.Parameter("state") String state,
        @CustomType.Parameter("timeCreated") String timeCreated,
        @CustomType.Parameter("timeUpdated") String timeUpdated) {
        this.compartmentId = compartmentId;
        this.displayName = displayName;
        this.instanceId = instanceId;
        this.lifecycleDetails = lifecycleDetails;
        this.managementAgentId = managementAgentId;
        this.monitoringState = monitoringState;
        this.state = state;
        this.timeCreated = timeCreated;
        this.timeUpdated = timeUpdated;
    }

    /**
     * @return The ID of the compartment in which to list resources.
     * 
     */
    public String compartmentId() {
        return this.compartmentId;
    }
    /**
     * @return A filter to return only resources that match the entire display name given.
     * 
     */
    public String displayName() {
        return this.displayName;
    }
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of monitored instance.
     * 
     */
    public String instanceId() {
        return this.instanceId;
    }
    /**
     * @return A message describing the current state in more detail. For example, can be used to provide actionable information for a resource in Failed state.
     * 
     */
    public String lifecycleDetails() {
        return this.lifecycleDetails;
    }
    /**
     * @return Management Agent Identifier [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm). Used to invoke manage operations on Management Agent Cloud Service.
     * 
     */
    public String managementAgentId() {
        return this.managementAgentId;
    }
    /**
     * @return Monitoring status. Can be either enabled or disabled.
     * 
     */
    public String monitoringState() {
        return this.monitoringState;
    }
    /**
     * @return The current state of the monitored instance.
     * 
     */
    public String state() {
        return this.state;
    }
    /**
     * @return The time the MonitoredInstance was created. An RFC3339 formatted datetime string
     * 
     */
    public String timeCreated() {
        return this.timeCreated;
    }
    /**
     * @return The time the MonitoredInstance was updated. An RFC3339 formatted datetime string
     * 
     */
    public String timeUpdated() {
        return this.timeUpdated;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetMonitoredInstancesMonitoredInstanceCollectionItem defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private String compartmentId;
        private String displayName;
        private String instanceId;
        private String lifecycleDetails;
        private String managementAgentId;
        private String monitoringState;
        private String state;
        private String timeCreated;
        private String timeUpdated;

        public Builder() {
    	      // Empty
        }

        public Builder(GetMonitoredInstancesMonitoredInstanceCollectionItem defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.compartmentId = defaults.compartmentId;
    	      this.displayName = defaults.displayName;
    	      this.instanceId = defaults.instanceId;
    	      this.lifecycleDetails = defaults.lifecycleDetails;
    	      this.managementAgentId = defaults.managementAgentId;
    	      this.monitoringState = defaults.monitoringState;
    	      this.state = defaults.state;
    	      this.timeCreated = defaults.timeCreated;
    	      this.timeUpdated = defaults.timeUpdated;
        }

        public Builder compartmentId(String compartmentId) {
            this.compartmentId = Objects.requireNonNull(compartmentId);
            return this;
        }
        public Builder displayName(String displayName) {
            this.displayName = Objects.requireNonNull(displayName);
            return this;
        }
        public Builder instanceId(String instanceId) {
            this.instanceId = Objects.requireNonNull(instanceId);
            return this;
        }
        public Builder lifecycleDetails(String lifecycleDetails) {
            this.lifecycleDetails = Objects.requireNonNull(lifecycleDetails);
            return this;
        }
        public Builder managementAgentId(String managementAgentId) {
            this.managementAgentId = Objects.requireNonNull(managementAgentId);
            return this;
        }
        public Builder monitoringState(String monitoringState) {
            this.monitoringState = Objects.requireNonNull(monitoringState);
            return this;
        }
        public Builder state(String state) {
            this.state = Objects.requireNonNull(state);
            return this;
        }
        public Builder timeCreated(String timeCreated) {
            this.timeCreated = Objects.requireNonNull(timeCreated);
            return this;
        }
        public Builder timeUpdated(String timeUpdated) {
            this.timeUpdated = Objects.requireNonNull(timeUpdated);
            return this;
        }        public GetMonitoredInstancesMonitoredInstanceCollectionItem build() {
            return new GetMonitoredInstancesMonitoredInstanceCollectionItem(compartmentId, displayName, instanceId, lifecycleDetails, managementAgentId, monitoringState, state, timeCreated, timeUpdated);
        }
    }
}
