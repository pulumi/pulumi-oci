// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.ManagementAgent.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.oci.ManagementAgent.outputs.GetManagementAgentsManagementAgentPluginList;
import java.lang.Boolean;
import java.lang.Object;
import java.lang.String;
import java.util.List;
import java.util.Map;
import java.util.Objects;

@CustomType
public final class GetManagementAgentsManagementAgent {
    /**
     * @return Filter to return only Management Agents in the particular availability status.
     * 
     */
    private String availabilityStatus;
    /**
     * @return The OCID of the compartment to which a request will be scoped.
     * 
     */
    private String compartmentId;
    /**
     * @return Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{&#34;foo-namespace.bar-key&#34;: &#34;value&#34;}`
     * 
     */
    private Map<String,Object> definedTags;
    private List<String> deployPluginsIds;
    /**
     * @return Filter to return only Management Agents having the particular display name.
     * 
     */
    private String displayName;
    /**
     * @return Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{&#34;bar-key&#34;: &#34;value&#34;}`
     * 
     */
    private Map<String,Object> freeformTags;
    /**
     * @return Management Agent host machine name
     * 
     */
    private String host;
    /**
     * @return Filter to return only Management Agents having the particular agent host id.
     * 
     */
    private String hostId;
    /**
     * @return agent identifier
     * 
     */
    private String id;
    /**
     * @return agent install key identifier
     * 
     */
    private String installKeyId;
    /**
     * @return Path where Management Agent is installed
     * 
     */
    private String installPath;
    /**
     * @return A filter to return either agents or gateway types depending upon install type selected by user. By default both install type will be returned.
     * 
     */
    private String installType;
    /**
     * @return true if the agent can be upgraded automatically; false if it must be upgraded manually. This flag is derived from the tenancy level auto upgrade preference.
     * 
     */
    private Boolean isAgentAutoUpgradable;
    /**
     * @return true, if the agent image is manually downloaded and installed. false, if the agent is deployed as a plugin in Oracle Cloud Agent.
     * 
     */
    private Boolean isCustomerDeployed;
    /**
     * @return A message describing the current state in more detail. For example, can be used to provide actionable information for a resource in Failed state.
     * 
     */
    private String lifecycleDetails;
    private String managedAgentId;
    /**
     * @return Platform Name
     * 
     */
    private String platformName;
    /**
     * @return Array of PlatformTypes to return only results having the particular platform types. Example: [&#34;LINUX&#34;]
     * 
     */
    private String platformType;
    /**
     * @return Platform Version
     * 
     */
    private String platformVersion;
    /**
     * @return list of managementAgentPlugins associated with the agent
     * 
     */
    private List<GetManagementAgentsManagementAgentPluginList> pluginLists;
    /**
     * @return Version of the deployment artifact instantiated by this Management Agent. The format for Standalone resourceMode is YYMMDD.HHMM, and the format for other modes (whose artifacts are based upon Standalone but can advance independently) is YYMMDD.HHMM.VVVVVVVVVVVV. VVVVVVVVVVVV is always a numeric value between 000000000000 and 999999999999
     * 
     */
    private String resourceArtifactVersion;
    /**
     * @return Filter to return only Management Agents in the particular lifecycle state.
     * 
     */
    private String state;
    /**
     * @return The time the Management Agent was created. An RFC3339 formatted datetime string
     * 
     */
    private String timeCreated;
    /**
     * @return The time the Management Agent has last recorded its health status in telemetry. This value will be null if the agent has not recorded its health status in last 7 days. An RFC3339 formatted datetime string
     * 
     */
    private String timeLastHeartbeat;
    /**
     * @return The time the Management Agent was last updated. An RFC3339 formatted datetime string
     * 
     */
    private String timeUpdated;
    /**
     * @return Array of versions to return only Management Agents having the particular agent versions. Example: [&#34;202020.0101&#34;,&#34;210201.0513&#34;]
     * 
     */
    private String version;

    private GetManagementAgentsManagementAgent() {}
    /**
     * @return Filter to return only Management Agents in the particular availability status.
     * 
     */
    public String availabilityStatus() {
        return this.availabilityStatus;
    }
    /**
     * @return The OCID of the compartment to which a request will be scoped.
     * 
     */
    public String compartmentId() {
        return this.compartmentId;
    }
    /**
     * @return Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{&#34;foo-namespace.bar-key&#34;: &#34;value&#34;}`
     * 
     */
    public Map<String,Object> definedTags() {
        return this.definedTags;
    }
    public List<String> deployPluginsIds() {
        return this.deployPluginsIds;
    }
    /**
     * @return Filter to return only Management Agents having the particular display name.
     * 
     */
    public String displayName() {
        return this.displayName;
    }
    /**
     * @return Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{&#34;bar-key&#34;: &#34;value&#34;}`
     * 
     */
    public Map<String,Object> freeformTags() {
        return this.freeformTags;
    }
    /**
     * @return Management Agent host machine name
     * 
     */
    public String host() {
        return this.host;
    }
    /**
     * @return Filter to return only Management Agents having the particular agent host id.
     * 
     */
    public String hostId() {
        return this.hostId;
    }
    /**
     * @return agent identifier
     * 
     */
    public String id() {
        return this.id;
    }
    /**
     * @return agent install key identifier
     * 
     */
    public String installKeyId() {
        return this.installKeyId;
    }
    /**
     * @return Path where Management Agent is installed
     * 
     */
    public String installPath() {
        return this.installPath;
    }
    /**
     * @return A filter to return either agents or gateway types depending upon install type selected by user. By default both install type will be returned.
     * 
     */
    public String installType() {
        return this.installType;
    }
    /**
     * @return true if the agent can be upgraded automatically; false if it must be upgraded manually. This flag is derived from the tenancy level auto upgrade preference.
     * 
     */
    public Boolean isAgentAutoUpgradable() {
        return this.isAgentAutoUpgradable;
    }
    /**
     * @return true, if the agent image is manually downloaded and installed. false, if the agent is deployed as a plugin in Oracle Cloud Agent.
     * 
     */
    public Boolean isCustomerDeployed() {
        return this.isCustomerDeployed;
    }
    /**
     * @return A message describing the current state in more detail. For example, can be used to provide actionable information for a resource in Failed state.
     * 
     */
    public String lifecycleDetails() {
        return this.lifecycleDetails;
    }
    public String managedAgentId() {
        return this.managedAgentId;
    }
    /**
     * @return Platform Name
     * 
     */
    public String platformName() {
        return this.platformName;
    }
    /**
     * @return Array of PlatformTypes to return only results having the particular platform types. Example: [&#34;LINUX&#34;]
     * 
     */
    public String platformType() {
        return this.platformType;
    }
    /**
     * @return Platform Version
     * 
     */
    public String platformVersion() {
        return this.platformVersion;
    }
    /**
     * @return list of managementAgentPlugins associated with the agent
     * 
     */
    public List<GetManagementAgentsManagementAgentPluginList> pluginLists() {
        return this.pluginLists;
    }
    /**
     * @return Version of the deployment artifact instantiated by this Management Agent. The format for Standalone resourceMode is YYMMDD.HHMM, and the format for other modes (whose artifacts are based upon Standalone but can advance independently) is YYMMDD.HHMM.VVVVVVVVVVVV. VVVVVVVVVVVV is always a numeric value between 000000000000 and 999999999999
     * 
     */
    public String resourceArtifactVersion() {
        return this.resourceArtifactVersion;
    }
    /**
     * @return Filter to return only Management Agents in the particular lifecycle state.
     * 
     */
    public String state() {
        return this.state;
    }
    /**
     * @return The time the Management Agent was created. An RFC3339 formatted datetime string
     * 
     */
    public String timeCreated() {
        return this.timeCreated;
    }
    /**
     * @return The time the Management Agent has last recorded its health status in telemetry. This value will be null if the agent has not recorded its health status in last 7 days. An RFC3339 formatted datetime string
     * 
     */
    public String timeLastHeartbeat() {
        return this.timeLastHeartbeat;
    }
    /**
     * @return The time the Management Agent was last updated. An RFC3339 formatted datetime string
     * 
     */
    public String timeUpdated() {
        return this.timeUpdated;
    }
    /**
     * @return Array of versions to return only Management Agents having the particular agent versions. Example: [&#34;202020.0101&#34;,&#34;210201.0513&#34;]
     * 
     */
    public String version() {
        return this.version;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetManagementAgentsManagementAgent defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String availabilityStatus;
        private String compartmentId;
        private Map<String,Object> definedTags;
        private List<String> deployPluginsIds;
        private String displayName;
        private Map<String,Object> freeformTags;
        private String host;
        private String hostId;
        private String id;
        private String installKeyId;
        private String installPath;
        private String installType;
        private Boolean isAgentAutoUpgradable;
        private Boolean isCustomerDeployed;
        private String lifecycleDetails;
        private String managedAgentId;
        private String platformName;
        private String platformType;
        private String platformVersion;
        private List<GetManagementAgentsManagementAgentPluginList> pluginLists;
        private String resourceArtifactVersion;
        private String state;
        private String timeCreated;
        private String timeLastHeartbeat;
        private String timeUpdated;
        private String version;
        public Builder() {}
        public Builder(GetManagementAgentsManagementAgent defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.availabilityStatus = defaults.availabilityStatus;
    	      this.compartmentId = defaults.compartmentId;
    	      this.definedTags = defaults.definedTags;
    	      this.deployPluginsIds = defaults.deployPluginsIds;
    	      this.displayName = defaults.displayName;
    	      this.freeformTags = defaults.freeformTags;
    	      this.host = defaults.host;
    	      this.hostId = defaults.hostId;
    	      this.id = defaults.id;
    	      this.installKeyId = defaults.installKeyId;
    	      this.installPath = defaults.installPath;
    	      this.installType = defaults.installType;
    	      this.isAgentAutoUpgradable = defaults.isAgentAutoUpgradable;
    	      this.isCustomerDeployed = defaults.isCustomerDeployed;
    	      this.lifecycleDetails = defaults.lifecycleDetails;
    	      this.managedAgentId = defaults.managedAgentId;
    	      this.platformName = defaults.platformName;
    	      this.platformType = defaults.platformType;
    	      this.platformVersion = defaults.platformVersion;
    	      this.pluginLists = defaults.pluginLists;
    	      this.resourceArtifactVersion = defaults.resourceArtifactVersion;
    	      this.state = defaults.state;
    	      this.timeCreated = defaults.timeCreated;
    	      this.timeLastHeartbeat = defaults.timeLastHeartbeat;
    	      this.timeUpdated = defaults.timeUpdated;
    	      this.version = defaults.version;
        }

        @CustomType.Setter
        public Builder availabilityStatus(String availabilityStatus) {
            this.availabilityStatus = Objects.requireNonNull(availabilityStatus);
            return this;
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
        public Builder deployPluginsIds(List<String> deployPluginsIds) {
            this.deployPluginsIds = Objects.requireNonNull(deployPluginsIds);
            return this;
        }
        public Builder deployPluginsIds(String... deployPluginsIds) {
            return deployPluginsIds(List.of(deployPluginsIds));
        }
        @CustomType.Setter
        public Builder displayName(String displayName) {
            this.displayName = Objects.requireNonNull(displayName);
            return this;
        }
        @CustomType.Setter
        public Builder freeformTags(Map<String,Object> freeformTags) {
            this.freeformTags = Objects.requireNonNull(freeformTags);
            return this;
        }
        @CustomType.Setter
        public Builder host(String host) {
            this.host = Objects.requireNonNull(host);
            return this;
        }
        @CustomType.Setter
        public Builder hostId(String hostId) {
            this.hostId = Objects.requireNonNull(hostId);
            return this;
        }
        @CustomType.Setter
        public Builder id(String id) {
            this.id = Objects.requireNonNull(id);
            return this;
        }
        @CustomType.Setter
        public Builder installKeyId(String installKeyId) {
            this.installKeyId = Objects.requireNonNull(installKeyId);
            return this;
        }
        @CustomType.Setter
        public Builder installPath(String installPath) {
            this.installPath = Objects.requireNonNull(installPath);
            return this;
        }
        @CustomType.Setter
        public Builder installType(String installType) {
            this.installType = Objects.requireNonNull(installType);
            return this;
        }
        @CustomType.Setter
        public Builder isAgentAutoUpgradable(Boolean isAgentAutoUpgradable) {
            this.isAgentAutoUpgradable = Objects.requireNonNull(isAgentAutoUpgradable);
            return this;
        }
        @CustomType.Setter
        public Builder isCustomerDeployed(Boolean isCustomerDeployed) {
            this.isCustomerDeployed = Objects.requireNonNull(isCustomerDeployed);
            return this;
        }
        @CustomType.Setter
        public Builder lifecycleDetails(String lifecycleDetails) {
            this.lifecycleDetails = Objects.requireNonNull(lifecycleDetails);
            return this;
        }
        @CustomType.Setter
        public Builder managedAgentId(String managedAgentId) {
            this.managedAgentId = Objects.requireNonNull(managedAgentId);
            return this;
        }
        @CustomType.Setter
        public Builder platformName(String platformName) {
            this.platformName = Objects.requireNonNull(platformName);
            return this;
        }
        @CustomType.Setter
        public Builder platformType(String platformType) {
            this.platformType = Objects.requireNonNull(platformType);
            return this;
        }
        @CustomType.Setter
        public Builder platformVersion(String platformVersion) {
            this.platformVersion = Objects.requireNonNull(platformVersion);
            return this;
        }
        @CustomType.Setter
        public Builder pluginLists(List<GetManagementAgentsManagementAgentPluginList> pluginLists) {
            this.pluginLists = Objects.requireNonNull(pluginLists);
            return this;
        }
        public Builder pluginLists(GetManagementAgentsManagementAgentPluginList... pluginLists) {
            return pluginLists(List.of(pluginLists));
        }
        @CustomType.Setter
        public Builder resourceArtifactVersion(String resourceArtifactVersion) {
            this.resourceArtifactVersion = Objects.requireNonNull(resourceArtifactVersion);
            return this;
        }
        @CustomType.Setter
        public Builder state(String state) {
            this.state = Objects.requireNonNull(state);
            return this;
        }
        @CustomType.Setter
        public Builder timeCreated(String timeCreated) {
            this.timeCreated = Objects.requireNonNull(timeCreated);
            return this;
        }
        @CustomType.Setter
        public Builder timeLastHeartbeat(String timeLastHeartbeat) {
            this.timeLastHeartbeat = Objects.requireNonNull(timeLastHeartbeat);
            return this;
        }
        @CustomType.Setter
        public Builder timeUpdated(String timeUpdated) {
            this.timeUpdated = Objects.requireNonNull(timeUpdated);
            return this;
        }
        @CustomType.Setter
        public Builder version(String version) {
            this.version = Objects.requireNonNull(version);
            return this;
        }
        public GetManagementAgentsManagementAgent build() {
            final var o = new GetManagementAgentsManagementAgent();
            o.availabilityStatus = availabilityStatus;
            o.compartmentId = compartmentId;
            o.definedTags = definedTags;
            o.deployPluginsIds = deployPluginsIds;
            o.displayName = displayName;
            o.freeformTags = freeformTags;
            o.host = host;
            o.hostId = hostId;
            o.id = id;
            o.installKeyId = installKeyId;
            o.installPath = installPath;
            o.installType = installType;
            o.isAgentAutoUpgradable = isAgentAutoUpgradable;
            o.isCustomerDeployed = isCustomerDeployed;
            o.lifecycleDetails = lifecycleDetails;
            o.managedAgentId = managedAgentId;
            o.platformName = platformName;
            o.platformType = platformType;
            o.platformVersion = platformVersion;
            o.pluginLists = pluginLists;
            o.resourceArtifactVersion = resourceArtifactVersion;
            o.state = state;
            o.timeCreated = timeCreated;
            o.timeLastHeartbeat = timeLastHeartbeat;
            o.timeUpdated = timeUpdated;
            o.version = version;
            return o;
        }
    }
}