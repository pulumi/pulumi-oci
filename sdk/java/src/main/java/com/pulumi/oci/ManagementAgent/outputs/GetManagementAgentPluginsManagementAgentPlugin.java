// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.ManagementAgent.outputs;

import com.pulumi.core.annotations.CustomType;
import java.lang.Boolean;
import java.lang.Integer;
import java.lang.String;
import java.util.List;
import java.util.Objects;

@CustomType
public final class GetManagementAgentPluginsManagementAgentPlugin {
    /**
     * @return Management Agent Plugin description
     * 
     */
    private final String description;
    /**
     * @return Filter to return only Management Agent Plugins having the particular display name.
     * 
     */
    private final String displayName;
    /**
     * @return Management Agent Plugin Id
     * 
     */
    private final String id;
    /**
     * @return A flag to indicate whether a given plugin can be deployed from Agent Console UI or not.
     * 
     */
    private final Boolean isConsoleDeployable;
    /**
     * @return Management Agent Plugin Name
     * 
     */
    private final String name;
    /**
     * @return Filter to return only Management Agents in the particular lifecycle state.
     * 
     */
    private final String state;
    /**
     * @return Supported Platform Types
     * 
     */
    private final List<String> supportedPlatformTypes;
    /**
     * @return Management Agent Plugin Version
     * 
     */
    private final Integer version;

    @CustomType.Constructor
    private GetManagementAgentPluginsManagementAgentPlugin(
        @CustomType.Parameter("description") String description,
        @CustomType.Parameter("displayName") String displayName,
        @CustomType.Parameter("id") String id,
        @CustomType.Parameter("isConsoleDeployable") Boolean isConsoleDeployable,
        @CustomType.Parameter("name") String name,
        @CustomType.Parameter("state") String state,
        @CustomType.Parameter("supportedPlatformTypes") List<String> supportedPlatformTypes,
        @CustomType.Parameter("version") Integer version) {
        this.description = description;
        this.displayName = displayName;
        this.id = id;
        this.isConsoleDeployable = isConsoleDeployable;
        this.name = name;
        this.state = state;
        this.supportedPlatformTypes = supportedPlatformTypes;
        this.version = version;
    }

    /**
     * @return Management Agent Plugin description
     * 
     */
    public String description() {
        return this.description;
    }
    /**
     * @return Filter to return only Management Agent Plugins having the particular display name.
     * 
     */
    public String displayName() {
        return this.displayName;
    }
    /**
     * @return Management Agent Plugin Id
     * 
     */
    public String id() {
        return this.id;
    }
    /**
     * @return A flag to indicate whether a given plugin can be deployed from Agent Console UI or not.
     * 
     */
    public Boolean isConsoleDeployable() {
        return this.isConsoleDeployable;
    }
    /**
     * @return Management Agent Plugin Name
     * 
     */
    public String name() {
        return this.name;
    }
    /**
     * @return Filter to return only Management Agents in the particular lifecycle state.
     * 
     */
    public String state() {
        return this.state;
    }
    /**
     * @return Supported Platform Types
     * 
     */
    public List<String> supportedPlatformTypes() {
        return this.supportedPlatformTypes;
    }
    /**
     * @return Management Agent Plugin Version
     * 
     */
    public Integer version() {
        return this.version;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetManagementAgentPluginsManagementAgentPlugin defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private String description;
        private String displayName;
        private String id;
        private Boolean isConsoleDeployable;
        private String name;
        private String state;
        private List<String> supportedPlatformTypes;
        private Integer version;

        public Builder() {
    	      // Empty
        }

        public Builder(GetManagementAgentPluginsManagementAgentPlugin defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.description = defaults.description;
    	      this.displayName = defaults.displayName;
    	      this.id = defaults.id;
    	      this.isConsoleDeployable = defaults.isConsoleDeployable;
    	      this.name = defaults.name;
    	      this.state = defaults.state;
    	      this.supportedPlatformTypes = defaults.supportedPlatformTypes;
    	      this.version = defaults.version;
        }

        public Builder description(String description) {
            this.description = Objects.requireNonNull(description);
            return this;
        }
        public Builder displayName(String displayName) {
            this.displayName = Objects.requireNonNull(displayName);
            return this;
        }
        public Builder id(String id) {
            this.id = Objects.requireNonNull(id);
            return this;
        }
        public Builder isConsoleDeployable(Boolean isConsoleDeployable) {
            this.isConsoleDeployable = Objects.requireNonNull(isConsoleDeployable);
            return this;
        }
        public Builder name(String name) {
            this.name = Objects.requireNonNull(name);
            return this;
        }
        public Builder state(String state) {
            this.state = Objects.requireNonNull(state);
            return this;
        }
        public Builder supportedPlatformTypes(List<String> supportedPlatformTypes) {
            this.supportedPlatformTypes = Objects.requireNonNull(supportedPlatformTypes);
            return this;
        }
        public Builder supportedPlatformTypes(String... supportedPlatformTypes) {
            return supportedPlatformTypes(List.of(supportedPlatformTypes));
        }
        public Builder version(Integer version) {
            this.version = Objects.requireNonNull(version);
            return this;
        }        public GetManagementAgentPluginsManagementAgentPlugin build() {
            return new GetManagementAgentPluginsManagementAgentPlugin(description, displayName, id, isConsoleDeployable, name, state, supportedPlatformTypes, version);
        }
    }
}
