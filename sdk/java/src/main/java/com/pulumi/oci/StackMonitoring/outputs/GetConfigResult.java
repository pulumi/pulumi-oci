// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.StackMonitoring.outputs;

import com.pulumi.core.annotations.CustomType;
import java.lang.Boolean;
import java.lang.Object;
import java.lang.String;
import java.util.Map;
import java.util.Objects;

@CustomType
public final class GetConfigResult {
    /**
     * @return The OCID of the compartment containing the configuration.
     * 
     */
    private String compartmentId;
    private String configId;
    /**
     * @return The type of configuration.
     * 
     */
    private String configType;
    /**
     * @return Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{&#34;foo-namespace.bar-key&#34;: &#34;value&#34;}`
     * 
     */
    private Map<String,Object> definedTags;
    /**
     * @return A user-friendly name. Does not have to be unique, and it&#39;s changeable. Avoid entering confidential information.
     * 
     */
    private String displayName;
    /**
     * @return Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{&#34;bar-key&#34;: &#34;value&#34;}`
     * 
     */
    private Map<String,Object> freeformTags;
    /**
     * @return The Unique Oracle ID (OCID) that is immutable on creation.
     * 
     */
    private String id;
    /**
     * @return True if automatic promotion is enabled, false if it is not enabled.
     * 
     */
    private Boolean isEnabled;
    /**
     * @return The type of resource to configure for automatic promotion.
     * 
     */
    private String resourceType;
    /**
     * @return The current state of the configuration.
     * 
     */
    private String state;
    /**
     * @return Usage of system tag keys. These predefined keys are scoped to namespaces. Example: `{&#34;orcl-cloud.free-tier-retained&#34;: &#34;true&#34;}`
     * 
     */
    private Map<String,Object> systemTags;
    /**
     * @return The time the configuration was created. An RFC3339 formatted datetime string.
     * 
     */
    private String timeCreated;
    /**
     * @return The time the Config was updated.
     * 
     */
    private String timeUpdated;

    private GetConfigResult() {}
    /**
     * @return The OCID of the compartment containing the configuration.
     * 
     */
    public String compartmentId() {
        return this.compartmentId;
    }
    public String configId() {
        return this.configId;
    }
    /**
     * @return The type of configuration.
     * 
     */
    public String configType() {
        return this.configType;
    }
    /**
     * @return Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{&#34;foo-namespace.bar-key&#34;: &#34;value&#34;}`
     * 
     */
    public Map<String,Object> definedTags() {
        return this.definedTags;
    }
    /**
     * @return A user-friendly name. Does not have to be unique, and it&#39;s changeable. Avoid entering confidential information.
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
     * @return The Unique Oracle ID (OCID) that is immutable on creation.
     * 
     */
    public String id() {
        return this.id;
    }
    /**
     * @return True if automatic promotion is enabled, false if it is not enabled.
     * 
     */
    public Boolean isEnabled() {
        return this.isEnabled;
    }
    /**
     * @return The type of resource to configure for automatic promotion.
     * 
     */
    public String resourceType() {
        return this.resourceType;
    }
    /**
     * @return The current state of the configuration.
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
     * @return The time the configuration was created. An RFC3339 formatted datetime string.
     * 
     */
    public String timeCreated() {
        return this.timeCreated;
    }
    /**
     * @return The time the Config was updated.
     * 
     */
    public String timeUpdated() {
        return this.timeUpdated;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetConfigResult defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String compartmentId;
        private String configId;
        private String configType;
        private Map<String,Object> definedTags;
        private String displayName;
        private Map<String,Object> freeformTags;
        private String id;
        private Boolean isEnabled;
        private String resourceType;
        private String state;
        private Map<String,Object> systemTags;
        private String timeCreated;
        private String timeUpdated;
        public Builder() {}
        public Builder(GetConfigResult defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.compartmentId = defaults.compartmentId;
    	      this.configId = defaults.configId;
    	      this.configType = defaults.configType;
    	      this.definedTags = defaults.definedTags;
    	      this.displayName = defaults.displayName;
    	      this.freeformTags = defaults.freeformTags;
    	      this.id = defaults.id;
    	      this.isEnabled = defaults.isEnabled;
    	      this.resourceType = defaults.resourceType;
    	      this.state = defaults.state;
    	      this.systemTags = defaults.systemTags;
    	      this.timeCreated = defaults.timeCreated;
    	      this.timeUpdated = defaults.timeUpdated;
        }

        @CustomType.Setter
        public Builder compartmentId(String compartmentId) {
            this.compartmentId = Objects.requireNonNull(compartmentId);
            return this;
        }
        @CustomType.Setter
        public Builder configId(String configId) {
            this.configId = Objects.requireNonNull(configId);
            return this;
        }
        @CustomType.Setter
        public Builder configType(String configType) {
            this.configType = Objects.requireNonNull(configType);
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
        public Builder freeformTags(Map<String,Object> freeformTags) {
            this.freeformTags = Objects.requireNonNull(freeformTags);
            return this;
        }
        @CustomType.Setter
        public Builder id(String id) {
            this.id = Objects.requireNonNull(id);
            return this;
        }
        @CustomType.Setter
        public Builder isEnabled(Boolean isEnabled) {
            this.isEnabled = Objects.requireNonNull(isEnabled);
            return this;
        }
        @CustomType.Setter
        public Builder resourceType(String resourceType) {
            this.resourceType = Objects.requireNonNull(resourceType);
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
        public Builder timeUpdated(String timeUpdated) {
            this.timeUpdated = Objects.requireNonNull(timeUpdated);
            return this;
        }
        public GetConfigResult build() {
            final var o = new GetConfigResult();
            o.compartmentId = compartmentId;
            o.configId = configId;
            o.configType = configType;
            o.definedTags = definedTags;
            o.displayName = displayName;
            o.freeformTags = freeformTags;
            o.id = id;
            o.isEnabled = isEnabled;
            o.resourceType = resourceType;
            o.state = state;
            o.systemTags = systemTags;
            o.timeCreated = timeCreated;
            o.timeUpdated = timeUpdated;
            return o;
        }
    }
}