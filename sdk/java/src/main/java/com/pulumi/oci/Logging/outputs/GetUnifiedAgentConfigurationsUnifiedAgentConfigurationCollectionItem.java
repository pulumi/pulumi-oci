// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Logging.outputs;

import com.pulumi.core.annotations.CustomType;
import java.lang.Boolean;
import java.lang.Object;
import java.lang.String;
import java.util.Map;
import java.util.Objects;

@CustomType
public final class GetUnifiedAgentConfigurationsUnifiedAgentConfigurationCollectionItem {
    /**
     * @return Compartment OCID to list resources in. See compartmentIdInSubtree for nested compartments traversal.
     * 
     */
    private final String compartmentId;
    /**
     * @return State of unified agent service configuration.
     * 
     */
    private final String configurationState;
    /**
     * @return Type of Unified Agent service configuration.
     * 
     */
    private final String configurationType;
    /**
     * @return Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{&#34;Operations.CostCenter&#34;: &#34;42&#34;}`
     * 
     */
    private final Map<String,Object> definedTags;
    /**
     * @return Description for this resource.
     * 
     */
    private final String description;
    /**
     * @return Resource name
     * 
     */
    private final String displayName;
    /**
     * @return Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{&#34;Department&#34;: &#34;Finance&#34;}`
     * 
     */
    private final Map<String,Object> freeformTags;
    /**
     * @return The OCID of the resource.
     * 
     */
    private final String id;
    /**
     * @return Whether or not this resource is currently enabled.
     * 
     */
    private final Boolean isEnabled;
    /**
     * @return Lifecycle state of the log object
     * 
     */
    private final String state;
    /**
     * @return Time the resource was created.
     * 
     */
    private final String timeCreated;
    /**
     * @return Time the resource was last modified.
     * 
     */
    private final String timeLastModified;

    @CustomType.Constructor
    private GetUnifiedAgentConfigurationsUnifiedAgentConfigurationCollectionItem(
        @CustomType.Parameter("compartmentId") String compartmentId,
        @CustomType.Parameter("configurationState") String configurationState,
        @CustomType.Parameter("configurationType") String configurationType,
        @CustomType.Parameter("definedTags") Map<String,Object> definedTags,
        @CustomType.Parameter("description") String description,
        @CustomType.Parameter("displayName") String displayName,
        @CustomType.Parameter("freeformTags") Map<String,Object> freeformTags,
        @CustomType.Parameter("id") String id,
        @CustomType.Parameter("isEnabled") Boolean isEnabled,
        @CustomType.Parameter("state") String state,
        @CustomType.Parameter("timeCreated") String timeCreated,
        @CustomType.Parameter("timeLastModified") String timeLastModified) {
        this.compartmentId = compartmentId;
        this.configurationState = configurationState;
        this.configurationType = configurationType;
        this.definedTags = definedTags;
        this.description = description;
        this.displayName = displayName;
        this.freeformTags = freeformTags;
        this.id = id;
        this.isEnabled = isEnabled;
        this.state = state;
        this.timeCreated = timeCreated;
        this.timeLastModified = timeLastModified;
    }

    /**
     * @return Compartment OCID to list resources in. See compartmentIdInSubtree for nested compartments traversal.
     * 
     */
    public String compartmentId() {
        return this.compartmentId;
    }
    /**
     * @return State of unified agent service configuration.
     * 
     */
    public String configurationState() {
        return this.configurationState;
    }
    /**
     * @return Type of Unified Agent service configuration.
     * 
     */
    public String configurationType() {
        return this.configurationType;
    }
    /**
     * @return Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{&#34;Operations.CostCenter&#34;: &#34;42&#34;}`
     * 
     */
    public Map<String,Object> definedTags() {
        return this.definedTags;
    }
    /**
     * @return Description for this resource.
     * 
     */
    public String description() {
        return this.description;
    }
    /**
     * @return Resource name
     * 
     */
    public String displayName() {
        return this.displayName;
    }
    /**
     * @return Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{&#34;Department&#34;: &#34;Finance&#34;}`
     * 
     */
    public Map<String,Object> freeformTags() {
        return this.freeformTags;
    }
    /**
     * @return The OCID of the resource.
     * 
     */
    public String id() {
        return this.id;
    }
    /**
     * @return Whether or not this resource is currently enabled.
     * 
     */
    public Boolean isEnabled() {
        return this.isEnabled;
    }
    /**
     * @return Lifecycle state of the log object
     * 
     */
    public String state() {
        return this.state;
    }
    /**
     * @return Time the resource was created.
     * 
     */
    public String timeCreated() {
        return this.timeCreated;
    }
    /**
     * @return Time the resource was last modified.
     * 
     */
    public String timeLastModified() {
        return this.timeLastModified;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetUnifiedAgentConfigurationsUnifiedAgentConfigurationCollectionItem defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private String compartmentId;
        private String configurationState;
        private String configurationType;
        private Map<String,Object> definedTags;
        private String description;
        private String displayName;
        private Map<String,Object> freeformTags;
        private String id;
        private Boolean isEnabled;
        private String state;
        private String timeCreated;
        private String timeLastModified;

        public Builder() {
    	      // Empty
        }

        public Builder(GetUnifiedAgentConfigurationsUnifiedAgentConfigurationCollectionItem defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.compartmentId = defaults.compartmentId;
    	      this.configurationState = defaults.configurationState;
    	      this.configurationType = defaults.configurationType;
    	      this.definedTags = defaults.definedTags;
    	      this.description = defaults.description;
    	      this.displayName = defaults.displayName;
    	      this.freeformTags = defaults.freeformTags;
    	      this.id = defaults.id;
    	      this.isEnabled = defaults.isEnabled;
    	      this.state = defaults.state;
    	      this.timeCreated = defaults.timeCreated;
    	      this.timeLastModified = defaults.timeLastModified;
        }

        public Builder compartmentId(String compartmentId) {
            this.compartmentId = Objects.requireNonNull(compartmentId);
            return this;
        }
        public Builder configurationState(String configurationState) {
            this.configurationState = Objects.requireNonNull(configurationState);
            return this;
        }
        public Builder configurationType(String configurationType) {
            this.configurationType = Objects.requireNonNull(configurationType);
            return this;
        }
        public Builder definedTags(Map<String,Object> definedTags) {
            this.definedTags = Objects.requireNonNull(definedTags);
            return this;
        }
        public Builder description(String description) {
            this.description = Objects.requireNonNull(description);
            return this;
        }
        public Builder displayName(String displayName) {
            this.displayName = Objects.requireNonNull(displayName);
            return this;
        }
        public Builder freeformTags(Map<String,Object> freeformTags) {
            this.freeformTags = Objects.requireNonNull(freeformTags);
            return this;
        }
        public Builder id(String id) {
            this.id = Objects.requireNonNull(id);
            return this;
        }
        public Builder isEnabled(Boolean isEnabled) {
            this.isEnabled = Objects.requireNonNull(isEnabled);
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
        public Builder timeLastModified(String timeLastModified) {
            this.timeLastModified = Objects.requireNonNull(timeLastModified);
            return this;
        }        public GetUnifiedAgentConfigurationsUnifiedAgentConfigurationCollectionItem build() {
            return new GetUnifiedAgentConfigurationsUnifiedAgentConfigurationCollectionItem(compartmentId, configurationState, configurationType, definedTags, description, displayName, freeformTags, id, isEnabled, state, timeCreated, timeLastModified);
        }
    }
}
