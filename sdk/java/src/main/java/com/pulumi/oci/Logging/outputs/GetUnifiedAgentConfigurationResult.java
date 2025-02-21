// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Logging.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.Logging.outputs.GetUnifiedAgentConfigurationGroupAssociation;
import com.pulumi.oci.Logging.outputs.GetUnifiedAgentConfigurationServiceConfiguration;
import java.lang.Boolean;
import java.lang.String;
import java.util.List;
import java.util.Map;
import java.util.Objects;

@CustomType
public final class GetUnifiedAgentConfigurationResult {
    /**
     * @return The OCID of the compartment that the resource belongs to.
     * 
     */
    private String compartmentId;
    /**
     * @return State of unified agent service configuration.
     * 
     */
    private String configurationState;
    /**
     * @return Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{&#34;Operations.CostCenter&#34;: &#34;42&#34;}`
     * 
     */
    private Map<String,String> definedTags;
    /**
     * @return Description for this resource.
     * 
     */
    private String description;
    /**
     * @return The user-friendly display name. This must be unique within the enclosing resource, and it&#39;s changeable. Avoid entering confidential information.
     * 
     */
    private String displayName;
    /**
     * @return Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{&#34;Department&#34;: &#34;Finance&#34;}`
     * 
     */
    private Map<String,String> freeformTags;
    /**
     * @return Groups using the configuration.
     * 
     */
    private List<GetUnifiedAgentConfigurationGroupAssociation> groupAssociations;
    /**
     * @return The OCID of the resource.
     * 
     */
    private String id;
    /**
     * @return Whether or not this resource is currently enabled.
     * 
     */
    private Boolean isEnabled;
    /**
     * @return Top level Unified Agent service configuration object.
     * 
     */
    private List<GetUnifiedAgentConfigurationServiceConfiguration> serviceConfigurations;
    /**
     * @return The pipeline state.
     * 
     */
    private String state;
    /**
     * @return Time the resource was created.
     * 
     */
    private String timeCreated;
    /**
     * @return Time the resource was last modified.
     * 
     */
    private String timeLastModified;
    private String unifiedAgentConfigurationId;

    private GetUnifiedAgentConfigurationResult() {}
    /**
     * @return The OCID of the compartment that the resource belongs to.
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
     * @return Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{&#34;Operations.CostCenter&#34;: &#34;42&#34;}`
     * 
     */
    public Map<String,String> definedTags() {
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
     * @return The user-friendly display name. This must be unique within the enclosing resource, and it&#39;s changeable. Avoid entering confidential information.
     * 
     */
    public String displayName() {
        return this.displayName;
    }
    /**
     * @return Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{&#34;Department&#34;: &#34;Finance&#34;}`
     * 
     */
    public Map<String,String> freeformTags() {
        return this.freeformTags;
    }
    /**
     * @return Groups using the configuration.
     * 
     */
    public List<GetUnifiedAgentConfigurationGroupAssociation> groupAssociations() {
        return this.groupAssociations;
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
     * @return Top level Unified Agent service configuration object.
     * 
     */
    public List<GetUnifiedAgentConfigurationServiceConfiguration> serviceConfigurations() {
        return this.serviceConfigurations;
    }
    /**
     * @return The pipeline state.
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
    public String unifiedAgentConfigurationId() {
        return this.unifiedAgentConfigurationId;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetUnifiedAgentConfigurationResult defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String compartmentId;
        private String configurationState;
        private Map<String,String> definedTags;
        private String description;
        private String displayName;
        private Map<String,String> freeformTags;
        private List<GetUnifiedAgentConfigurationGroupAssociation> groupAssociations;
        private String id;
        private Boolean isEnabled;
        private List<GetUnifiedAgentConfigurationServiceConfiguration> serviceConfigurations;
        private String state;
        private String timeCreated;
        private String timeLastModified;
        private String unifiedAgentConfigurationId;
        public Builder() {}
        public Builder(GetUnifiedAgentConfigurationResult defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.compartmentId = defaults.compartmentId;
    	      this.configurationState = defaults.configurationState;
    	      this.definedTags = defaults.definedTags;
    	      this.description = defaults.description;
    	      this.displayName = defaults.displayName;
    	      this.freeformTags = defaults.freeformTags;
    	      this.groupAssociations = defaults.groupAssociations;
    	      this.id = defaults.id;
    	      this.isEnabled = defaults.isEnabled;
    	      this.serviceConfigurations = defaults.serviceConfigurations;
    	      this.state = defaults.state;
    	      this.timeCreated = defaults.timeCreated;
    	      this.timeLastModified = defaults.timeLastModified;
    	      this.unifiedAgentConfigurationId = defaults.unifiedAgentConfigurationId;
        }

        @CustomType.Setter
        public Builder compartmentId(String compartmentId) {
            if (compartmentId == null) {
              throw new MissingRequiredPropertyException("GetUnifiedAgentConfigurationResult", "compartmentId");
            }
            this.compartmentId = compartmentId;
            return this;
        }
        @CustomType.Setter
        public Builder configurationState(String configurationState) {
            if (configurationState == null) {
              throw new MissingRequiredPropertyException("GetUnifiedAgentConfigurationResult", "configurationState");
            }
            this.configurationState = configurationState;
            return this;
        }
        @CustomType.Setter
        public Builder definedTags(Map<String,String> definedTags) {
            if (definedTags == null) {
              throw new MissingRequiredPropertyException("GetUnifiedAgentConfigurationResult", "definedTags");
            }
            this.definedTags = definedTags;
            return this;
        }
        @CustomType.Setter
        public Builder description(String description) {
            if (description == null) {
              throw new MissingRequiredPropertyException("GetUnifiedAgentConfigurationResult", "description");
            }
            this.description = description;
            return this;
        }
        @CustomType.Setter
        public Builder displayName(String displayName) {
            if (displayName == null) {
              throw new MissingRequiredPropertyException("GetUnifiedAgentConfigurationResult", "displayName");
            }
            this.displayName = displayName;
            return this;
        }
        @CustomType.Setter
        public Builder freeformTags(Map<String,String> freeformTags) {
            if (freeformTags == null) {
              throw new MissingRequiredPropertyException("GetUnifiedAgentConfigurationResult", "freeformTags");
            }
            this.freeformTags = freeformTags;
            return this;
        }
        @CustomType.Setter
        public Builder groupAssociations(List<GetUnifiedAgentConfigurationGroupAssociation> groupAssociations) {
            if (groupAssociations == null) {
              throw new MissingRequiredPropertyException("GetUnifiedAgentConfigurationResult", "groupAssociations");
            }
            this.groupAssociations = groupAssociations;
            return this;
        }
        public Builder groupAssociations(GetUnifiedAgentConfigurationGroupAssociation... groupAssociations) {
            return groupAssociations(List.of(groupAssociations));
        }
        @CustomType.Setter
        public Builder id(String id) {
            if (id == null) {
              throw new MissingRequiredPropertyException("GetUnifiedAgentConfigurationResult", "id");
            }
            this.id = id;
            return this;
        }
        @CustomType.Setter
        public Builder isEnabled(Boolean isEnabled) {
            if (isEnabled == null) {
              throw new MissingRequiredPropertyException("GetUnifiedAgentConfigurationResult", "isEnabled");
            }
            this.isEnabled = isEnabled;
            return this;
        }
        @CustomType.Setter
        public Builder serviceConfigurations(List<GetUnifiedAgentConfigurationServiceConfiguration> serviceConfigurations) {
            if (serviceConfigurations == null) {
              throw new MissingRequiredPropertyException("GetUnifiedAgentConfigurationResult", "serviceConfigurations");
            }
            this.serviceConfigurations = serviceConfigurations;
            return this;
        }
        public Builder serviceConfigurations(GetUnifiedAgentConfigurationServiceConfiguration... serviceConfigurations) {
            return serviceConfigurations(List.of(serviceConfigurations));
        }
        @CustomType.Setter
        public Builder state(String state) {
            if (state == null) {
              throw new MissingRequiredPropertyException("GetUnifiedAgentConfigurationResult", "state");
            }
            this.state = state;
            return this;
        }
        @CustomType.Setter
        public Builder timeCreated(String timeCreated) {
            if (timeCreated == null) {
              throw new MissingRequiredPropertyException("GetUnifiedAgentConfigurationResult", "timeCreated");
            }
            this.timeCreated = timeCreated;
            return this;
        }
        @CustomType.Setter
        public Builder timeLastModified(String timeLastModified) {
            if (timeLastModified == null) {
              throw new MissingRequiredPropertyException("GetUnifiedAgentConfigurationResult", "timeLastModified");
            }
            this.timeLastModified = timeLastModified;
            return this;
        }
        @CustomType.Setter
        public Builder unifiedAgentConfigurationId(String unifiedAgentConfigurationId) {
            if (unifiedAgentConfigurationId == null) {
              throw new MissingRequiredPropertyException("GetUnifiedAgentConfigurationResult", "unifiedAgentConfigurationId");
            }
            this.unifiedAgentConfigurationId = unifiedAgentConfigurationId;
            return this;
        }
        public GetUnifiedAgentConfigurationResult build() {
            final var _resultValue = new GetUnifiedAgentConfigurationResult();
            _resultValue.compartmentId = compartmentId;
            _resultValue.configurationState = configurationState;
            _resultValue.definedTags = definedTags;
            _resultValue.description = description;
            _resultValue.displayName = displayName;
            _resultValue.freeformTags = freeformTags;
            _resultValue.groupAssociations = groupAssociations;
            _resultValue.id = id;
            _resultValue.isEnabled = isEnabled;
            _resultValue.serviceConfigurations = serviceConfigurations;
            _resultValue.state = state;
            _resultValue.timeCreated = timeCreated;
            _resultValue.timeLastModified = timeLastModified;
            _resultValue.unifiedAgentConfigurationId = unifiedAgentConfigurationId;
            return _resultValue;
        }
    }
}
