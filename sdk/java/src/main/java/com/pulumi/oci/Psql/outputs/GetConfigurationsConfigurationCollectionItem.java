// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Psql.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.Psql.outputs.GetConfigurationsConfigurationCollectionItemConfigurationDetail;
import com.pulumi.oci.Psql.outputs.GetConfigurationsConfigurationCollectionItemDbConfigurationOverride;
import java.lang.Boolean;
import java.lang.Integer;
import java.lang.String;
import java.util.List;
import java.util.Map;
import java.util.Objects;

@CustomType
public final class GetConfigurationsConfigurationCollectionItem {
    /**
     * @return The ID of the compartment in which to list resources.
     * 
     */
    private String compartmentId;
    /**
     * @return A filter to return only resources if their `configType` matches the given `configType`.
     * 
     */
    private String configType;
    /**
     * @return List of configuration details.
     * 
     */
    private List<GetConfigurationsConfigurationCollectionItemConfigurationDetail> configurationDetails;
    private List<GetConfigurationsConfigurationCollectionItemDbConfigurationOverride> dbConfigurationOverrides;
    /**
     * @return Version of the PostgreSQL database, such as 14.9.
     * 
     */
    private String dbVersion;
    /**
     * @return Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{&#34;foo-namespace.bar-key&#34;: &#34;value&#34;}`
     * 
     */
    private Map<String,String> definedTags;
    /**
     * @return A description for the configuration.
     * 
     */
    private String description;
    /**
     * @return A filter to return only resources that match the entire display name given.
     * 
     */
    private String displayName;
    /**
     * @return Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{&#34;bar-key&#34;: &#34;value&#34;}`
     * 
     */
    private Map<String,String> freeformTags;
    /**
     * @return A unique identifier for the configuration. Immutable on creation.
     * 
     */
    private String id;
    /**
     * @return Memory size in gigabytes with 1GB increment.
     * 
     */
    private Integer instanceMemorySizeInGbs;
    /**
     * @return CPU core count.
     * 
     */
    private Integer instanceOcpuCount;
    /**
     * @return Whether the configuration supports flexible shapes.
     * 
     */
    private Boolean isFlexible;
    /**
     * @return A message describing the current state in more detail. For example, can be used to provide actionable information for a resource in Failed state.
     * 
     */
    private String lifecycleDetails;
    /**
     * @return The name of the shape for the configuration. Example: `VM.Standard.E4.Flex`
     * 
     */
    private String shape;
    /**
     * @return A filter to return only resources if their `lifecycleState` matches the given `lifecycleState`.
     * 
     */
    private String state;
    /**
     * @return System tags for this resource. Each key is predefined and scoped to a namespace. Example: `{&#34;orcl-cloud.free-tier-retained&#34;: &#34;true&#34;}`
     * 
     */
    private Map<String,String> systemTags;
    /**
     * @return The date and time that the configuration was created, expressed in [RFC 3339](https://tools.ietf.org/rfc/rfc3339) timestamp format.  Example: `2016-08-25T21:10:29.600Z`
     * 
     */
    private String timeCreated;

    private GetConfigurationsConfigurationCollectionItem() {}
    /**
     * @return The ID of the compartment in which to list resources.
     * 
     */
    public String compartmentId() {
        return this.compartmentId;
    }
    /**
     * @return A filter to return only resources if their `configType` matches the given `configType`.
     * 
     */
    public String configType() {
        return this.configType;
    }
    /**
     * @return List of configuration details.
     * 
     */
    public List<GetConfigurationsConfigurationCollectionItemConfigurationDetail> configurationDetails() {
        return this.configurationDetails;
    }
    public List<GetConfigurationsConfigurationCollectionItemDbConfigurationOverride> dbConfigurationOverrides() {
        return this.dbConfigurationOverrides;
    }
    /**
     * @return Version of the PostgreSQL database, such as 14.9.
     * 
     */
    public String dbVersion() {
        return this.dbVersion;
    }
    /**
     * @return Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{&#34;foo-namespace.bar-key&#34;: &#34;value&#34;}`
     * 
     */
    public Map<String,String> definedTags() {
        return this.definedTags;
    }
    /**
     * @return A description for the configuration.
     * 
     */
    public String description() {
        return this.description;
    }
    /**
     * @return A filter to return only resources that match the entire display name given.
     * 
     */
    public String displayName() {
        return this.displayName;
    }
    /**
     * @return Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{&#34;bar-key&#34;: &#34;value&#34;}`
     * 
     */
    public Map<String,String> freeformTags() {
        return this.freeformTags;
    }
    /**
     * @return A unique identifier for the configuration. Immutable on creation.
     * 
     */
    public String id() {
        return this.id;
    }
    /**
     * @return Memory size in gigabytes with 1GB increment.
     * 
     */
    public Integer instanceMemorySizeInGbs() {
        return this.instanceMemorySizeInGbs;
    }
    /**
     * @return CPU core count.
     * 
     */
    public Integer instanceOcpuCount() {
        return this.instanceOcpuCount;
    }
    /**
     * @return Whether the configuration supports flexible shapes.
     * 
     */
    public Boolean isFlexible() {
        return this.isFlexible;
    }
    /**
     * @return A message describing the current state in more detail. For example, can be used to provide actionable information for a resource in Failed state.
     * 
     */
    public String lifecycleDetails() {
        return this.lifecycleDetails;
    }
    /**
     * @return The name of the shape for the configuration. Example: `VM.Standard.E4.Flex`
     * 
     */
    public String shape() {
        return this.shape;
    }
    /**
     * @return A filter to return only resources if their `lifecycleState` matches the given `lifecycleState`.
     * 
     */
    public String state() {
        return this.state;
    }
    /**
     * @return System tags for this resource. Each key is predefined and scoped to a namespace. Example: `{&#34;orcl-cloud.free-tier-retained&#34;: &#34;true&#34;}`
     * 
     */
    public Map<String,String> systemTags() {
        return this.systemTags;
    }
    /**
     * @return The date and time that the configuration was created, expressed in [RFC 3339](https://tools.ietf.org/rfc/rfc3339) timestamp format.  Example: `2016-08-25T21:10:29.600Z`
     * 
     */
    public String timeCreated() {
        return this.timeCreated;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetConfigurationsConfigurationCollectionItem defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String compartmentId;
        private String configType;
        private List<GetConfigurationsConfigurationCollectionItemConfigurationDetail> configurationDetails;
        private List<GetConfigurationsConfigurationCollectionItemDbConfigurationOverride> dbConfigurationOverrides;
        private String dbVersion;
        private Map<String,String> definedTags;
        private String description;
        private String displayName;
        private Map<String,String> freeformTags;
        private String id;
        private Integer instanceMemorySizeInGbs;
        private Integer instanceOcpuCount;
        private Boolean isFlexible;
        private String lifecycleDetails;
        private String shape;
        private String state;
        private Map<String,String> systemTags;
        private String timeCreated;
        public Builder() {}
        public Builder(GetConfigurationsConfigurationCollectionItem defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.compartmentId = defaults.compartmentId;
    	      this.configType = defaults.configType;
    	      this.configurationDetails = defaults.configurationDetails;
    	      this.dbConfigurationOverrides = defaults.dbConfigurationOverrides;
    	      this.dbVersion = defaults.dbVersion;
    	      this.definedTags = defaults.definedTags;
    	      this.description = defaults.description;
    	      this.displayName = defaults.displayName;
    	      this.freeformTags = defaults.freeformTags;
    	      this.id = defaults.id;
    	      this.instanceMemorySizeInGbs = defaults.instanceMemorySizeInGbs;
    	      this.instanceOcpuCount = defaults.instanceOcpuCount;
    	      this.isFlexible = defaults.isFlexible;
    	      this.lifecycleDetails = defaults.lifecycleDetails;
    	      this.shape = defaults.shape;
    	      this.state = defaults.state;
    	      this.systemTags = defaults.systemTags;
    	      this.timeCreated = defaults.timeCreated;
        }

        @CustomType.Setter
        public Builder compartmentId(String compartmentId) {
            if (compartmentId == null) {
              throw new MissingRequiredPropertyException("GetConfigurationsConfigurationCollectionItem", "compartmentId");
            }
            this.compartmentId = compartmentId;
            return this;
        }
        @CustomType.Setter
        public Builder configType(String configType) {
            if (configType == null) {
              throw new MissingRequiredPropertyException("GetConfigurationsConfigurationCollectionItem", "configType");
            }
            this.configType = configType;
            return this;
        }
        @CustomType.Setter
        public Builder configurationDetails(List<GetConfigurationsConfigurationCollectionItemConfigurationDetail> configurationDetails) {
            if (configurationDetails == null) {
              throw new MissingRequiredPropertyException("GetConfigurationsConfigurationCollectionItem", "configurationDetails");
            }
            this.configurationDetails = configurationDetails;
            return this;
        }
        public Builder configurationDetails(GetConfigurationsConfigurationCollectionItemConfigurationDetail... configurationDetails) {
            return configurationDetails(List.of(configurationDetails));
        }
        @CustomType.Setter
        public Builder dbConfigurationOverrides(List<GetConfigurationsConfigurationCollectionItemDbConfigurationOverride> dbConfigurationOverrides) {
            if (dbConfigurationOverrides == null) {
              throw new MissingRequiredPropertyException("GetConfigurationsConfigurationCollectionItem", "dbConfigurationOverrides");
            }
            this.dbConfigurationOverrides = dbConfigurationOverrides;
            return this;
        }
        public Builder dbConfigurationOverrides(GetConfigurationsConfigurationCollectionItemDbConfigurationOverride... dbConfigurationOverrides) {
            return dbConfigurationOverrides(List.of(dbConfigurationOverrides));
        }
        @CustomType.Setter
        public Builder dbVersion(String dbVersion) {
            if (dbVersion == null) {
              throw new MissingRequiredPropertyException("GetConfigurationsConfigurationCollectionItem", "dbVersion");
            }
            this.dbVersion = dbVersion;
            return this;
        }
        @CustomType.Setter
        public Builder definedTags(Map<String,String> definedTags) {
            if (definedTags == null) {
              throw new MissingRequiredPropertyException("GetConfigurationsConfigurationCollectionItem", "definedTags");
            }
            this.definedTags = definedTags;
            return this;
        }
        @CustomType.Setter
        public Builder description(String description) {
            if (description == null) {
              throw new MissingRequiredPropertyException("GetConfigurationsConfigurationCollectionItem", "description");
            }
            this.description = description;
            return this;
        }
        @CustomType.Setter
        public Builder displayName(String displayName) {
            if (displayName == null) {
              throw new MissingRequiredPropertyException("GetConfigurationsConfigurationCollectionItem", "displayName");
            }
            this.displayName = displayName;
            return this;
        }
        @CustomType.Setter
        public Builder freeformTags(Map<String,String> freeformTags) {
            if (freeformTags == null) {
              throw new MissingRequiredPropertyException("GetConfigurationsConfigurationCollectionItem", "freeformTags");
            }
            this.freeformTags = freeformTags;
            return this;
        }
        @CustomType.Setter
        public Builder id(String id) {
            if (id == null) {
              throw new MissingRequiredPropertyException("GetConfigurationsConfigurationCollectionItem", "id");
            }
            this.id = id;
            return this;
        }
        @CustomType.Setter
        public Builder instanceMemorySizeInGbs(Integer instanceMemorySizeInGbs) {
            if (instanceMemorySizeInGbs == null) {
              throw new MissingRequiredPropertyException("GetConfigurationsConfigurationCollectionItem", "instanceMemorySizeInGbs");
            }
            this.instanceMemorySizeInGbs = instanceMemorySizeInGbs;
            return this;
        }
        @CustomType.Setter
        public Builder instanceOcpuCount(Integer instanceOcpuCount) {
            if (instanceOcpuCount == null) {
              throw new MissingRequiredPropertyException("GetConfigurationsConfigurationCollectionItem", "instanceOcpuCount");
            }
            this.instanceOcpuCount = instanceOcpuCount;
            return this;
        }
        @CustomType.Setter
        public Builder isFlexible(Boolean isFlexible) {
            if (isFlexible == null) {
              throw new MissingRequiredPropertyException("GetConfigurationsConfigurationCollectionItem", "isFlexible");
            }
            this.isFlexible = isFlexible;
            return this;
        }
        @CustomType.Setter
        public Builder lifecycleDetails(String lifecycleDetails) {
            if (lifecycleDetails == null) {
              throw new MissingRequiredPropertyException("GetConfigurationsConfigurationCollectionItem", "lifecycleDetails");
            }
            this.lifecycleDetails = lifecycleDetails;
            return this;
        }
        @CustomType.Setter
        public Builder shape(String shape) {
            if (shape == null) {
              throw new MissingRequiredPropertyException("GetConfigurationsConfigurationCollectionItem", "shape");
            }
            this.shape = shape;
            return this;
        }
        @CustomType.Setter
        public Builder state(String state) {
            if (state == null) {
              throw new MissingRequiredPropertyException("GetConfigurationsConfigurationCollectionItem", "state");
            }
            this.state = state;
            return this;
        }
        @CustomType.Setter
        public Builder systemTags(Map<String,String> systemTags) {
            if (systemTags == null) {
              throw new MissingRequiredPropertyException("GetConfigurationsConfigurationCollectionItem", "systemTags");
            }
            this.systemTags = systemTags;
            return this;
        }
        @CustomType.Setter
        public Builder timeCreated(String timeCreated) {
            if (timeCreated == null) {
              throw new MissingRequiredPropertyException("GetConfigurationsConfigurationCollectionItem", "timeCreated");
            }
            this.timeCreated = timeCreated;
            return this;
        }
        public GetConfigurationsConfigurationCollectionItem build() {
            final var _resultValue = new GetConfigurationsConfigurationCollectionItem();
            _resultValue.compartmentId = compartmentId;
            _resultValue.configType = configType;
            _resultValue.configurationDetails = configurationDetails;
            _resultValue.dbConfigurationOverrides = dbConfigurationOverrides;
            _resultValue.dbVersion = dbVersion;
            _resultValue.definedTags = definedTags;
            _resultValue.description = description;
            _resultValue.displayName = displayName;
            _resultValue.freeformTags = freeformTags;
            _resultValue.id = id;
            _resultValue.instanceMemorySizeInGbs = instanceMemorySizeInGbs;
            _resultValue.instanceOcpuCount = instanceOcpuCount;
            _resultValue.isFlexible = isFlexible;
            _resultValue.lifecycleDetails = lifecycleDetails;
            _resultValue.shape = shape;
            _resultValue.state = state;
            _resultValue.systemTags = systemTags;
            _resultValue.timeCreated = timeCreated;
            return _resultValue;
        }
    }
}
