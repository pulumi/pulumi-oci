// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.StackMonitoring.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.StackMonitoring.outputs.GetMonitoredResourceTypeMetadata;
import java.lang.String;
import java.util.List;
import java.util.Map;
import java.util.Objects;

@CustomType
public final class GetMonitoredResourceTypeResult {
    /**
     * @return Key/Value pair for additional namespaces used by stack monitoring services for SYSTEM (SMB) resource types.
     * 
     */
    private Map<String,String> additionalNamespaceMap;
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the tenancy containing the resource type.
     * 
     */
    private String compartmentId;
    /**
     * @return Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{&#34;foo-namespace.bar-key&#34;: &#34;value&#34;}`
     * 
     */
    private Map<String,String> definedTags;
    /**
     * @return A friendly description.
     * 
     */
    private String description;
    /**
     * @return Monitored resource type display name.
     * 
     */
    private String displayName;
    /**
     * @return Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{&#34;bar-key&#34;: &#34;value&#34;}`
     * 
     */
    private Map<String,String> freeformTags;
    /**
     * @return Monitored resource type identifier [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
     * 
     */
    private String id;
    /**
     * @return The metadata details for resource type.
     * 
     */
    private List<GetMonitoredResourceTypeMetadata> metadatas;
    /**
     * @return Metric namespace for resource type.
     * 
     */
    private String metricNamespace;
    private String monitoredResourceTypeId;
    /**
     * @return A unique monitored resource type name. The name must be unique across tenancy.  Name can not be changed.
     * 
     */
    private String name;
    /**
     * @return Resource Category to indicate the kind of resource type.
     * 
     */
    private String resourceCategory;
    /**
     * @return Source type to indicate if the resource is stack monitoring discovered, Oracle Cloud Infrastructure native resource, etc.
     * 
     */
    private String sourceType;
    /**
     * @return Lifecycle state of the monitored resource type.
     * 
     */
    private String state;
    /**
     * @return Usage of system tag keys. These predefined keys are scoped to namespaces. Example: `{&#34;orcl-cloud.free-tier-retained&#34;: &#34;true&#34;}`
     * 
     */
    private Map<String,String> systemTags;
    /**
     * @return The date and time when the monitored resource type was created, expressed in  [RFC 3339](https://tools.ietf.org/html/rfc3339) timestamp format.
     * 
     */
    private String timeCreated;
    /**
     * @return The date and time when the monitored resource was updated, expressed in  [RFC 3339](https://tools.ietf.org/html/rfc3339) timestamp format.
     * 
     */
    private String timeUpdated;

    private GetMonitoredResourceTypeResult() {}
    /**
     * @return Key/Value pair for additional namespaces used by stack monitoring services for SYSTEM (SMB) resource types.
     * 
     */
    public Map<String,String> additionalNamespaceMap() {
        return this.additionalNamespaceMap;
    }
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the tenancy containing the resource type.
     * 
     */
    public String compartmentId() {
        return this.compartmentId;
    }
    /**
     * @return Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{&#34;foo-namespace.bar-key&#34;: &#34;value&#34;}`
     * 
     */
    public Map<String,String> definedTags() {
        return this.definedTags;
    }
    /**
     * @return A friendly description.
     * 
     */
    public String description() {
        return this.description;
    }
    /**
     * @return Monitored resource type display name.
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
     * @return Monitored resource type identifier [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
     * 
     */
    public String id() {
        return this.id;
    }
    /**
     * @return The metadata details for resource type.
     * 
     */
    public List<GetMonitoredResourceTypeMetadata> metadatas() {
        return this.metadatas;
    }
    /**
     * @return Metric namespace for resource type.
     * 
     */
    public String metricNamespace() {
        return this.metricNamespace;
    }
    public String monitoredResourceTypeId() {
        return this.monitoredResourceTypeId;
    }
    /**
     * @return A unique monitored resource type name. The name must be unique across tenancy.  Name can not be changed.
     * 
     */
    public String name() {
        return this.name;
    }
    /**
     * @return Resource Category to indicate the kind of resource type.
     * 
     */
    public String resourceCategory() {
        return this.resourceCategory;
    }
    /**
     * @return Source type to indicate if the resource is stack monitoring discovered, Oracle Cloud Infrastructure native resource, etc.
     * 
     */
    public String sourceType() {
        return this.sourceType;
    }
    /**
     * @return Lifecycle state of the monitored resource type.
     * 
     */
    public String state() {
        return this.state;
    }
    /**
     * @return Usage of system tag keys. These predefined keys are scoped to namespaces. Example: `{&#34;orcl-cloud.free-tier-retained&#34;: &#34;true&#34;}`
     * 
     */
    public Map<String,String> systemTags() {
        return this.systemTags;
    }
    /**
     * @return The date and time when the monitored resource type was created, expressed in  [RFC 3339](https://tools.ietf.org/html/rfc3339) timestamp format.
     * 
     */
    public String timeCreated() {
        return this.timeCreated;
    }
    /**
     * @return The date and time when the monitored resource was updated, expressed in  [RFC 3339](https://tools.ietf.org/html/rfc3339) timestamp format.
     * 
     */
    public String timeUpdated() {
        return this.timeUpdated;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetMonitoredResourceTypeResult defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private Map<String,String> additionalNamespaceMap;
        private String compartmentId;
        private Map<String,String> definedTags;
        private String description;
        private String displayName;
        private Map<String,String> freeformTags;
        private String id;
        private List<GetMonitoredResourceTypeMetadata> metadatas;
        private String metricNamespace;
        private String monitoredResourceTypeId;
        private String name;
        private String resourceCategory;
        private String sourceType;
        private String state;
        private Map<String,String> systemTags;
        private String timeCreated;
        private String timeUpdated;
        public Builder() {}
        public Builder(GetMonitoredResourceTypeResult defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.additionalNamespaceMap = defaults.additionalNamespaceMap;
    	      this.compartmentId = defaults.compartmentId;
    	      this.definedTags = defaults.definedTags;
    	      this.description = defaults.description;
    	      this.displayName = defaults.displayName;
    	      this.freeformTags = defaults.freeformTags;
    	      this.id = defaults.id;
    	      this.metadatas = defaults.metadatas;
    	      this.metricNamespace = defaults.metricNamespace;
    	      this.monitoredResourceTypeId = defaults.monitoredResourceTypeId;
    	      this.name = defaults.name;
    	      this.resourceCategory = defaults.resourceCategory;
    	      this.sourceType = defaults.sourceType;
    	      this.state = defaults.state;
    	      this.systemTags = defaults.systemTags;
    	      this.timeCreated = defaults.timeCreated;
    	      this.timeUpdated = defaults.timeUpdated;
        }

        @CustomType.Setter
        public Builder additionalNamespaceMap(Map<String,String> additionalNamespaceMap) {
            if (additionalNamespaceMap == null) {
              throw new MissingRequiredPropertyException("GetMonitoredResourceTypeResult", "additionalNamespaceMap");
            }
            this.additionalNamespaceMap = additionalNamespaceMap;
            return this;
        }
        @CustomType.Setter
        public Builder compartmentId(String compartmentId) {
            if (compartmentId == null) {
              throw new MissingRequiredPropertyException("GetMonitoredResourceTypeResult", "compartmentId");
            }
            this.compartmentId = compartmentId;
            return this;
        }
        @CustomType.Setter
        public Builder definedTags(Map<String,String> definedTags) {
            if (definedTags == null) {
              throw new MissingRequiredPropertyException("GetMonitoredResourceTypeResult", "definedTags");
            }
            this.definedTags = definedTags;
            return this;
        }
        @CustomType.Setter
        public Builder description(String description) {
            if (description == null) {
              throw new MissingRequiredPropertyException("GetMonitoredResourceTypeResult", "description");
            }
            this.description = description;
            return this;
        }
        @CustomType.Setter
        public Builder displayName(String displayName) {
            if (displayName == null) {
              throw new MissingRequiredPropertyException("GetMonitoredResourceTypeResult", "displayName");
            }
            this.displayName = displayName;
            return this;
        }
        @CustomType.Setter
        public Builder freeformTags(Map<String,String> freeformTags) {
            if (freeformTags == null) {
              throw new MissingRequiredPropertyException("GetMonitoredResourceTypeResult", "freeformTags");
            }
            this.freeformTags = freeformTags;
            return this;
        }
        @CustomType.Setter
        public Builder id(String id) {
            if (id == null) {
              throw new MissingRequiredPropertyException("GetMonitoredResourceTypeResult", "id");
            }
            this.id = id;
            return this;
        }
        @CustomType.Setter
        public Builder metadatas(List<GetMonitoredResourceTypeMetadata> metadatas) {
            if (metadatas == null) {
              throw new MissingRequiredPropertyException("GetMonitoredResourceTypeResult", "metadatas");
            }
            this.metadatas = metadatas;
            return this;
        }
        public Builder metadatas(GetMonitoredResourceTypeMetadata... metadatas) {
            return metadatas(List.of(metadatas));
        }
        @CustomType.Setter
        public Builder metricNamespace(String metricNamespace) {
            if (metricNamespace == null) {
              throw new MissingRequiredPropertyException("GetMonitoredResourceTypeResult", "metricNamespace");
            }
            this.metricNamespace = metricNamespace;
            return this;
        }
        @CustomType.Setter
        public Builder monitoredResourceTypeId(String monitoredResourceTypeId) {
            if (monitoredResourceTypeId == null) {
              throw new MissingRequiredPropertyException("GetMonitoredResourceTypeResult", "monitoredResourceTypeId");
            }
            this.monitoredResourceTypeId = monitoredResourceTypeId;
            return this;
        }
        @CustomType.Setter
        public Builder name(String name) {
            if (name == null) {
              throw new MissingRequiredPropertyException("GetMonitoredResourceTypeResult", "name");
            }
            this.name = name;
            return this;
        }
        @CustomType.Setter
        public Builder resourceCategory(String resourceCategory) {
            if (resourceCategory == null) {
              throw new MissingRequiredPropertyException("GetMonitoredResourceTypeResult", "resourceCategory");
            }
            this.resourceCategory = resourceCategory;
            return this;
        }
        @CustomType.Setter
        public Builder sourceType(String sourceType) {
            if (sourceType == null) {
              throw new MissingRequiredPropertyException("GetMonitoredResourceTypeResult", "sourceType");
            }
            this.sourceType = sourceType;
            return this;
        }
        @CustomType.Setter
        public Builder state(String state) {
            if (state == null) {
              throw new MissingRequiredPropertyException("GetMonitoredResourceTypeResult", "state");
            }
            this.state = state;
            return this;
        }
        @CustomType.Setter
        public Builder systemTags(Map<String,String> systemTags) {
            if (systemTags == null) {
              throw new MissingRequiredPropertyException("GetMonitoredResourceTypeResult", "systemTags");
            }
            this.systemTags = systemTags;
            return this;
        }
        @CustomType.Setter
        public Builder timeCreated(String timeCreated) {
            if (timeCreated == null) {
              throw new MissingRequiredPropertyException("GetMonitoredResourceTypeResult", "timeCreated");
            }
            this.timeCreated = timeCreated;
            return this;
        }
        @CustomType.Setter
        public Builder timeUpdated(String timeUpdated) {
            if (timeUpdated == null) {
              throw new MissingRequiredPropertyException("GetMonitoredResourceTypeResult", "timeUpdated");
            }
            this.timeUpdated = timeUpdated;
            return this;
        }
        public GetMonitoredResourceTypeResult build() {
            final var _resultValue = new GetMonitoredResourceTypeResult();
            _resultValue.additionalNamespaceMap = additionalNamespaceMap;
            _resultValue.compartmentId = compartmentId;
            _resultValue.definedTags = definedTags;
            _resultValue.description = description;
            _resultValue.displayName = displayName;
            _resultValue.freeformTags = freeformTags;
            _resultValue.id = id;
            _resultValue.metadatas = metadatas;
            _resultValue.metricNamespace = metricNamespace;
            _resultValue.monitoredResourceTypeId = monitoredResourceTypeId;
            _resultValue.name = name;
            _resultValue.resourceCategory = resourceCategory;
            _resultValue.sourceType = sourceType;
            _resultValue.state = state;
            _resultValue.systemTags = systemTags;
            _resultValue.timeCreated = timeCreated;
            _resultValue.timeUpdated = timeUpdated;
            return _resultValue;
        }
    }
}
