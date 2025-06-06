// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.CloudBridge.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.String;
import java.util.Map;
import java.util.Objects;

@CustomType
public final class GetAgentDependencyResult {
    private String agentDependencyId;
    /**
     * @return Object storage bucket where the Agent dependency is uploaded.
     * 
     */
    private String bucket;
    /**
     * @return The checksum associated with the dependency object returned by Object Storage.
     * 
     */
    private String checksum;
    /**
     * @return Compartment identifier
     * 
     */
    private String compartmentId;
    /**
     * @return The defined tags associated with this resource, if any. Each key is predefined and scoped to namespaces. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{&#34;Operations.CostCenter&#34;: &#34;42&#34;}`
     * 
     */
    private Map<String,String> definedTags;
    /**
     * @return Name of the dependency type. This should match the whitelisted enum of dependency names.
     * 
     */
    private String dependencyName;
    /**
     * @return Version of the Agent dependency.
     * 
     */
    private String dependencyVersion;
    /**
     * @return Description about the Agent dependency.
     * 
     */
    private String description;
    /**
     * @return Display name of the Agent dependency.
     * 
     */
    private String displayName;
    /**
     * @return The eTag associated with the dependency object returned by Object Storage.
     * 
     */
    private String eTag;
    /**
     * @return The freeform tags associated with this resource, if any. Each tag is a simple key-value pair with no predefined name, type, or namespace/scope. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{&#34;Department&#34;: &#34;Finance&#34;}`
     * 
     */
    private Map<String,String> freeformTags;
    /**
     * @return Unique identifier that is immutable on creation.
     * 
     */
    private String id;
    /**
     * @return A message describing the current state in more detail. For example, it can be used to provide actionable information for a resource in Failed state.
     * 
     */
    private String lifecycleDetails;
    /**
     * @return Object storage namespace associated with the customer&#39;s tenancy.
     * 
     */
    private String namespace;
    /**
     * @return Name of the dependency object uploaded by the customer.
     * 
     */
    private String object;
    /**
     * @return The current state of AgentDependency.
     * 
     */
    private String state;
    /**
     * @return The system tags associated with this resource, if any. The system tags are set by Oracle cloud infrastructure services. Each key is predefined and scoped to namespaces. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{orcl-cloud: {free-tier-retain: true}}`
     * 
     */
    private Map<String,String> systemTags;
    /**
     * @return The time when the AgentDependency was created. An RFC3339 formatted datetime string.
     * 
     */
    private String timeCreated;

    private GetAgentDependencyResult() {}
    public String agentDependencyId() {
        return this.agentDependencyId;
    }
    /**
     * @return Object storage bucket where the Agent dependency is uploaded.
     * 
     */
    public String bucket() {
        return this.bucket;
    }
    /**
     * @return The checksum associated with the dependency object returned by Object Storage.
     * 
     */
    public String checksum() {
        return this.checksum;
    }
    /**
     * @return Compartment identifier
     * 
     */
    public String compartmentId() {
        return this.compartmentId;
    }
    /**
     * @return The defined tags associated with this resource, if any. Each key is predefined and scoped to namespaces. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{&#34;Operations.CostCenter&#34;: &#34;42&#34;}`
     * 
     */
    public Map<String,String> definedTags() {
        return this.definedTags;
    }
    /**
     * @return Name of the dependency type. This should match the whitelisted enum of dependency names.
     * 
     */
    public String dependencyName() {
        return this.dependencyName;
    }
    /**
     * @return Version of the Agent dependency.
     * 
     */
    public String dependencyVersion() {
        return this.dependencyVersion;
    }
    /**
     * @return Description about the Agent dependency.
     * 
     */
    public String description() {
        return this.description;
    }
    /**
     * @return Display name of the Agent dependency.
     * 
     */
    public String displayName() {
        return this.displayName;
    }
    /**
     * @return The eTag associated with the dependency object returned by Object Storage.
     * 
     */
    public String eTag() {
        return this.eTag;
    }
    /**
     * @return The freeform tags associated with this resource, if any. Each tag is a simple key-value pair with no predefined name, type, or namespace/scope. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{&#34;Department&#34;: &#34;Finance&#34;}`
     * 
     */
    public Map<String,String> freeformTags() {
        return this.freeformTags;
    }
    /**
     * @return Unique identifier that is immutable on creation.
     * 
     */
    public String id() {
        return this.id;
    }
    /**
     * @return A message describing the current state in more detail. For example, it can be used to provide actionable information for a resource in Failed state.
     * 
     */
    public String lifecycleDetails() {
        return this.lifecycleDetails;
    }
    /**
     * @return Object storage namespace associated with the customer&#39;s tenancy.
     * 
     */
    public String namespace() {
        return this.namespace;
    }
    /**
     * @return Name of the dependency object uploaded by the customer.
     * 
     */
    public String object() {
        return this.object;
    }
    /**
     * @return The current state of AgentDependency.
     * 
     */
    public String state() {
        return this.state;
    }
    /**
     * @return The system tags associated with this resource, if any. The system tags are set by Oracle cloud infrastructure services. Each key is predefined and scoped to namespaces. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{orcl-cloud: {free-tier-retain: true}}`
     * 
     */
    public Map<String,String> systemTags() {
        return this.systemTags;
    }
    /**
     * @return The time when the AgentDependency was created. An RFC3339 formatted datetime string.
     * 
     */
    public String timeCreated() {
        return this.timeCreated;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetAgentDependencyResult defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String agentDependencyId;
        private String bucket;
        private String checksum;
        private String compartmentId;
        private Map<String,String> definedTags;
        private String dependencyName;
        private String dependencyVersion;
        private String description;
        private String displayName;
        private String eTag;
        private Map<String,String> freeformTags;
        private String id;
        private String lifecycleDetails;
        private String namespace;
        private String object;
        private String state;
        private Map<String,String> systemTags;
        private String timeCreated;
        public Builder() {}
        public Builder(GetAgentDependencyResult defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.agentDependencyId = defaults.agentDependencyId;
    	      this.bucket = defaults.bucket;
    	      this.checksum = defaults.checksum;
    	      this.compartmentId = defaults.compartmentId;
    	      this.definedTags = defaults.definedTags;
    	      this.dependencyName = defaults.dependencyName;
    	      this.dependencyVersion = defaults.dependencyVersion;
    	      this.description = defaults.description;
    	      this.displayName = defaults.displayName;
    	      this.eTag = defaults.eTag;
    	      this.freeformTags = defaults.freeformTags;
    	      this.id = defaults.id;
    	      this.lifecycleDetails = defaults.lifecycleDetails;
    	      this.namespace = defaults.namespace;
    	      this.object = defaults.object;
    	      this.state = defaults.state;
    	      this.systemTags = defaults.systemTags;
    	      this.timeCreated = defaults.timeCreated;
        }

        @CustomType.Setter
        public Builder agentDependencyId(String agentDependencyId) {
            if (agentDependencyId == null) {
              throw new MissingRequiredPropertyException("GetAgentDependencyResult", "agentDependencyId");
            }
            this.agentDependencyId = agentDependencyId;
            return this;
        }
        @CustomType.Setter
        public Builder bucket(String bucket) {
            if (bucket == null) {
              throw new MissingRequiredPropertyException("GetAgentDependencyResult", "bucket");
            }
            this.bucket = bucket;
            return this;
        }
        @CustomType.Setter
        public Builder checksum(String checksum) {
            if (checksum == null) {
              throw new MissingRequiredPropertyException("GetAgentDependencyResult", "checksum");
            }
            this.checksum = checksum;
            return this;
        }
        @CustomType.Setter
        public Builder compartmentId(String compartmentId) {
            if (compartmentId == null) {
              throw new MissingRequiredPropertyException("GetAgentDependencyResult", "compartmentId");
            }
            this.compartmentId = compartmentId;
            return this;
        }
        @CustomType.Setter
        public Builder definedTags(Map<String,String> definedTags) {
            if (definedTags == null) {
              throw new MissingRequiredPropertyException("GetAgentDependencyResult", "definedTags");
            }
            this.definedTags = definedTags;
            return this;
        }
        @CustomType.Setter
        public Builder dependencyName(String dependencyName) {
            if (dependencyName == null) {
              throw new MissingRequiredPropertyException("GetAgentDependencyResult", "dependencyName");
            }
            this.dependencyName = dependencyName;
            return this;
        }
        @CustomType.Setter
        public Builder dependencyVersion(String dependencyVersion) {
            if (dependencyVersion == null) {
              throw new MissingRequiredPropertyException("GetAgentDependencyResult", "dependencyVersion");
            }
            this.dependencyVersion = dependencyVersion;
            return this;
        }
        @CustomType.Setter
        public Builder description(String description) {
            if (description == null) {
              throw new MissingRequiredPropertyException("GetAgentDependencyResult", "description");
            }
            this.description = description;
            return this;
        }
        @CustomType.Setter
        public Builder displayName(String displayName) {
            if (displayName == null) {
              throw new MissingRequiredPropertyException("GetAgentDependencyResult", "displayName");
            }
            this.displayName = displayName;
            return this;
        }
        @CustomType.Setter
        public Builder eTag(String eTag) {
            if (eTag == null) {
              throw new MissingRequiredPropertyException("GetAgentDependencyResult", "eTag");
            }
            this.eTag = eTag;
            return this;
        }
        @CustomType.Setter
        public Builder freeformTags(Map<String,String> freeformTags) {
            if (freeformTags == null) {
              throw new MissingRequiredPropertyException("GetAgentDependencyResult", "freeformTags");
            }
            this.freeformTags = freeformTags;
            return this;
        }
        @CustomType.Setter
        public Builder id(String id) {
            if (id == null) {
              throw new MissingRequiredPropertyException("GetAgentDependencyResult", "id");
            }
            this.id = id;
            return this;
        }
        @CustomType.Setter
        public Builder lifecycleDetails(String lifecycleDetails) {
            if (lifecycleDetails == null) {
              throw new MissingRequiredPropertyException("GetAgentDependencyResult", "lifecycleDetails");
            }
            this.lifecycleDetails = lifecycleDetails;
            return this;
        }
        @CustomType.Setter
        public Builder namespace(String namespace) {
            if (namespace == null) {
              throw new MissingRequiredPropertyException("GetAgentDependencyResult", "namespace");
            }
            this.namespace = namespace;
            return this;
        }
        @CustomType.Setter
        public Builder object(String object) {
            if (object == null) {
              throw new MissingRequiredPropertyException("GetAgentDependencyResult", "object");
            }
            this.object = object;
            return this;
        }
        @CustomType.Setter
        public Builder state(String state) {
            if (state == null) {
              throw new MissingRequiredPropertyException("GetAgentDependencyResult", "state");
            }
            this.state = state;
            return this;
        }
        @CustomType.Setter
        public Builder systemTags(Map<String,String> systemTags) {
            if (systemTags == null) {
              throw new MissingRequiredPropertyException("GetAgentDependencyResult", "systemTags");
            }
            this.systemTags = systemTags;
            return this;
        }
        @CustomType.Setter
        public Builder timeCreated(String timeCreated) {
            if (timeCreated == null) {
              throw new MissingRequiredPropertyException("GetAgentDependencyResult", "timeCreated");
            }
            this.timeCreated = timeCreated;
            return this;
        }
        public GetAgentDependencyResult build() {
            final var _resultValue = new GetAgentDependencyResult();
            _resultValue.agentDependencyId = agentDependencyId;
            _resultValue.bucket = bucket;
            _resultValue.checksum = checksum;
            _resultValue.compartmentId = compartmentId;
            _resultValue.definedTags = definedTags;
            _resultValue.dependencyName = dependencyName;
            _resultValue.dependencyVersion = dependencyVersion;
            _resultValue.description = description;
            _resultValue.displayName = displayName;
            _resultValue.eTag = eTag;
            _resultValue.freeformTags = freeformTags;
            _resultValue.id = id;
            _resultValue.lifecycleDetails = lifecycleDetails;
            _resultValue.namespace = namespace;
            _resultValue.object = object;
            _resultValue.state = state;
            _resultValue.systemTags = systemTags;
            _resultValue.timeCreated = timeCreated;
            return _resultValue;
        }
    }
}
