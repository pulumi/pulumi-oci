// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Opsi.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.String;
import java.util.Map;
import java.util.Objects;

@CustomType
public final class GetEnterpriseManagerBridgeResult {
    /**
     * @return Compartment identifier of the Enterprise Manager bridge
     * 
     */
    private String compartmentId;
    /**
     * @return Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{&#34;foo-namespace.bar-key&#34;: &#34;value&#34;}`
     * 
     */
    private Map<String,String> definedTags;
    /**
     * @return Description of Enterprise Manager Bridge
     * 
     */
    private String description;
    /**
     * @return User-friedly name of Enterprise Manager Bridge that does not have to be unique.
     * 
     */
    private String displayName;
    private String enterpriseManagerBridgeId;
    /**
     * @return Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{&#34;bar-key&#34;: &#34;value&#34;}`
     * 
     */
    private Map<String,String> freeformTags;
    /**
     * @return Enterprise Manager bridge identifier
     * 
     */
    private String id;
    /**
     * @return A message describing the current state in more detail. For example, can be used to provide actionable information for a resource in Failed state.
     * 
     */
    private String lifecycleDetails;
    /**
     * @return Object Storage Bucket Name
     * 
     */
    private String objectStorageBucketName;
    /**
     * @return A message describing status of the object storage bucket of this resource. For example, it can be used to provide actionable information about the permission and content validity of the bucket.
     * 
     */
    private String objectStorageBucketStatusDetails;
    /**
     * @return Object Storage Namespace Name
     * 
     */
    private String objectStorageNamespaceName;
    /**
     * @return The current state of the Enterprise Manager bridge.
     * 
     */
    private String state;
    /**
     * @return System tags for this resource. Each key is predefined and scoped to a namespace. Example: `{&#34;orcl-cloud.free-tier-retained&#34;: &#34;true&#34;}`
     * 
     */
    private Map<String,String> systemTags;
    /**
     * @return The time the the Enterprise Manager bridge was first created. An RFC3339 formatted datetime string
     * 
     */
    private String timeCreated;
    /**
     * @return The time the Enterprise Manager bridge was updated. An RFC3339 formatted datetime string
     * 
     */
    private String timeUpdated;

    private GetEnterpriseManagerBridgeResult() {}
    /**
     * @return Compartment identifier of the Enterprise Manager bridge
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
     * @return Description of Enterprise Manager Bridge
     * 
     */
    public String description() {
        return this.description;
    }
    /**
     * @return User-friedly name of Enterprise Manager Bridge that does not have to be unique.
     * 
     */
    public String displayName() {
        return this.displayName;
    }
    public String enterpriseManagerBridgeId() {
        return this.enterpriseManagerBridgeId;
    }
    /**
     * @return Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{&#34;bar-key&#34;: &#34;value&#34;}`
     * 
     */
    public Map<String,String> freeformTags() {
        return this.freeformTags;
    }
    /**
     * @return Enterprise Manager bridge identifier
     * 
     */
    public String id() {
        return this.id;
    }
    /**
     * @return A message describing the current state in more detail. For example, can be used to provide actionable information for a resource in Failed state.
     * 
     */
    public String lifecycleDetails() {
        return this.lifecycleDetails;
    }
    /**
     * @return Object Storage Bucket Name
     * 
     */
    public String objectStorageBucketName() {
        return this.objectStorageBucketName;
    }
    /**
     * @return A message describing status of the object storage bucket of this resource. For example, it can be used to provide actionable information about the permission and content validity of the bucket.
     * 
     */
    public String objectStorageBucketStatusDetails() {
        return this.objectStorageBucketStatusDetails;
    }
    /**
     * @return Object Storage Namespace Name
     * 
     */
    public String objectStorageNamespaceName() {
        return this.objectStorageNamespaceName;
    }
    /**
     * @return The current state of the Enterprise Manager bridge.
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
     * @return The time the the Enterprise Manager bridge was first created. An RFC3339 formatted datetime string
     * 
     */
    public String timeCreated() {
        return this.timeCreated;
    }
    /**
     * @return The time the Enterprise Manager bridge was updated. An RFC3339 formatted datetime string
     * 
     */
    public String timeUpdated() {
        return this.timeUpdated;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetEnterpriseManagerBridgeResult defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String compartmentId;
        private Map<String,String> definedTags;
        private String description;
        private String displayName;
        private String enterpriseManagerBridgeId;
        private Map<String,String> freeformTags;
        private String id;
        private String lifecycleDetails;
        private String objectStorageBucketName;
        private String objectStorageBucketStatusDetails;
        private String objectStorageNamespaceName;
        private String state;
        private Map<String,String> systemTags;
        private String timeCreated;
        private String timeUpdated;
        public Builder() {}
        public Builder(GetEnterpriseManagerBridgeResult defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.compartmentId = defaults.compartmentId;
    	      this.definedTags = defaults.definedTags;
    	      this.description = defaults.description;
    	      this.displayName = defaults.displayName;
    	      this.enterpriseManagerBridgeId = defaults.enterpriseManagerBridgeId;
    	      this.freeformTags = defaults.freeformTags;
    	      this.id = defaults.id;
    	      this.lifecycleDetails = defaults.lifecycleDetails;
    	      this.objectStorageBucketName = defaults.objectStorageBucketName;
    	      this.objectStorageBucketStatusDetails = defaults.objectStorageBucketStatusDetails;
    	      this.objectStorageNamespaceName = defaults.objectStorageNamespaceName;
    	      this.state = defaults.state;
    	      this.systemTags = defaults.systemTags;
    	      this.timeCreated = defaults.timeCreated;
    	      this.timeUpdated = defaults.timeUpdated;
        }

        @CustomType.Setter
        public Builder compartmentId(String compartmentId) {
            if (compartmentId == null) {
              throw new MissingRequiredPropertyException("GetEnterpriseManagerBridgeResult", "compartmentId");
            }
            this.compartmentId = compartmentId;
            return this;
        }
        @CustomType.Setter
        public Builder definedTags(Map<String,String> definedTags) {
            if (definedTags == null) {
              throw new MissingRequiredPropertyException("GetEnterpriseManagerBridgeResult", "definedTags");
            }
            this.definedTags = definedTags;
            return this;
        }
        @CustomType.Setter
        public Builder description(String description) {
            if (description == null) {
              throw new MissingRequiredPropertyException("GetEnterpriseManagerBridgeResult", "description");
            }
            this.description = description;
            return this;
        }
        @CustomType.Setter
        public Builder displayName(String displayName) {
            if (displayName == null) {
              throw new MissingRequiredPropertyException("GetEnterpriseManagerBridgeResult", "displayName");
            }
            this.displayName = displayName;
            return this;
        }
        @CustomType.Setter
        public Builder enterpriseManagerBridgeId(String enterpriseManagerBridgeId) {
            if (enterpriseManagerBridgeId == null) {
              throw new MissingRequiredPropertyException("GetEnterpriseManagerBridgeResult", "enterpriseManagerBridgeId");
            }
            this.enterpriseManagerBridgeId = enterpriseManagerBridgeId;
            return this;
        }
        @CustomType.Setter
        public Builder freeformTags(Map<String,String> freeformTags) {
            if (freeformTags == null) {
              throw new MissingRequiredPropertyException("GetEnterpriseManagerBridgeResult", "freeformTags");
            }
            this.freeformTags = freeformTags;
            return this;
        }
        @CustomType.Setter
        public Builder id(String id) {
            if (id == null) {
              throw new MissingRequiredPropertyException("GetEnterpriseManagerBridgeResult", "id");
            }
            this.id = id;
            return this;
        }
        @CustomType.Setter
        public Builder lifecycleDetails(String lifecycleDetails) {
            if (lifecycleDetails == null) {
              throw new MissingRequiredPropertyException("GetEnterpriseManagerBridgeResult", "lifecycleDetails");
            }
            this.lifecycleDetails = lifecycleDetails;
            return this;
        }
        @CustomType.Setter
        public Builder objectStorageBucketName(String objectStorageBucketName) {
            if (objectStorageBucketName == null) {
              throw new MissingRequiredPropertyException("GetEnterpriseManagerBridgeResult", "objectStorageBucketName");
            }
            this.objectStorageBucketName = objectStorageBucketName;
            return this;
        }
        @CustomType.Setter
        public Builder objectStorageBucketStatusDetails(String objectStorageBucketStatusDetails) {
            if (objectStorageBucketStatusDetails == null) {
              throw new MissingRequiredPropertyException("GetEnterpriseManagerBridgeResult", "objectStorageBucketStatusDetails");
            }
            this.objectStorageBucketStatusDetails = objectStorageBucketStatusDetails;
            return this;
        }
        @CustomType.Setter
        public Builder objectStorageNamespaceName(String objectStorageNamespaceName) {
            if (objectStorageNamespaceName == null) {
              throw new MissingRequiredPropertyException("GetEnterpriseManagerBridgeResult", "objectStorageNamespaceName");
            }
            this.objectStorageNamespaceName = objectStorageNamespaceName;
            return this;
        }
        @CustomType.Setter
        public Builder state(String state) {
            if (state == null) {
              throw new MissingRequiredPropertyException("GetEnterpriseManagerBridgeResult", "state");
            }
            this.state = state;
            return this;
        }
        @CustomType.Setter
        public Builder systemTags(Map<String,String> systemTags) {
            if (systemTags == null) {
              throw new MissingRequiredPropertyException("GetEnterpriseManagerBridgeResult", "systemTags");
            }
            this.systemTags = systemTags;
            return this;
        }
        @CustomType.Setter
        public Builder timeCreated(String timeCreated) {
            if (timeCreated == null) {
              throw new MissingRequiredPropertyException("GetEnterpriseManagerBridgeResult", "timeCreated");
            }
            this.timeCreated = timeCreated;
            return this;
        }
        @CustomType.Setter
        public Builder timeUpdated(String timeUpdated) {
            if (timeUpdated == null) {
              throw new MissingRequiredPropertyException("GetEnterpriseManagerBridgeResult", "timeUpdated");
            }
            this.timeUpdated = timeUpdated;
            return this;
        }
        public GetEnterpriseManagerBridgeResult build() {
            final var _resultValue = new GetEnterpriseManagerBridgeResult();
            _resultValue.compartmentId = compartmentId;
            _resultValue.definedTags = definedTags;
            _resultValue.description = description;
            _resultValue.displayName = displayName;
            _resultValue.enterpriseManagerBridgeId = enterpriseManagerBridgeId;
            _resultValue.freeformTags = freeformTags;
            _resultValue.id = id;
            _resultValue.lifecycleDetails = lifecycleDetails;
            _resultValue.objectStorageBucketName = objectStorageBucketName;
            _resultValue.objectStorageBucketStatusDetails = objectStorageBucketStatusDetails;
            _resultValue.objectStorageNamespaceName = objectStorageNamespaceName;
            _resultValue.state = state;
            _resultValue.systemTags = systemTags;
            _resultValue.timeCreated = timeCreated;
            _resultValue.timeUpdated = timeUpdated;
            return _resultValue;
        }
    }
}
