// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.oci.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.String;
import java.util.List;
import java.util.Map;
import java.util.Objects;

@CustomType
public final class GetApiaccesscontrolApiMetadataResult {
    private String apiMetadataId;
    /**
     * @return The name of the api to execute the api request.
     * 
     */
    private String apiName;
    /**
     * @return Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{&#34;Operations.CostCenter&#34;: &#34;42&#34;}`
     * 
     */
    private Map<String,String> definedTags;
    /**
     * @return The operation Name of the api. The name must be unique.
     * 
     */
    private String displayName;
    /**
     * @return ResourceType to which the apiMetadata belongs to.
     * 
     */
    private String entityType;
    /**
     * @return List of the fields that is use while calling post or put for the data.
     * 
     */
    private List<String> fields;
    /**
     * @return Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{&#34;Department&#34;: &#34;Finance&#34;}`
     * 
     */
    private Map<String,String> freeformTags;
    /**
     * @return The provider-assigned unique ID for this managed resource.
     * 
     */
    private String id;
    /**
     * @return A message that describes the current state of the ApiMetadata in more detail. For example, can be used to provide actionable information for a resource in the Failed state.
     * 
     */
    private String lifecycleDetails;
    /**
     * @return rest path of the api.
     * 
     */
    private String path;
    /**
     * @return The service Name to which the api belongs to.
     * 
     */
    private String serviceName;
    /**
     * @return The current state of the ApiMetadata.
     * 
     */
    private String state;
    /**
     * @return System tags for this resource. Each key is predefined and scoped to a namespace.  Example: `{&#34;orcl-cloud.free-tier-retained&#34;: &#34;true&#34;}`
     * 
     */
    private Map<String,String> systemTags;
    /**
     * @return The date and time the PrivilegedApiControl was created, in the format defined by [RFC 3339](https://tools.ietf.org/html/rfc3339).  Example: `2016-08-25T21:10:29.600Z`
     * 
     */
    private String timeCreated;
    /**
     * @return The date and time the PrivilegedApiControl was marked for delete, in the format defined by [RFC 3339](https://tools.ietf.org/html/rfc3339).  Example: `2016-08-25T21:10:29.600Z`
     * 
     */
    private String timeDeleted;
    /**
     * @return The date and time the PrivilegedApiControl was updated, in the format defined by [RFC 3339](https://tools.ietf.org/html/rfc3339).  Example: `2016-08-25T21:10:29.600Z`
     * 
     */
    private String timeUpdated;

    private GetApiaccesscontrolApiMetadataResult() {}
    public String apiMetadataId() {
        return this.apiMetadataId;
    }
    /**
     * @return The name of the api to execute the api request.
     * 
     */
    public String apiName() {
        return this.apiName;
    }
    /**
     * @return Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{&#34;Operations.CostCenter&#34;: &#34;42&#34;}`
     * 
     */
    public Map<String,String> definedTags() {
        return this.definedTags;
    }
    /**
     * @return The operation Name of the api. The name must be unique.
     * 
     */
    public String displayName() {
        return this.displayName;
    }
    /**
     * @return ResourceType to which the apiMetadata belongs to.
     * 
     */
    public String entityType() {
        return this.entityType;
    }
    /**
     * @return List of the fields that is use while calling post or put for the data.
     * 
     */
    public List<String> fields() {
        return this.fields;
    }
    /**
     * @return Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{&#34;Department&#34;: &#34;Finance&#34;}`
     * 
     */
    public Map<String,String> freeformTags() {
        return this.freeformTags;
    }
    /**
     * @return The provider-assigned unique ID for this managed resource.
     * 
     */
    public String id() {
        return this.id;
    }
    /**
     * @return A message that describes the current state of the ApiMetadata in more detail. For example, can be used to provide actionable information for a resource in the Failed state.
     * 
     */
    public String lifecycleDetails() {
        return this.lifecycleDetails;
    }
    /**
     * @return rest path of the api.
     * 
     */
    public String path() {
        return this.path;
    }
    /**
     * @return The service Name to which the api belongs to.
     * 
     */
    public String serviceName() {
        return this.serviceName;
    }
    /**
     * @return The current state of the ApiMetadata.
     * 
     */
    public String state() {
        return this.state;
    }
    /**
     * @return System tags for this resource. Each key is predefined and scoped to a namespace.  Example: `{&#34;orcl-cloud.free-tier-retained&#34;: &#34;true&#34;}`
     * 
     */
    public Map<String,String> systemTags() {
        return this.systemTags;
    }
    /**
     * @return The date and time the PrivilegedApiControl was created, in the format defined by [RFC 3339](https://tools.ietf.org/html/rfc3339).  Example: `2016-08-25T21:10:29.600Z`
     * 
     */
    public String timeCreated() {
        return this.timeCreated;
    }
    /**
     * @return The date and time the PrivilegedApiControl was marked for delete, in the format defined by [RFC 3339](https://tools.ietf.org/html/rfc3339).  Example: `2016-08-25T21:10:29.600Z`
     * 
     */
    public String timeDeleted() {
        return this.timeDeleted;
    }
    /**
     * @return The date and time the PrivilegedApiControl was updated, in the format defined by [RFC 3339](https://tools.ietf.org/html/rfc3339).  Example: `2016-08-25T21:10:29.600Z`
     * 
     */
    public String timeUpdated() {
        return this.timeUpdated;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetApiaccesscontrolApiMetadataResult defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String apiMetadataId;
        private String apiName;
        private Map<String,String> definedTags;
        private String displayName;
        private String entityType;
        private List<String> fields;
        private Map<String,String> freeformTags;
        private String id;
        private String lifecycleDetails;
        private String path;
        private String serviceName;
        private String state;
        private Map<String,String> systemTags;
        private String timeCreated;
        private String timeDeleted;
        private String timeUpdated;
        public Builder() {}
        public Builder(GetApiaccesscontrolApiMetadataResult defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.apiMetadataId = defaults.apiMetadataId;
    	      this.apiName = defaults.apiName;
    	      this.definedTags = defaults.definedTags;
    	      this.displayName = defaults.displayName;
    	      this.entityType = defaults.entityType;
    	      this.fields = defaults.fields;
    	      this.freeformTags = defaults.freeformTags;
    	      this.id = defaults.id;
    	      this.lifecycleDetails = defaults.lifecycleDetails;
    	      this.path = defaults.path;
    	      this.serviceName = defaults.serviceName;
    	      this.state = defaults.state;
    	      this.systemTags = defaults.systemTags;
    	      this.timeCreated = defaults.timeCreated;
    	      this.timeDeleted = defaults.timeDeleted;
    	      this.timeUpdated = defaults.timeUpdated;
        }

        @CustomType.Setter
        public Builder apiMetadataId(String apiMetadataId) {
            if (apiMetadataId == null) {
              throw new MissingRequiredPropertyException("GetApiaccesscontrolApiMetadataResult", "apiMetadataId");
            }
            this.apiMetadataId = apiMetadataId;
            return this;
        }
        @CustomType.Setter
        public Builder apiName(String apiName) {
            if (apiName == null) {
              throw new MissingRequiredPropertyException("GetApiaccesscontrolApiMetadataResult", "apiName");
            }
            this.apiName = apiName;
            return this;
        }
        @CustomType.Setter
        public Builder definedTags(Map<String,String> definedTags) {
            if (definedTags == null) {
              throw new MissingRequiredPropertyException("GetApiaccesscontrolApiMetadataResult", "definedTags");
            }
            this.definedTags = definedTags;
            return this;
        }
        @CustomType.Setter
        public Builder displayName(String displayName) {
            if (displayName == null) {
              throw new MissingRequiredPropertyException("GetApiaccesscontrolApiMetadataResult", "displayName");
            }
            this.displayName = displayName;
            return this;
        }
        @CustomType.Setter
        public Builder entityType(String entityType) {
            if (entityType == null) {
              throw new MissingRequiredPropertyException("GetApiaccesscontrolApiMetadataResult", "entityType");
            }
            this.entityType = entityType;
            return this;
        }
        @CustomType.Setter
        public Builder fields(List<String> fields) {
            if (fields == null) {
              throw new MissingRequiredPropertyException("GetApiaccesscontrolApiMetadataResult", "fields");
            }
            this.fields = fields;
            return this;
        }
        public Builder fields(String... fields) {
            return fields(List.of(fields));
        }
        @CustomType.Setter
        public Builder freeformTags(Map<String,String> freeformTags) {
            if (freeformTags == null) {
              throw new MissingRequiredPropertyException("GetApiaccesscontrolApiMetadataResult", "freeformTags");
            }
            this.freeformTags = freeformTags;
            return this;
        }
        @CustomType.Setter
        public Builder id(String id) {
            if (id == null) {
              throw new MissingRequiredPropertyException("GetApiaccesscontrolApiMetadataResult", "id");
            }
            this.id = id;
            return this;
        }
        @CustomType.Setter
        public Builder lifecycleDetails(String lifecycleDetails) {
            if (lifecycleDetails == null) {
              throw new MissingRequiredPropertyException("GetApiaccesscontrolApiMetadataResult", "lifecycleDetails");
            }
            this.lifecycleDetails = lifecycleDetails;
            return this;
        }
        @CustomType.Setter
        public Builder path(String path) {
            if (path == null) {
              throw new MissingRequiredPropertyException("GetApiaccesscontrolApiMetadataResult", "path");
            }
            this.path = path;
            return this;
        }
        @CustomType.Setter
        public Builder serviceName(String serviceName) {
            if (serviceName == null) {
              throw new MissingRequiredPropertyException("GetApiaccesscontrolApiMetadataResult", "serviceName");
            }
            this.serviceName = serviceName;
            return this;
        }
        @CustomType.Setter
        public Builder state(String state) {
            if (state == null) {
              throw new MissingRequiredPropertyException("GetApiaccesscontrolApiMetadataResult", "state");
            }
            this.state = state;
            return this;
        }
        @CustomType.Setter
        public Builder systemTags(Map<String,String> systemTags) {
            if (systemTags == null) {
              throw new MissingRequiredPropertyException("GetApiaccesscontrolApiMetadataResult", "systemTags");
            }
            this.systemTags = systemTags;
            return this;
        }
        @CustomType.Setter
        public Builder timeCreated(String timeCreated) {
            if (timeCreated == null) {
              throw new MissingRequiredPropertyException("GetApiaccesscontrolApiMetadataResult", "timeCreated");
            }
            this.timeCreated = timeCreated;
            return this;
        }
        @CustomType.Setter
        public Builder timeDeleted(String timeDeleted) {
            if (timeDeleted == null) {
              throw new MissingRequiredPropertyException("GetApiaccesscontrolApiMetadataResult", "timeDeleted");
            }
            this.timeDeleted = timeDeleted;
            return this;
        }
        @CustomType.Setter
        public Builder timeUpdated(String timeUpdated) {
            if (timeUpdated == null) {
              throw new MissingRequiredPropertyException("GetApiaccesscontrolApiMetadataResult", "timeUpdated");
            }
            this.timeUpdated = timeUpdated;
            return this;
        }
        public GetApiaccesscontrolApiMetadataResult build() {
            final var _resultValue = new GetApiaccesscontrolApiMetadataResult();
            _resultValue.apiMetadataId = apiMetadataId;
            _resultValue.apiName = apiName;
            _resultValue.definedTags = definedTags;
            _resultValue.displayName = displayName;
            _resultValue.entityType = entityType;
            _resultValue.fields = fields;
            _resultValue.freeformTags = freeformTags;
            _resultValue.id = id;
            _resultValue.lifecycleDetails = lifecycleDetails;
            _resultValue.path = path;
            _resultValue.serviceName = serviceName;
            _resultValue.state = state;
            _resultValue.systemTags = systemTags;
            _resultValue.timeCreated = timeCreated;
            _resultValue.timeDeleted = timeDeleted;
            _resultValue.timeUpdated = timeUpdated;
            return _resultValue;
        }
    }
}
