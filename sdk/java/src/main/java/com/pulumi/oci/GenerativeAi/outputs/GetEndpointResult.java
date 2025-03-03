// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.GenerativeAi.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.GenerativeAi.outputs.GetEndpointContentModerationConfig;
import java.lang.String;
import java.util.List;
import java.util.Map;
import java.util.Objects;

@CustomType
public final class GetEndpointResult {
    private String compartmentId;
    private List<GetEndpointContentModerationConfig> contentModerationConfigs;
    private String dedicatedAiClusterId;
    private Map<String,String> definedTags;
    /**
     * @return An optional description of the endpoint.
     * 
     */
    private String description;
    /**
     * @return A user-friendly name. Does not have to be unique, and it&#39;s changeable.
     * 
     */
    private String displayName;
    private String endpointId;
    private Map<String,String> freeformTags;
    private String id;
    private String lifecycleDetails;
    /**
     * @return The OCID of the model that&#39;s used to create this endpoint.
     * 
     */
    private String modelId;
    /**
     * @return The current state of the endpoint.
     * 
     */
    private String state;
    private Map<String,String> systemTags;
    private String timeCreated;
    /**
     * @return The date and time that the endpoint was updated in the format of an RFC3339 datetime string.
     * 
     */
    private String timeUpdated;

    private GetEndpointResult() {}
    public String compartmentId() {
        return this.compartmentId;
    }
    public List<GetEndpointContentModerationConfig> contentModerationConfigs() {
        return this.contentModerationConfigs;
    }
    public String dedicatedAiClusterId() {
        return this.dedicatedAiClusterId;
    }
    public Map<String,String> definedTags() {
        return this.definedTags;
    }
    /**
     * @return An optional description of the endpoint.
     * 
     */
    public String description() {
        return this.description;
    }
    /**
     * @return A user-friendly name. Does not have to be unique, and it&#39;s changeable.
     * 
     */
    public String displayName() {
        return this.displayName;
    }
    public String endpointId() {
        return this.endpointId;
    }
    public Map<String,String> freeformTags() {
        return this.freeformTags;
    }
    public String id() {
        return this.id;
    }
    public String lifecycleDetails() {
        return this.lifecycleDetails;
    }
    /**
     * @return The OCID of the model that&#39;s used to create this endpoint.
     * 
     */
    public String modelId() {
        return this.modelId;
    }
    /**
     * @return The current state of the endpoint.
     * 
     */
    public String state() {
        return this.state;
    }
    public Map<String,String> systemTags() {
        return this.systemTags;
    }
    public String timeCreated() {
        return this.timeCreated;
    }
    /**
     * @return The date and time that the endpoint was updated in the format of an RFC3339 datetime string.
     * 
     */
    public String timeUpdated() {
        return this.timeUpdated;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetEndpointResult defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String compartmentId;
        private List<GetEndpointContentModerationConfig> contentModerationConfigs;
        private String dedicatedAiClusterId;
        private Map<String,String> definedTags;
        private String description;
        private String displayName;
        private String endpointId;
        private Map<String,String> freeformTags;
        private String id;
        private String lifecycleDetails;
        private String modelId;
        private String state;
        private Map<String,String> systemTags;
        private String timeCreated;
        private String timeUpdated;
        public Builder() {}
        public Builder(GetEndpointResult defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.compartmentId = defaults.compartmentId;
    	      this.contentModerationConfigs = defaults.contentModerationConfigs;
    	      this.dedicatedAiClusterId = defaults.dedicatedAiClusterId;
    	      this.definedTags = defaults.definedTags;
    	      this.description = defaults.description;
    	      this.displayName = defaults.displayName;
    	      this.endpointId = defaults.endpointId;
    	      this.freeformTags = defaults.freeformTags;
    	      this.id = defaults.id;
    	      this.lifecycleDetails = defaults.lifecycleDetails;
    	      this.modelId = defaults.modelId;
    	      this.state = defaults.state;
    	      this.systemTags = defaults.systemTags;
    	      this.timeCreated = defaults.timeCreated;
    	      this.timeUpdated = defaults.timeUpdated;
        }

        @CustomType.Setter
        public Builder compartmentId(String compartmentId) {
            if (compartmentId == null) {
              throw new MissingRequiredPropertyException("GetEndpointResult", "compartmentId");
            }
            this.compartmentId = compartmentId;
            return this;
        }
        @CustomType.Setter
        public Builder contentModerationConfigs(List<GetEndpointContentModerationConfig> contentModerationConfigs) {
            if (contentModerationConfigs == null) {
              throw new MissingRequiredPropertyException("GetEndpointResult", "contentModerationConfigs");
            }
            this.contentModerationConfigs = contentModerationConfigs;
            return this;
        }
        public Builder contentModerationConfigs(GetEndpointContentModerationConfig... contentModerationConfigs) {
            return contentModerationConfigs(List.of(contentModerationConfigs));
        }
        @CustomType.Setter
        public Builder dedicatedAiClusterId(String dedicatedAiClusterId) {
            if (dedicatedAiClusterId == null) {
              throw new MissingRequiredPropertyException("GetEndpointResult", "dedicatedAiClusterId");
            }
            this.dedicatedAiClusterId = dedicatedAiClusterId;
            return this;
        }
        @CustomType.Setter
        public Builder definedTags(Map<String,String> definedTags) {
            if (definedTags == null) {
              throw new MissingRequiredPropertyException("GetEndpointResult", "definedTags");
            }
            this.definedTags = definedTags;
            return this;
        }
        @CustomType.Setter
        public Builder description(String description) {
            if (description == null) {
              throw new MissingRequiredPropertyException("GetEndpointResult", "description");
            }
            this.description = description;
            return this;
        }
        @CustomType.Setter
        public Builder displayName(String displayName) {
            if (displayName == null) {
              throw new MissingRequiredPropertyException("GetEndpointResult", "displayName");
            }
            this.displayName = displayName;
            return this;
        }
        @CustomType.Setter
        public Builder endpointId(String endpointId) {
            if (endpointId == null) {
              throw new MissingRequiredPropertyException("GetEndpointResult", "endpointId");
            }
            this.endpointId = endpointId;
            return this;
        }
        @CustomType.Setter
        public Builder freeformTags(Map<String,String> freeformTags) {
            if (freeformTags == null) {
              throw new MissingRequiredPropertyException("GetEndpointResult", "freeformTags");
            }
            this.freeformTags = freeformTags;
            return this;
        }
        @CustomType.Setter
        public Builder id(String id) {
            if (id == null) {
              throw new MissingRequiredPropertyException("GetEndpointResult", "id");
            }
            this.id = id;
            return this;
        }
        @CustomType.Setter
        public Builder lifecycleDetails(String lifecycleDetails) {
            if (lifecycleDetails == null) {
              throw new MissingRequiredPropertyException("GetEndpointResult", "lifecycleDetails");
            }
            this.lifecycleDetails = lifecycleDetails;
            return this;
        }
        @CustomType.Setter
        public Builder modelId(String modelId) {
            if (modelId == null) {
              throw new MissingRequiredPropertyException("GetEndpointResult", "modelId");
            }
            this.modelId = modelId;
            return this;
        }
        @CustomType.Setter
        public Builder state(String state) {
            if (state == null) {
              throw new MissingRequiredPropertyException("GetEndpointResult", "state");
            }
            this.state = state;
            return this;
        }
        @CustomType.Setter
        public Builder systemTags(Map<String,String> systemTags) {
            if (systemTags == null) {
              throw new MissingRequiredPropertyException("GetEndpointResult", "systemTags");
            }
            this.systemTags = systemTags;
            return this;
        }
        @CustomType.Setter
        public Builder timeCreated(String timeCreated) {
            if (timeCreated == null) {
              throw new MissingRequiredPropertyException("GetEndpointResult", "timeCreated");
            }
            this.timeCreated = timeCreated;
            return this;
        }
        @CustomType.Setter
        public Builder timeUpdated(String timeUpdated) {
            if (timeUpdated == null) {
              throw new MissingRequiredPropertyException("GetEndpointResult", "timeUpdated");
            }
            this.timeUpdated = timeUpdated;
            return this;
        }
        public GetEndpointResult build() {
            final var _resultValue = new GetEndpointResult();
            _resultValue.compartmentId = compartmentId;
            _resultValue.contentModerationConfigs = contentModerationConfigs;
            _resultValue.dedicatedAiClusterId = dedicatedAiClusterId;
            _resultValue.definedTags = definedTags;
            _resultValue.description = description;
            _resultValue.displayName = displayName;
            _resultValue.endpointId = endpointId;
            _resultValue.freeformTags = freeformTags;
            _resultValue.id = id;
            _resultValue.lifecycleDetails = lifecycleDetails;
            _resultValue.modelId = modelId;
            _resultValue.state = state;
            _resultValue.systemTags = systemTags;
            _resultValue.timeCreated = timeCreated;
            _resultValue.timeUpdated = timeUpdated;
            return _resultValue;
        }
    }
}
