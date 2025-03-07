// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Functions.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.Boolean;
import java.lang.String;
import java.util.Map;
import java.util.Objects;

@CustomType
public final class GetFusionEnvironmentServiceAttachmentsServiceAttachmentCollectionItem {
    /**
     * @return Compartment Identifier
     * 
     */
    private String compartmentId;
    /**
     * @return Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{&#34;foo-namespace.bar-key&#34;: &#34;value&#34;}`
     * 
     */
    private Map<String,String> definedTags;
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
     * @return unique FusionEnvironment identifier
     * 
     */
    private String fusionEnvironmentId;
    /**
     * @return Unique identifier that is immutable on creation
     * 
     */
    private String id;
    /**
     * @return Whether this service is provisioned due to the customer being subscribed to a specific SKU
     * 
     */
    private Boolean isSkuBased;
    /**
     * @return The ID of the service instance created that can be used to identify this on the service control plane
     * 
     */
    private String serviceInstanceId;
    /**
     * @return A filter that returns all resources that match the specified lifecycle state.
     * 
     */
    private String serviceInstanceType;
    /**
     * @return Public URL
     * 
     */
    private String serviceUrl;
    /**
     * @return A filter that returns all resources that match the specified lifecycle state.
     * 
     */
    private String state;
    /**
     * @return The time the the ServiceInstance was created. An RFC3339 formatted datetime string
     * 
     */
    private String timeCreated;
    /**
     * @return The time the ServiceInstance was updated. An RFC3339 formatted datetime string
     * 
     */
    private String timeUpdated;

    private GetFusionEnvironmentServiceAttachmentsServiceAttachmentCollectionItem() {}
    /**
     * @return Compartment Identifier
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
     * @return unique FusionEnvironment identifier
     * 
     */
    public String fusionEnvironmentId() {
        return this.fusionEnvironmentId;
    }
    /**
     * @return Unique identifier that is immutable on creation
     * 
     */
    public String id() {
        return this.id;
    }
    /**
     * @return Whether this service is provisioned due to the customer being subscribed to a specific SKU
     * 
     */
    public Boolean isSkuBased() {
        return this.isSkuBased;
    }
    /**
     * @return The ID of the service instance created that can be used to identify this on the service control plane
     * 
     */
    public String serviceInstanceId() {
        return this.serviceInstanceId;
    }
    /**
     * @return A filter that returns all resources that match the specified lifecycle state.
     * 
     */
    public String serviceInstanceType() {
        return this.serviceInstanceType;
    }
    /**
     * @return Public URL
     * 
     */
    public String serviceUrl() {
        return this.serviceUrl;
    }
    /**
     * @return A filter that returns all resources that match the specified lifecycle state.
     * 
     */
    public String state() {
        return this.state;
    }
    /**
     * @return The time the the ServiceInstance was created. An RFC3339 formatted datetime string
     * 
     */
    public String timeCreated() {
        return this.timeCreated;
    }
    /**
     * @return The time the ServiceInstance was updated. An RFC3339 formatted datetime string
     * 
     */
    public String timeUpdated() {
        return this.timeUpdated;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetFusionEnvironmentServiceAttachmentsServiceAttachmentCollectionItem defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String compartmentId;
        private Map<String,String> definedTags;
        private String displayName;
        private Map<String,String> freeformTags;
        private String fusionEnvironmentId;
        private String id;
        private Boolean isSkuBased;
        private String serviceInstanceId;
        private String serviceInstanceType;
        private String serviceUrl;
        private String state;
        private String timeCreated;
        private String timeUpdated;
        public Builder() {}
        public Builder(GetFusionEnvironmentServiceAttachmentsServiceAttachmentCollectionItem defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.compartmentId = defaults.compartmentId;
    	      this.definedTags = defaults.definedTags;
    	      this.displayName = defaults.displayName;
    	      this.freeformTags = defaults.freeformTags;
    	      this.fusionEnvironmentId = defaults.fusionEnvironmentId;
    	      this.id = defaults.id;
    	      this.isSkuBased = defaults.isSkuBased;
    	      this.serviceInstanceId = defaults.serviceInstanceId;
    	      this.serviceInstanceType = defaults.serviceInstanceType;
    	      this.serviceUrl = defaults.serviceUrl;
    	      this.state = defaults.state;
    	      this.timeCreated = defaults.timeCreated;
    	      this.timeUpdated = defaults.timeUpdated;
        }

        @CustomType.Setter
        public Builder compartmentId(String compartmentId) {
            if (compartmentId == null) {
              throw new MissingRequiredPropertyException("GetFusionEnvironmentServiceAttachmentsServiceAttachmentCollectionItem", "compartmentId");
            }
            this.compartmentId = compartmentId;
            return this;
        }
        @CustomType.Setter
        public Builder definedTags(Map<String,String> definedTags) {
            if (definedTags == null) {
              throw new MissingRequiredPropertyException("GetFusionEnvironmentServiceAttachmentsServiceAttachmentCollectionItem", "definedTags");
            }
            this.definedTags = definedTags;
            return this;
        }
        @CustomType.Setter
        public Builder displayName(String displayName) {
            if (displayName == null) {
              throw new MissingRequiredPropertyException("GetFusionEnvironmentServiceAttachmentsServiceAttachmentCollectionItem", "displayName");
            }
            this.displayName = displayName;
            return this;
        }
        @CustomType.Setter
        public Builder freeformTags(Map<String,String> freeformTags) {
            if (freeformTags == null) {
              throw new MissingRequiredPropertyException("GetFusionEnvironmentServiceAttachmentsServiceAttachmentCollectionItem", "freeformTags");
            }
            this.freeformTags = freeformTags;
            return this;
        }
        @CustomType.Setter
        public Builder fusionEnvironmentId(String fusionEnvironmentId) {
            if (fusionEnvironmentId == null) {
              throw new MissingRequiredPropertyException("GetFusionEnvironmentServiceAttachmentsServiceAttachmentCollectionItem", "fusionEnvironmentId");
            }
            this.fusionEnvironmentId = fusionEnvironmentId;
            return this;
        }
        @CustomType.Setter
        public Builder id(String id) {
            if (id == null) {
              throw new MissingRequiredPropertyException("GetFusionEnvironmentServiceAttachmentsServiceAttachmentCollectionItem", "id");
            }
            this.id = id;
            return this;
        }
        @CustomType.Setter
        public Builder isSkuBased(Boolean isSkuBased) {
            if (isSkuBased == null) {
              throw new MissingRequiredPropertyException("GetFusionEnvironmentServiceAttachmentsServiceAttachmentCollectionItem", "isSkuBased");
            }
            this.isSkuBased = isSkuBased;
            return this;
        }
        @CustomType.Setter
        public Builder serviceInstanceId(String serviceInstanceId) {
            if (serviceInstanceId == null) {
              throw new MissingRequiredPropertyException("GetFusionEnvironmentServiceAttachmentsServiceAttachmentCollectionItem", "serviceInstanceId");
            }
            this.serviceInstanceId = serviceInstanceId;
            return this;
        }
        @CustomType.Setter
        public Builder serviceInstanceType(String serviceInstanceType) {
            if (serviceInstanceType == null) {
              throw new MissingRequiredPropertyException("GetFusionEnvironmentServiceAttachmentsServiceAttachmentCollectionItem", "serviceInstanceType");
            }
            this.serviceInstanceType = serviceInstanceType;
            return this;
        }
        @CustomType.Setter
        public Builder serviceUrl(String serviceUrl) {
            if (serviceUrl == null) {
              throw new MissingRequiredPropertyException("GetFusionEnvironmentServiceAttachmentsServiceAttachmentCollectionItem", "serviceUrl");
            }
            this.serviceUrl = serviceUrl;
            return this;
        }
        @CustomType.Setter
        public Builder state(String state) {
            if (state == null) {
              throw new MissingRequiredPropertyException("GetFusionEnvironmentServiceAttachmentsServiceAttachmentCollectionItem", "state");
            }
            this.state = state;
            return this;
        }
        @CustomType.Setter
        public Builder timeCreated(String timeCreated) {
            if (timeCreated == null) {
              throw new MissingRequiredPropertyException("GetFusionEnvironmentServiceAttachmentsServiceAttachmentCollectionItem", "timeCreated");
            }
            this.timeCreated = timeCreated;
            return this;
        }
        @CustomType.Setter
        public Builder timeUpdated(String timeUpdated) {
            if (timeUpdated == null) {
              throw new MissingRequiredPropertyException("GetFusionEnvironmentServiceAttachmentsServiceAttachmentCollectionItem", "timeUpdated");
            }
            this.timeUpdated = timeUpdated;
            return this;
        }
        public GetFusionEnvironmentServiceAttachmentsServiceAttachmentCollectionItem build() {
            final var _resultValue = new GetFusionEnvironmentServiceAttachmentsServiceAttachmentCollectionItem();
            _resultValue.compartmentId = compartmentId;
            _resultValue.definedTags = definedTags;
            _resultValue.displayName = displayName;
            _resultValue.freeformTags = freeformTags;
            _resultValue.fusionEnvironmentId = fusionEnvironmentId;
            _resultValue.id = id;
            _resultValue.isSkuBased = isSkuBased;
            _resultValue.serviceInstanceId = serviceInstanceId;
            _resultValue.serviceInstanceType = serviceInstanceType;
            _resultValue.serviceUrl = serviceUrl;
            _resultValue.state = state;
            _resultValue.timeCreated = timeCreated;
            _resultValue.timeUpdated = timeUpdated;
            return _resultValue;
        }
    }
}
