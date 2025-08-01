// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.oci.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.String;
import java.util.Map;
import java.util.Objects;

@CustomType
public final class GetDbmulticloudOracleDbAzureBlobContainerResult {
    /**
     * @return Azure Storage Account Name.
     * 
     */
    private String azureStorageAccountName;
    /**
     * @return Azure Storage Container Name.
     * 
     */
    private String azureStorageContainerName;
    /**
     * @return The ID of the compartment that contains Oracle DB Azure Blob Container Resource.
     * 
     */
    private String compartmentId;
    /**
     * @return Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{&#34;Operations.CostCenter&#34;: &#34;42&#34;}`
     * 
     */
    private Map<String,String> definedTags;
    /**
     * @return Display name of Oracle DB Azure Blob Container.
     * 
     */
    private String displayName;
    /**
     * @return Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{&#34;Department&#34;: &#34;Finance&#34;}`
     * 
     */
    private Map<String,String> freeformTags;
    /**
     * @return The ID of the compartment that contains Oracle DB Azure Blob Container Resource.
     * 
     */
    private String id;
    /**
     * @return Description of the latest modification of the Oracle DB Azure Blob Container Resource.
     * 
     */
    private String lastModification;
    /**
     * @return Description of the current lifecycle state in more detail.
     * 
     */
    private String lifecycleStateDetails;
    private String oracleDbAzureBlobContainerId;
    /**
     * @return Private endpoint DNS Alias.
     * 
     */
    private String privateEndpointDnsAlias;
    /**
     * @return Private endpoint IP.
     * 
     */
    private String privateEndpointIpAddress;
    /**
     * @return The current lifecycle state of the Oracle DB Azure Blob Container Resource.
     * 
     */
    private String state;
    /**
     * @return System tags for this resource. Each key is predefined and scoped to a namespace.  Example: `{&#34;orcl-cloud.free-tier-retained&#34;: &#34;true&#34;}`
     * 
     */
    private Map<String,String> systemTags;
    /**
     * @return Time when the Oracle DB Azure Blob Container was created in [RFC 3339](https://tools.ietf.org/html/rfc3339) timestamp format, e.g. &#39;2020-05-22T21:10:29.600Z&#39;
     * 
     */
    private String timeCreated;
    /**
     * @return Time when the Oracle DB Azure Blob Container was last modified, expressed in [RFC 3339](https://tools.ietf.org/html/rfc3339) timestamp format, e.g. &#39;2020-05-22T21:10:29.600Z&#39;
     * 
     */
    private String timeUpdated;

    private GetDbmulticloudOracleDbAzureBlobContainerResult() {}
    /**
     * @return Azure Storage Account Name.
     * 
     */
    public String azureStorageAccountName() {
        return this.azureStorageAccountName;
    }
    /**
     * @return Azure Storage Container Name.
     * 
     */
    public String azureStorageContainerName() {
        return this.azureStorageContainerName;
    }
    /**
     * @return The ID of the compartment that contains Oracle DB Azure Blob Container Resource.
     * 
     */
    public String compartmentId() {
        return this.compartmentId;
    }
    /**
     * @return Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{&#34;Operations.CostCenter&#34;: &#34;42&#34;}`
     * 
     */
    public Map<String,String> definedTags() {
        return this.definedTags;
    }
    /**
     * @return Display name of Oracle DB Azure Blob Container.
     * 
     */
    public String displayName() {
        return this.displayName;
    }
    /**
     * @return Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{&#34;Department&#34;: &#34;Finance&#34;}`
     * 
     */
    public Map<String,String> freeformTags() {
        return this.freeformTags;
    }
    /**
     * @return The ID of the compartment that contains Oracle DB Azure Blob Container Resource.
     * 
     */
    public String id() {
        return this.id;
    }
    /**
     * @return Description of the latest modification of the Oracle DB Azure Blob Container Resource.
     * 
     */
    public String lastModification() {
        return this.lastModification;
    }
    /**
     * @return Description of the current lifecycle state in more detail.
     * 
     */
    public String lifecycleStateDetails() {
        return this.lifecycleStateDetails;
    }
    public String oracleDbAzureBlobContainerId() {
        return this.oracleDbAzureBlobContainerId;
    }
    /**
     * @return Private endpoint DNS Alias.
     * 
     */
    public String privateEndpointDnsAlias() {
        return this.privateEndpointDnsAlias;
    }
    /**
     * @return Private endpoint IP.
     * 
     */
    public String privateEndpointIpAddress() {
        return this.privateEndpointIpAddress;
    }
    /**
     * @return The current lifecycle state of the Oracle DB Azure Blob Container Resource.
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
     * @return Time when the Oracle DB Azure Blob Container was created in [RFC 3339](https://tools.ietf.org/html/rfc3339) timestamp format, e.g. &#39;2020-05-22T21:10:29.600Z&#39;
     * 
     */
    public String timeCreated() {
        return this.timeCreated;
    }
    /**
     * @return Time when the Oracle DB Azure Blob Container was last modified, expressed in [RFC 3339](https://tools.ietf.org/html/rfc3339) timestamp format, e.g. &#39;2020-05-22T21:10:29.600Z&#39;
     * 
     */
    public String timeUpdated() {
        return this.timeUpdated;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetDbmulticloudOracleDbAzureBlobContainerResult defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String azureStorageAccountName;
        private String azureStorageContainerName;
        private String compartmentId;
        private Map<String,String> definedTags;
        private String displayName;
        private Map<String,String> freeformTags;
        private String id;
        private String lastModification;
        private String lifecycleStateDetails;
        private String oracleDbAzureBlobContainerId;
        private String privateEndpointDnsAlias;
        private String privateEndpointIpAddress;
        private String state;
        private Map<String,String> systemTags;
        private String timeCreated;
        private String timeUpdated;
        public Builder() {}
        public Builder(GetDbmulticloudOracleDbAzureBlobContainerResult defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.azureStorageAccountName = defaults.azureStorageAccountName;
    	      this.azureStorageContainerName = defaults.azureStorageContainerName;
    	      this.compartmentId = defaults.compartmentId;
    	      this.definedTags = defaults.definedTags;
    	      this.displayName = defaults.displayName;
    	      this.freeformTags = defaults.freeformTags;
    	      this.id = defaults.id;
    	      this.lastModification = defaults.lastModification;
    	      this.lifecycleStateDetails = defaults.lifecycleStateDetails;
    	      this.oracleDbAzureBlobContainerId = defaults.oracleDbAzureBlobContainerId;
    	      this.privateEndpointDnsAlias = defaults.privateEndpointDnsAlias;
    	      this.privateEndpointIpAddress = defaults.privateEndpointIpAddress;
    	      this.state = defaults.state;
    	      this.systemTags = defaults.systemTags;
    	      this.timeCreated = defaults.timeCreated;
    	      this.timeUpdated = defaults.timeUpdated;
        }

        @CustomType.Setter
        public Builder azureStorageAccountName(String azureStorageAccountName) {
            if (azureStorageAccountName == null) {
              throw new MissingRequiredPropertyException("GetDbmulticloudOracleDbAzureBlobContainerResult", "azureStorageAccountName");
            }
            this.azureStorageAccountName = azureStorageAccountName;
            return this;
        }
        @CustomType.Setter
        public Builder azureStorageContainerName(String azureStorageContainerName) {
            if (azureStorageContainerName == null) {
              throw new MissingRequiredPropertyException("GetDbmulticloudOracleDbAzureBlobContainerResult", "azureStorageContainerName");
            }
            this.azureStorageContainerName = azureStorageContainerName;
            return this;
        }
        @CustomType.Setter
        public Builder compartmentId(String compartmentId) {
            if (compartmentId == null) {
              throw new MissingRequiredPropertyException("GetDbmulticloudOracleDbAzureBlobContainerResult", "compartmentId");
            }
            this.compartmentId = compartmentId;
            return this;
        }
        @CustomType.Setter
        public Builder definedTags(Map<String,String> definedTags) {
            if (definedTags == null) {
              throw new MissingRequiredPropertyException("GetDbmulticloudOracleDbAzureBlobContainerResult", "definedTags");
            }
            this.definedTags = definedTags;
            return this;
        }
        @CustomType.Setter
        public Builder displayName(String displayName) {
            if (displayName == null) {
              throw new MissingRequiredPropertyException("GetDbmulticloudOracleDbAzureBlobContainerResult", "displayName");
            }
            this.displayName = displayName;
            return this;
        }
        @CustomType.Setter
        public Builder freeformTags(Map<String,String> freeformTags) {
            if (freeformTags == null) {
              throw new MissingRequiredPropertyException("GetDbmulticloudOracleDbAzureBlobContainerResult", "freeformTags");
            }
            this.freeformTags = freeformTags;
            return this;
        }
        @CustomType.Setter
        public Builder id(String id) {
            if (id == null) {
              throw new MissingRequiredPropertyException("GetDbmulticloudOracleDbAzureBlobContainerResult", "id");
            }
            this.id = id;
            return this;
        }
        @CustomType.Setter
        public Builder lastModification(String lastModification) {
            if (lastModification == null) {
              throw new MissingRequiredPropertyException("GetDbmulticloudOracleDbAzureBlobContainerResult", "lastModification");
            }
            this.lastModification = lastModification;
            return this;
        }
        @CustomType.Setter
        public Builder lifecycleStateDetails(String lifecycleStateDetails) {
            if (lifecycleStateDetails == null) {
              throw new MissingRequiredPropertyException("GetDbmulticloudOracleDbAzureBlobContainerResult", "lifecycleStateDetails");
            }
            this.lifecycleStateDetails = lifecycleStateDetails;
            return this;
        }
        @CustomType.Setter
        public Builder oracleDbAzureBlobContainerId(String oracleDbAzureBlobContainerId) {
            if (oracleDbAzureBlobContainerId == null) {
              throw new MissingRequiredPropertyException("GetDbmulticloudOracleDbAzureBlobContainerResult", "oracleDbAzureBlobContainerId");
            }
            this.oracleDbAzureBlobContainerId = oracleDbAzureBlobContainerId;
            return this;
        }
        @CustomType.Setter
        public Builder privateEndpointDnsAlias(String privateEndpointDnsAlias) {
            if (privateEndpointDnsAlias == null) {
              throw new MissingRequiredPropertyException("GetDbmulticloudOracleDbAzureBlobContainerResult", "privateEndpointDnsAlias");
            }
            this.privateEndpointDnsAlias = privateEndpointDnsAlias;
            return this;
        }
        @CustomType.Setter
        public Builder privateEndpointIpAddress(String privateEndpointIpAddress) {
            if (privateEndpointIpAddress == null) {
              throw new MissingRequiredPropertyException("GetDbmulticloudOracleDbAzureBlobContainerResult", "privateEndpointIpAddress");
            }
            this.privateEndpointIpAddress = privateEndpointIpAddress;
            return this;
        }
        @CustomType.Setter
        public Builder state(String state) {
            if (state == null) {
              throw new MissingRequiredPropertyException("GetDbmulticloudOracleDbAzureBlobContainerResult", "state");
            }
            this.state = state;
            return this;
        }
        @CustomType.Setter
        public Builder systemTags(Map<String,String> systemTags) {
            if (systemTags == null) {
              throw new MissingRequiredPropertyException("GetDbmulticloudOracleDbAzureBlobContainerResult", "systemTags");
            }
            this.systemTags = systemTags;
            return this;
        }
        @CustomType.Setter
        public Builder timeCreated(String timeCreated) {
            if (timeCreated == null) {
              throw new MissingRequiredPropertyException("GetDbmulticloudOracleDbAzureBlobContainerResult", "timeCreated");
            }
            this.timeCreated = timeCreated;
            return this;
        }
        @CustomType.Setter
        public Builder timeUpdated(String timeUpdated) {
            if (timeUpdated == null) {
              throw new MissingRequiredPropertyException("GetDbmulticloudOracleDbAzureBlobContainerResult", "timeUpdated");
            }
            this.timeUpdated = timeUpdated;
            return this;
        }
        public GetDbmulticloudOracleDbAzureBlobContainerResult build() {
            final var _resultValue = new GetDbmulticloudOracleDbAzureBlobContainerResult();
            _resultValue.azureStorageAccountName = azureStorageAccountName;
            _resultValue.azureStorageContainerName = azureStorageContainerName;
            _resultValue.compartmentId = compartmentId;
            _resultValue.definedTags = definedTags;
            _resultValue.displayName = displayName;
            _resultValue.freeformTags = freeformTags;
            _resultValue.id = id;
            _resultValue.lastModification = lastModification;
            _resultValue.lifecycleStateDetails = lifecycleStateDetails;
            _resultValue.oracleDbAzureBlobContainerId = oracleDbAzureBlobContainerId;
            _resultValue.privateEndpointDnsAlias = privateEndpointDnsAlias;
            _resultValue.privateEndpointIpAddress = privateEndpointIpAddress;
            _resultValue.state = state;
            _resultValue.systemTags = systemTags;
            _resultValue.timeCreated = timeCreated;
            _resultValue.timeUpdated = timeUpdated;
            return _resultValue;
        }
    }
}
