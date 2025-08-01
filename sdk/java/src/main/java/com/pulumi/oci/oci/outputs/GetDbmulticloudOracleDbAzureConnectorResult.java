// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.oci.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.oci.outputs.GetDbmulticloudOracleDbAzureConnectorArcAgentNode;
import java.lang.String;
import java.util.List;
import java.util.Objects;

@CustomType
public final class GetDbmulticloudOracleDbAzureConnectorResult {
    /**
     * @return Azure bearer access token. If bearer access token is provided then Service Principal detail is not required.
     * 
     */
    private String accessToken;
    /**
     * @return List of All VMs where Arc Agent is Install under VMCluster.
     * 
     */
    private List<GetDbmulticloudOracleDbAzureConnectorArcAgentNode> arcAgentNodes;
    /**
     * @return Azure Identity Mechanism.
     * 
     */
    private String azureIdentityMechanism;
    /**
     * @return Azure Resource Group Name.
     * 
     */
    private String azureResourceGroup;
    /**
     * @return Azure Subscription ID.
     * 
     */
    private String azureSubscriptionId;
    /**
     * @return Azure Tenant ID.
     * 
     */
    private String azureTenantId;
    /**
     * @return The ID of the compartment that contains Oracle DB Azure Connector resource.
     * 
     */
    private String compartmentId;
    /**
     * @return The ID of the DB Cluster Resource where this Azure Arc Agent identity to configure.
     * 
     */
    private String dbClusterResourceId;
    /**
     * @return Oracle DB Azure Connector resource name.
     * 
     */
    private String displayName;
    /**
     * @return The ID of the Oracle DB Azure Connector resource.
     * 
     */
    private String id;
    /**
     * @return Description of the latest modification of the Oracle DB Azure Connector Resource.
     * 
     */
    private String lastModification;
    /**
     * @return Description of the current lifecycle state in more detail.
     * 
     */
    private String lifecycleStateDetails;
    private String oracleDbAzureConnectorId;
    /**
     * @return The current lifecycle state of the Azure Arc Agent Resource.
     * 
     */
    private String state;
    /**
     * @return Time when the Oracle DB Azure Connector Resource was created expressed in [RFC 3339](https://tools.ietf.org/html/rfc3339) timestamp format, e.g. &#39;2020-05-22T21:10:29.600Z&#39;
     * 
     */
    private String timeCreated;
    /**
     * @return Time when the Oracle DB Azure Connector Resource was last modified expressed in [RFC 3339](https://tools.ietf.org/html/rfc3339) timestamp format, e.g. &#39;2020-05-22T21:10:29.600Z&#39;
     * 
     */
    private String timeUpdated;

    private GetDbmulticloudOracleDbAzureConnectorResult() {}
    /**
     * @return Azure bearer access token. If bearer access token is provided then Service Principal detail is not required.
     * 
     */
    public String accessToken() {
        return this.accessToken;
    }
    /**
     * @return List of All VMs where Arc Agent is Install under VMCluster.
     * 
     */
    public List<GetDbmulticloudOracleDbAzureConnectorArcAgentNode> arcAgentNodes() {
        return this.arcAgentNodes;
    }
    /**
     * @return Azure Identity Mechanism.
     * 
     */
    public String azureIdentityMechanism() {
        return this.azureIdentityMechanism;
    }
    /**
     * @return Azure Resource Group Name.
     * 
     */
    public String azureResourceGroup() {
        return this.azureResourceGroup;
    }
    /**
     * @return Azure Subscription ID.
     * 
     */
    public String azureSubscriptionId() {
        return this.azureSubscriptionId;
    }
    /**
     * @return Azure Tenant ID.
     * 
     */
    public String azureTenantId() {
        return this.azureTenantId;
    }
    /**
     * @return The ID of the compartment that contains Oracle DB Azure Connector resource.
     * 
     */
    public String compartmentId() {
        return this.compartmentId;
    }
    /**
     * @return The ID of the DB Cluster Resource where this Azure Arc Agent identity to configure.
     * 
     */
    public String dbClusterResourceId() {
        return this.dbClusterResourceId;
    }
    /**
     * @return Oracle DB Azure Connector resource name.
     * 
     */
    public String displayName() {
        return this.displayName;
    }
    /**
     * @return The ID of the Oracle DB Azure Connector resource.
     * 
     */
    public String id() {
        return this.id;
    }
    /**
     * @return Description of the latest modification of the Oracle DB Azure Connector Resource.
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
    public String oracleDbAzureConnectorId() {
        return this.oracleDbAzureConnectorId;
    }
    /**
     * @return The current lifecycle state of the Azure Arc Agent Resource.
     * 
     */
    public String state() {
        return this.state;
    }
    /**
     * @return Time when the Oracle DB Azure Connector Resource was created expressed in [RFC 3339](https://tools.ietf.org/html/rfc3339) timestamp format, e.g. &#39;2020-05-22T21:10:29.600Z&#39;
     * 
     */
    public String timeCreated() {
        return this.timeCreated;
    }
    /**
     * @return Time when the Oracle DB Azure Connector Resource was last modified expressed in [RFC 3339](https://tools.ietf.org/html/rfc3339) timestamp format, e.g. &#39;2020-05-22T21:10:29.600Z&#39;
     * 
     */
    public String timeUpdated() {
        return this.timeUpdated;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetDbmulticloudOracleDbAzureConnectorResult defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String accessToken;
        private List<GetDbmulticloudOracleDbAzureConnectorArcAgentNode> arcAgentNodes;
        private String azureIdentityMechanism;
        private String azureResourceGroup;
        private String azureSubscriptionId;
        private String azureTenantId;
        private String compartmentId;
        private String dbClusterResourceId;
        private String displayName;
        private String id;
        private String lastModification;
        private String lifecycleStateDetails;
        private String oracleDbAzureConnectorId;
        private String state;
        private String timeCreated;
        private String timeUpdated;
        public Builder() {}
        public Builder(GetDbmulticloudOracleDbAzureConnectorResult defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.accessToken = defaults.accessToken;
    	      this.arcAgentNodes = defaults.arcAgentNodes;
    	      this.azureIdentityMechanism = defaults.azureIdentityMechanism;
    	      this.azureResourceGroup = defaults.azureResourceGroup;
    	      this.azureSubscriptionId = defaults.azureSubscriptionId;
    	      this.azureTenantId = defaults.azureTenantId;
    	      this.compartmentId = defaults.compartmentId;
    	      this.dbClusterResourceId = defaults.dbClusterResourceId;
    	      this.displayName = defaults.displayName;
    	      this.id = defaults.id;
    	      this.lastModification = defaults.lastModification;
    	      this.lifecycleStateDetails = defaults.lifecycleStateDetails;
    	      this.oracleDbAzureConnectorId = defaults.oracleDbAzureConnectorId;
    	      this.state = defaults.state;
    	      this.timeCreated = defaults.timeCreated;
    	      this.timeUpdated = defaults.timeUpdated;
        }

        @CustomType.Setter
        public Builder accessToken(String accessToken) {
            if (accessToken == null) {
              throw new MissingRequiredPropertyException("GetDbmulticloudOracleDbAzureConnectorResult", "accessToken");
            }
            this.accessToken = accessToken;
            return this;
        }
        @CustomType.Setter
        public Builder arcAgentNodes(List<GetDbmulticloudOracleDbAzureConnectorArcAgentNode> arcAgentNodes) {
            if (arcAgentNodes == null) {
              throw new MissingRequiredPropertyException("GetDbmulticloudOracleDbAzureConnectorResult", "arcAgentNodes");
            }
            this.arcAgentNodes = arcAgentNodes;
            return this;
        }
        public Builder arcAgentNodes(GetDbmulticloudOracleDbAzureConnectorArcAgentNode... arcAgentNodes) {
            return arcAgentNodes(List.of(arcAgentNodes));
        }
        @CustomType.Setter
        public Builder azureIdentityMechanism(String azureIdentityMechanism) {
            if (azureIdentityMechanism == null) {
              throw new MissingRequiredPropertyException("GetDbmulticloudOracleDbAzureConnectorResult", "azureIdentityMechanism");
            }
            this.azureIdentityMechanism = azureIdentityMechanism;
            return this;
        }
        @CustomType.Setter
        public Builder azureResourceGroup(String azureResourceGroup) {
            if (azureResourceGroup == null) {
              throw new MissingRequiredPropertyException("GetDbmulticloudOracleDbAzureConnectorResult", "azureResourceGroup");
            }
            this.azureResourceGroup = azureResourceGroup;
            return this;
        }
        @CustomType.Setter
        public Builder azureSubscriptionId(String azureSubscriptionId) {
            if (azureSubscriptionId == null) {
              throw new MissingRequiredPropertyException("GetDbmulticloudOracleDbAzureConnectorResult", "azureSubscriptionId");
            }
            this.azureSubscriptionId = azureSubscriptionId;
            return this;
        }
        @CustomType.Setter
        public Builder azureTenantId(String azureTenantId) {
            if (azureTenantId == null) {
              throw new MissingRequiredPropertyException("GetDbmulticloudOracleDbAzureConnectorResult", "azureTenantId");
            }
            this.azureTenantId = azureTenantId;
            return this;
        }
        @CustomType.Setter
        public Builder compartmentId(String compartmentId) {
            if (compartmentId == null) {
              throw new MissingRequiredPropertyException("GetDbmulticloudOracleDbAzureConnectorResult", "compartmentId");
            }
            this.compartmentId = compartmentId;
            return this;
        }
        @CustomType.Setter
        public Builder dbClusterResourceId(String dbClusterResourceId) {
            if (dbClusterResourceId == null) {
              throw new MissingRequiredPropertyException("GetDbmulticloudOracleDbAzureConnectorResult", "dbClusterResourceId");
            }
            this.dbClusterResourceId = dbClusterResourceId;
            return this;
        }
        @CustomType.Setter
        public Builder displayName(String displayName) {
            if (displayName == null) {
              throw new MissingRequiredPropertyException("GetDbmulticloudOracleDbAzureConnectorResult", "displayName");
            }
            this.displayName = displayName;
            return this;
        }
        @CustomType.Setter
        public Builder id(String id) {
            if (id == null) {
              throw new MissingRequiredPropertyException("GetDbmulticloudOracleDbAzureConnectorResult", "id");
            }
            this.id = id;
            return this;
        }
        @CustomType.Setter
        public Builder lastModification(String lastModification) {
            if (lastModification == null) {
              throw new MissingRequiredPropertyException("GetDbmulticloudOracleDbAzureConnectorResult", "lastModification");
            }
            this.lastModification = lastModification;
            return this;
        }
        @CustomType.Setter
        public Builder lifecycleStateDetails(String lifecycleStateDetails) {
            if (lifecycleStateDetails == null) {
              throw new MissingRequiredPropertyException("GetDbmulticloudOracleDbAzureConnectorResult", "lifecycleStateDetails");
            }
            this.lifecycleStateDetails = lifecycleStateDetails;
            return this;
        }
        @CustomType.Setter
        public Builder oracleDbAzureConnectorId(String oracleDbAzureConnectorId) {
            if (oracleDbAzureConnectorId == null) {
              throw new MissingRequiredPropertyException("GetDbmulticloudOracleDbAzureConnectorResult", "oracleDbAzureConnectorId");
            }
            this.oracleDbAzureConnectorId = oracleDbAzureConnectorId;
            return this;
        }
        @CustomType.Setter
        public Builder state(String state) {
            if (state == null) {
              throw new MissingRequiredPropertyException("GetDbmulticloudOracleDbAzureConnectorResult", "state");
            }
            this.state = state;
            return this;
        }
        @CustomType.Setter
        public Builder timeCreated(String timeCreated) {
            if (timeCreated == null) {
              throw new MissingRequiredPropertyException("GetDbmulticloudOracleDbAzureConnectorResult", "timeCreated");
            }
            this.timeCreated = timeCreated;
            return this;
        }
        @CustomType.Setter
        public Builder timeUpdated(String timeUpdated) {
            if (timeUpdated == null) {
              throw new MissingRequiredPropertyException("GetDbmulticloudOracleDbAzureConnectorResult", "timeUpdated");
            }
            this.timeUpdated = timeUpdated;
            return this;
        }
        public GetDbmulticloudOracleDbAzureConnectorResult build() {
            final var _resultValue = new GetDbmulticloudOracleDbAzureConnectorResult();
            _resultValue.accessToken = accessToken;
            _resultValue.arcAgentNodes = arcAgentNodes;
            _resultValue.azureIdentityMechanism = azureIdentityMechanism;
            _resultValue.azureResourceGroup = azureResourceGroup;
            _resultValue.azureSubscriptionId = azureSubscriptionId;
            _resultValue.azureTenantId = azureTenantId;
            _resultValue.compartmentId = compartmentId;
            _resultValue.dbClusterResourceId = dbClusterResourceId;
            _resultValue.displayName = displayName;
            _resultValue.id = id;
            _resultValue.lastModification = lastModification;
            _resultValue.lifecycleStateDetails = lifecycleStateDetails;
            _resultValue.oracleDbAzureConnectorId = oracleDbAzureConnectorId;
            _resultValue.state = state;
            _resultValue.timeCreated = timeCreated;
            _resultValue.timeUpdated = timeUpdated;
            return _resultValue;
        }
    }
}
