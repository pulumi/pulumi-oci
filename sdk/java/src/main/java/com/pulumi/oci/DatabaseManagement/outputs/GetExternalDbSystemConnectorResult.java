// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DatabaseManagement.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.DatabaseManagement.outputs.GetExternalDbSystemConnectorConnectionInfo;
import java.lang.String;
import java.util.List;
import java.util.Map;
import java.util.Objects;

@CustomType
public final class GetExternalDbSystemConnectorResult {
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the management agent used for the external DB system connector.
     * 
     */
    private String agentId;
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
     * 
     */
    private String compartmentId;
    /**
     * @return The error message indicating the reason for connection failure or `null` if the connection was successful.
     * 
     */
    private String connectionFailureMessage;
    /**
     * @return The connection details required to connect to an external DB system component.
     * 
     */
    private List<GetExternalDbSystemConnectorConnectionInfo> connectionInfos;
    /**
     * @return The status of connectivity to the external DB system component.
     * 
     */
    private String connectionStatus;
    /**
     * @return The type of connector.
     * 
     */
    private String connectorType;
    /**
     * @return Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{&#34;Operations.CostCenter&#34;: &#34;42&#34;}`
     * 
     */
    private Map<String,String> definedTags;
    /**
     * @return The user-friendly name for the external connector. The name does not have to be unique.
     * 
     */
    private String displayName;
    private String externalDbSystemConnectorId;
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the external DB system that the connector is a part of.
     * 
     */
    private String externalDbSystemId;
    /**
     * @return Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{&#34;Department&#34;: &#34;Finance&#34;}`
     * 
     */
    private Map<String,String> freeformTags;
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the external DB system connector.
     * 
     */
    private String id;
    /**
     * @return Additional information about the current lifecycle state.
     * 
     */
    private String lifecycleDetails;
    /**
     * @return The current lifecycle state of the external DB system connector.
     * 
     */
    private String state;
    /**
     * @return System tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). System tags can be viewed by users, but can only be created by the system.  Example: `{&#34;orcl-cloud.free-tier-retained&#34;: &#34;true&#34;}`
     * 
     */
    private Map<String,String> systemTags;
    /**
     * @return The date and time the connectionStatus of the external DB system connector was last updated.
     * 
     */
    private String timeConnectionStatusLastUpdated;
    /**
     * @return The date and time the external DB system connector was created.
     * 
     */
    private String timeCreated;
    /**
     * @return The date and time the external DB system connector was last updated.
     * 
     */
    private String timeUpdated;

    private GetExternalDbSystemConnectorResult() {}
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the management agent used for the external DB system connector.
     * 
     */
    public String agentId() {
        return this.agentId;
    }
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
     * 
     */
    public String compartmentId() {
        return this.compartmentId;
    }
    /**
     * @return The error message indicating the reason for connection failure or `null` if the connection was successful.
     * 
     */
    public String connectionFailureMessage() {
        return this.connectionFailureMessage;
    }
    /**
     * @return The connection details required to connect to an external DB system component.
     * 
     */
    public List<GetExternalDbSystemConnectorConnectionInfo> connectionInfos() {
        return this.connectionInfos;
    }
    /**
     * @return The status of connectivity to the external DB system component.
     * 
     */
    public String connectionStatus() {
        return this.connectionStatus;
    }
    /**
     * @return The type of connector.
     * 
     */
    public String connectorType() {
        return this.connectorType;
    }
    /**
     * @return Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{&#34;Operations.CostCenter&#34;: &#34;42&#34;}`
     * 
     */
    public Map<String,String> definedTags() {
        return this.definedTags;
    }
    /**
     * @return The user-friendly name for the external connector. The name does not have to be unique.
     * 
     */
    public String displayName() {
        return this.displayName;
    }
    public String externalDbSystemConnectorId() {
        return this.externalDbSystemConnectorId;
    }
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the external DB system that the connector is a part of.
     * 
     */
    public String externalDbSystemId() {
        return this.externalDbSystemId;
    }
    /**
     * @return Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{&#34;Department&#34;: &#34;Finance&#34;}`
     * 
     */
    public Map<String,String> freeformTags() {
        return this.freeformTags;
    }
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the external DB system connector.
     * 
     */
    public String id() {
        return this.id;
    }
    /**
     * @return Additional information about the current lifecycle state.
     * 
     */
    public String lifecycleDetails() {
        return this.lifecycleDetails;
    }
    /**
     * @return The current lifecycle state of the external DB system connector.
     * 
     */
    public String state() {
        return this.state;
    }
    /**
     * @return System tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). System tags can be viewed by users, but can only be created by the system.  Example: `{&#34;orcl-cloud.free-tier-retained&#34;: &#34;true&#34;}`
     * 
     */
    public Map<String,String> systemTags() {
        return this.systemTags;
    }
    /**
     * @return The date and time the connectionStatus of the external DB system connector was last updated.
     * 
     */
    public String timeConnectionStatusLastUpdated() {
        return this.timeConnectionStatusLastUpdated;
    }
    /**
     * @return The date and time the external DB system connector was created.
     * 
     */
    public String timeCreated() {
        return this.timeCreated;
    }
    /**
     * @return The date and time the external DB system connector was last updated.
     * 
     */
    public String timeUpdated() {
        return this.timeUpdated;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetExternalDbSystemConnectorResult defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String agentId;
        private String compartmentId;
        private String connectionFailureMessage;
        private List<GetExternalDbSystemConnectorConnectionInfo> connectionInfos;
        private String connectionStatus;
        private String connectorType;
        private Map<String,String> definedTags;
        private String displayName;
        private String externalDbSystemConnectorId;
        private String externalDbSystemId;
        private Map<String,String> freeformTags;
        private String id;
        private String lifecycleDetails;
        private String state;
        private Map<String,String> systemTags;
        private String timeConnectionStatusLastUpdated;
        private String timeCreated;
        private String timeUpdated;
        public Builder() {}
        public Builder(GetExternalDbSystemConnectorResult defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.agentId = defaults.agentId;
    	      this.compartmentId = defaults.compartmentId;
    	      this.connectionFailureMessage = defaults.connectionFailureMessage;
    	      this.connectionInfos = defaults.connectionInfos;
    	      this.connectionStatus = defaults.connectionStatus;
    	      this.connectorType = defaults.connectorType;
    	      this.definedTags = defaults.definedTags;
    	      this.displayName = defaults.displayName;
    	      this.externalDbSystemConnectorId = defaults.externalDbSystemConnectorId;
    	      this.externalDbSystemId = defaults.externalDbSystemId;
    	      this.freeformTags = defaults.freeformTags;
    	      this.id = defaults.id;
    	      this.lifecycleDetails = defaults.lifecycleDetails;
    	      this.state = defaults.state;
    	      this.systemTags = defaults.systemTags;
    	      this.timeConnectionStatusLastUpdated = defaults.timeConnectionStatusLastUpdated;
    	      this.timeCreated = defaults.timeCreated;
    	      this.timeUpdated = defaults.timeUpdated;
        }

        @CustomType.Setter
        public Builder agentId(String agentId) {
            if (agentId == null) {
              throw new MissingRequiredPropertyException("GetExternalDbSystemConnectorResult", "agentId");
            }
            this.agentId = agentId;
            return this;
        }
        @CustomType.Setter
        public Builder compartmentId(String compartmentId) {
            if (compartmentId == null) {
              throw new MissingRequiredPropertyException("GetExternalDbSystemConnectorResult", "compartmentId");
            }
            this.compartmentId = compartmentId;
            return this;
        }
        @CustomType.Setter
        public Builder connectionFailureMessage(String connectionFailureMessage) {
            if (connectionFailureMessage == null) {
              throw new MissingRequiredPropertyException("GetExternalDbSystemConnectorResult", "connectionFailureMessage");
            }
            this.connectionFailureMessage = connectionFailureMessage;
            return this;
        }
        @CustomType.Setter
        public Builder connectionInfos(List<GetExternalDbSystemConnectorConnectionInfo> connectionInfos) {
            if (connectionInfos == null) {
              throw new MissingRequiredPropertyException("GetExternalDbSystemConnectorResult", "connectionInfos");
            }
            this.connectionInfos = connectionInfos;
            return this;
        }
        public Builder connectionInfos(GetExternalDbSystemConnectorConnectionInfo... connectionInfos) {
            return connectionInfos(List.of(connectionInfos));
        }
        @CustomType.Setter
        public Builder connectionStatus(String connectionStatus) {
            if (connectionStatus == null) {
              throw new MissingRequiredPropertyException("GetExternalDbSystemConnectorResult", "connectionStatus");
            }
            this.connectionStatus = connectionStatus;
            return this;
        }
        @CustomType.Setter
        public Builder connectorType(String connectorType) {
            if (connectorType == null) {
              throw new MissingRequiredPropertyException("GetExternalDbSystemConnectorResult", "connectorType");
            }
            this.connectorType = connectorType;
            return this;
        }
        @CustomType.Setter
        public Builder definedTags(Map<String,String> definedTags) {
            if (definedTags == null) {
              throw new MissingRequiredPropertyException("GetExternalDbSystemConnectorResult", "definedTags");
            }
            this.definedTags = definedTags;
            return this;
        }
        @CustomType.Setter
        public Builder displayName(String displayName) {
            if (displayName == null) {
              throw new MissingRequiredPropertyException("GetExternalDbSystemConnectorResult", "displayName");
            }
            this.displayName = displayName;
            return this;
        }
        @CustomType.Setter
        public Builder externalDbSystemConnectorId(String externalDbSystemConnectorId) {
            if (externalDbSystemConnectorId == null) {
              throw new MissingRequiredPropertyException("GetExternalDbSystemConnectorResult", "externalDbSystemConnectorId");
            }
            this.externalDbSystemConnectorId = externalDbSystemConnectorId;
            return this;
        }
        @CustomType.Setter
        public Builder externalDbSystemId(String externalDbSystemId) {
            if (externalDbSystemId == null) {
              throw new MissingRequiredPropertyException("GetExternalDbSystemConnectorResult", "externalDbSystemId");
            }
            this.externalDbSystemId = externalDbSystemId;
            return this;
        }
        @CustomType.Setter
        public Builder freeformTags(Map<String,String> freeformTags) {
            if (freeformTags == null) {
              throw new MissingRequiredPropertyException("GetExternalDbSystemConnectorResult", "freeformTags");
            }
            this.freeformTags = freeformTags;
            return this;
        }
        @CustomType.Setter
        public Builder id(String id) {
            if (id == null) {
              throw new MissingRequiredPropertyException("GetExternalDbSystemConnectorResult", "id");
            }
            this.id = id;
            return this;
        }
        @CustomType.Setter
        public Builder lifecycleDetails(String lifecycleDetails) {
            if (lifecycleDetails == null) {
              throw new MissingRequiredPropertyException("GetExternalDbSystemConnectorResult", "lifecycleDetails");
            }
            this.lifecycleDetails = lifecycleDetails;
            return this;
        }
        @CustomType.Setter
        public Builder state(String state) {
            if (state == null) {
              throw new MissingRequiredPropertyException("GetExternalDbSystemConnectorResult", "state");
            }
            this.state = state;
            return this;
        }
        @CustomType.Setter
        public Builder systemTags(Map<String,String> systemTags) {
            if (systemTags == null) {
              throw new MissingRequiredPropertyException("GetExternalDbSystemConnectorResult", "systemTags");
            }
            this.systemTags = systemTags;
            return this;
        }
        @CustomType.Setter
        public Builder timeConnectionStatusLastUpdated(String timeConnectionStatusLastUpdated) {
            if (timeConnectionStatusLastUpdated == null) {
              throw new MissingRequiredPropertyException("GetExternalDbSystemConnectorResult", "timeConnectionStatusLastUpdated");
            }
            this.timeConnectionStatusLastUpdated = timeConnectionStatusLastUpdated;
            return this;
        }
        @CustomType.Setter
        public Builder timeCreated(String timeCreated) {
            if (timeCreated == null) {
              throw new MissingRequiredPropertyException("GetExternalDbSystemConnectorResult", "timeCreated");
            }
            this.timeCreated = timeCreated;
            return this;
        }
        @CustomType.Setter
        public Builder timeUpdated(String timeUpdated) {
            if (timeUpdated == null) {
              throw new MissingRequiredPropertyException("GetExternalDbSystemConnectorResult", "timeUpdated");
            }
            this.timeUpdated = timeUpdated;
            return this;
        }
        public GetExternalDbSystemConnectorResult build() {
            final var _resultValue = new GetExternalDbSystemConnectorResult();
            _resultValue.agentId = agentId;
            _resultValue.compartmentId = compartmentId;
            _resultValue.connectionFailureMessage = connectionFailureMessage;
            _resultValue.connectionInfos = connectionInfos;
            _resultValue.connectionStatus = connectionStatus;
            _resultValue.connectorType = connectorType;
            _resultValue.definedTags = definedTags;
            _resultValue.displayName = displayName;
            _resultValue.externalDbSystemConnectorId = externalDbSystemConnectorId;
            _resultValue.externalDbSystemId = externalDbSystemId;
            _resultValue.freeformTags = freeformTags;
            _resultValue.id = id;
            _resultValue.lifecycleDetails = lifecycleDetails;
            _resultValue.state = state;
            _resultValue.systemTags = systemTags;
            _resultValue.timeConnectionStatusLastUpdated = timeConnectionStatusLastUpdated;
            _resultValue.timeCreated = timeCreated;
            _resultValue.timeUpdated = timeUpdated;
            return _resultValue;
        }
    }
}
