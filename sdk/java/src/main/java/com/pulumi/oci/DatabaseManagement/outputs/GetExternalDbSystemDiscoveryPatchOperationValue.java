// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DatabaseManagement.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.DatabaseManagement.outputs.GetExternalDbSystemDiscoveryPatchOperationValueConnector;
import java.lang.Boolean;
import java.lang.String;
import java.util.List;
import java.util.Objects;

@CustomType
public final class GetExternalDbSystemDiscoveryPatchOperationValue {
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
     * 
     */
    private String compartmentId;
    /**
     * @return The connector details used to connect to the external DB system component.
     * 
     */
    private List<GetExternalDbSystemDiscoveryPatchOperationValueConnector> connectors;
    /**
     * @return The user-friendly name for the DB system. The name does not have to be unique.
     * 
     */
    private String displayName;
    /**
     * @return Indicates whether the DB system component should be provisioned as an Oracle Cloud Infrastructure resource or not.
     * 
     */
    private Boolean isSelectedForMonitoring;

    private GetExternalDbSystemDiscoveryPatchOperationValue() {}
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
     * 
     */
    public String compartmentId() {
        return this.compartmentId;
    }
    /**
     * @return The connector details used to connect to the external DB system component.
     * 
     */
    public List<GetExternalDbSystemDiscoveryPatchOperationValueConnector> connectors() {
        return this.connectors;
    }
    /**
     * @return The user-friendly name for the DB system. The name does not have to be unique.
     * 
     */
    public String displayName() {
        return this.displayName;
    }
    /**
     * @return Indicates whether the DB system component should be provisioned as an Oracle Cloud Infrastructure resource or not.
     * 
     */
    public Boolean isSelectedForMonitoring() {
        return this.isSelectedForMonitoring;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetExternalDbSystemDiscoveryPatchOperationValue defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String compartmentId;
        private List<GetExternalDbSystemDiscoveryPatchOperationValueConnector> connectors;
        private String displayName;
        private Boolean isSelectedForMonitoring;
        public Builder() {}
        public Builder(GetExternalDbSystemDiscoveryPatchOperationValue defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.compartmentId = defaults.compartmentId;
    	      this.connectors = defaults.connectors;
    	      this.displayName = defaults.displayName;
    	      this.isSelectedForMonitoring = defaults.isSelectedForMonitoring;
        }

        @CustomType.Setter
        public Builder compartmentId(String compartmentId) {
            if (compartmentId == null) {
              throw new MissingRequiredPropertyException("GetExternalDbSystemDiscoveryPatchOperationValue", "compartmentId");
            }
            this.compartmentId = compartmentId;
            return this;
        }
        @CustomType.Setter
        public Builder connectors(List<GetExternalDbSystemDiscoveryPatchOperationValueConnector> connectors) {
            if (connectors == null) {
              throw new MissingRequiredPropertyException("GetExternalDbSystemDiscoveryPatchOperationValue", "connectors");
            }
            this.connectors = connectors;
            return this;
        }
        public Builder connectors(GetExternalDbSystemDiscoveryPatchOperationValueConnector... connectors) {
            return connectors(List.of(connectors));
        }
        @CustomType.Setter
        public Builder displayName(String displayName) {
            if (displayName == null) {
              throw new MissingRequiredPropertyException("GetExternalDbSystemDiscoveryPatchOperationValue", "displayName");
            }
            this.displayName = displayName;
            return this;
        }
        @CustomType.Setter
        public Builder isSelectedForMonitoring(Boolean isSelectedForMonitoring) {
            if (isSelectedForMonitoring == null) {
              throw new MissingRequiredPropertyException("GetExternalDbSystemDiscoveryPatchOperationValue", "isSelectedForMonitoring");
            }
            this.isSelectedForMonitoring = isSelectedForMonitoring;
            return this;
        }
        public GetExternalDbSystemDiscoveryPatchOperationValue build() {
            final var _resultValue = new GetExternalDbSystemDiscoveryPatchOperationValue();
            _resultValue.compartmentId = compartmentId;
            _resultValue.connectors = connectors;
            _resultValue.displayName = displayName;
            _resultValue.isSelectedForMonitoring = isSelectedForMonitoring;
            return _resultValue;
        }
    }
}
