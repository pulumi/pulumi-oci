// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DatabaseManagement.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.oci.DatabaseManagement.outputs.ExternalDbSystemDiscoveryPatchOperationValueConnector;
import java.lang.Boolean;
import java.lang.String;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;

@CustomType
public final class ExternalDbSystemDiscoveryPatchOperationValue {
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment in which the external DB system resides.
     * 
     */
    private @Nullable String compartmentId;
    /**
     * @return The connector details used to connect to the external DB system component.
     * 
     */
    private @Nullable ExternalDbSystemDiscoveryPatchOperationValueConnector connector;
    /**
     * @return (Updatable) The user-friendly name for the DB system. The name does not have to be unique.
     * 
     */
    private @Nullable String displayName;
    /**
     * @return Indicates whether the DB system component should be provisioned as an Oracle Cloud Infrastructure resource or not.
     * 
     */
    private @Nullable Boolean isSelectedForMonitoring;

    private ExternalDbSystemDiscoveryPatchOperationValue() {}
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment in which the external DB system resides.
     * 
     */
    public Optional<String> compartmentId() {
        return Optional.ofNullable(this.compartmentId);
    }
    /**
     * @return The connector details used to connect to the external DB system component.
     * 
     */
    public Optional<ExternalDbSystemDiscoveryPatchOperationValueConnector> connector() {
        return Optional.ofNullable(this.connector);
    }
    /**
     * @return (Updatable) The user-friendly name for the DB system. The name does not have to be unique.
     * 
     */
    public Optional<String> displayName() {
        return Optional.ofNullable(this.displayName);
    }
    /**
     * @return Indicates whether the DB system component should be provisioned as an Oracle Cloud Infrastructure resource or not.
     * 
     */
    public Optional<Boolean> isSelectedForMonitoring() {
        return Optional.ofNullable(this.isSelectedForMonitoring);
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(ExternalDbSystemDiscoveryPatchOperationValue defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private @Nullable String compartmentId;
        private @Nullable ExternalDbSystemDiscoveryPatchOperationValueConnector connector;
        private @Nullable String displayName;
        private @Nullable Boolean isSelectedForMonitoring;
        public Builder() {}
        public Builder(ExternalDbSystemDiscoveryPatchOperationValue defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.compartmentId = defaults.compartmentId;
    	      this.connector = defaults.connector;
    	      this.displayName = defaults.displayName;
    	      this.isSelectedForMonitoring = defaults.isSelectedForMonitoring;
        }

        @CustomType.Setter
        public Builder compartmentId(@Nullable String compartmentId) {

            this.compartmentId = compartmentId;
            return this;
        }
        @CustomType.Setter
        public Builder connector(@Nullable ExternalDbSystemDiscoveryPatchOperationValueConnector connector) {

            this.connector = connector;
            return this;
        }
        @CustomType.Setter
        public Builder displayName(@Nullable String displayName) {

            this.displayName = displayName;
            return this;
        }
        @CustomType.Setter
        public Builder isSelectedForMonitoring(@Nullable Boolean isSelectedForMonitoring) {

            this.isSelectedForMonitoring = isSelectedForMonitoring;
            return this;
        }
        public ExternalDbSystemDiscoveryPatchOperationValue build() {
            final var _resultValue = new ExternalDbSystemDiscoveryPatchOperationValue();
            _resultValue.compartmentId = compartmentId;
            _resultValue.connector = connector;
            _resultValue.displayName = displayName;
            _resultValue.isSelectedForMonitoring = isSelectedForMonitoring;
            return _resultValue;
        }
    }
}
