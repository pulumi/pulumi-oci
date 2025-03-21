// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Database.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.String;
import java.util.Objects;

@CustomType
public final class GetExternalPluggableDatabaseStackMonitoringConfig {
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the [external database connector](https://docs.cloud.oracle.com/iaas/api/#/en/database/latest/datatypes/CreateExternalDatabaseConnectorDetails).
     * 
     */
    private String stackMonitoringConnectorId;
    /**
     * @return The status of Stack Monitoring.
     * 
     */
    private String stackMonitoringStatus;

    private GetExternalPluggableDatabaseStackMonitoringConfig() {}
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the [external database connector](https://docs.cloud.oracle.com/iaas/api/#/en/database/latest/datatypes/CreateExternalDatabaseConnectorDetails).
     * 
     */
    public String stackMonitoringConnectorId() {
        return this.stackMonitoringConnectorId;
    }
    /**
     * @return The status of Stack Monitoring.
     * 
     */
    public String stackMonitoringStatus() {
        return this.stackMonitoringStatus;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetExternalPluggableDatabaseStackMonitoringConfig defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String stackMonitoringConnectorId;
        private String stackMonitoringStatus;
        public Builder() {}
        public Builder(GetExternalPluggableDatabaseStackMonitoringConfig defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.stackMonitoringConnectorId = defaults.stackMonitoringConnectorId;
    	      this.stackMonitoringStatus = defaults.stackMonitoringStatus;
        }

        @CustomType.Setter
        public Builder stackMonitoringConnectorId(String stackMonitoringConnectorId) {
            if (stackMonitoringConnectorId == null) {
              throw new MissingRequiredPropertyException("GetExternalPluggableDatabaseStackMonitoringConfig", "stackMonitoringConnectorId");
            }
            this.stackMonitoringConnectorId = stackMonitoringConnectorId;
            return this;
        }
        @CustomType.Setter
        public Builder stackMonitoringStatus(String stackMonitoringStatus) {
            if (stackMonitoringStatus == null) {
              throw new MissingRequiredPropertyException("GetExternalPluggableDatabaseStackMonitoringConfig", "stackMonitoringStatus");
            }
            this.stackMonitoringStatus = stackMonitoringStatus;
            return this;
        }
        public GetExternalPluggableDatabaseStackMonitoringConfig build() {
            final var _resultValue = new GetExternalPluggableDatabaseStackMonitoringConfig();
            _resultValue.stackMonitoringConnectorId = stackMonitoringConnectorId;
            _resultValue.stackMonitoringStatus = stackMonitoringStatus;
            return _resultValue;
        }
    }
}
