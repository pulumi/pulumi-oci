// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Database.outputs;

import com.pulumi.core.annotations.CustomType;
import java.lang.String;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;

@CustomType
public final class ExternalContainerDatabaseStackMonitoringConfig {
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the [external database connector](https://docs.cloud.oracle.com/iaas/api/#/en/database/latest/datatypes/CreateExternalDatabaseConnectorDetails).
     * 
     */
    private @Nullable String stackMonitoringConnectorId;
    /**
     * @return The status of Stack Monitoring.
     * 
     */
    private @Nullable String stackMonitoringStatus;

    private ExternalContainerDatabaseStackMonitoringConfig() {}
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the [external database connector](https://docs.cloud.oracle.com/iaas/api/#/en/database/latest/datatypes/CreateExternalDatabaseConnectorDetails).
     * 
     */
    public Optional<String> stackMonitoringConnectorId() {
        return Optional.ofNullable(this.stackMonitoringConnectorId);
    }
    /**
     * @return The status of Stack Monitoring.
     * 
     */
    public Optional<String> stackMonitoringStatus() {
        return Optional.ofNullable(this.stackMonitoringStatus);
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(ExternalContainerDatabaseStackMonitoringConfig defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private @Nullable String stackMonitoringConnectorId;
        private @Nullable String stackMonitoringStatus;
        public Builder() {}
        public Builder(ExternalContainerDatabaseStackMonitoringConfig defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.stackMonitoringConnectorId = defaults.stackMonitoringConnectorId;
    	      this.stackMonitoringStatus = defaults.stackMonitoringStatus;
        }

        @CustomType.Setter
        public Builder stackMonitoringConnectorId(@Nullable String stackMonitoringConnectorId) {
            this.stackMonitoringConnectorId = stackMonitoringConnectorId;
            return this;
        }
        @CustomType.Setter
        public Builder stackMonitoringStatus(@Nullable String stackMonitoringStatus) {
            this.stackMonitoringStatus = stackMonitoringStatus;
            return this;
        }
        public ExternalContainerDatabaseStackMonitoringConfig build() {
            final var o = new ExternalContainerDatabaseStackMonitoringConfig();
            o.stackMonitoringConnectorId = stackMonitoringConnectorId;
            o.stackMonitoringStatus = stackMonitoringStatus;
            return o;
        }
    }
}