// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DatabaseManagement.outputs;

import com.pulumi.core.annotations.CustomType;
import java.lang.String;
import java.util.Objects;

@CustomType
public final class GetExternalDatabasesExternalDatabaseCollectionItemDbManagementConfig {
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the external database connector.
     * 
     */
    private String connectorId;
    /**
     * @return The status of the Database Management service.
     * 
     */
    private String databaseManagementStatus;
    /**
     * @return The Oracle license model that applies to the external database.
     * 
     */
    private String licenseModel;

    private GetExternalDatabasesExternalDatabaseCollectionItemDbManagementConfig() {}
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the external database connector.
     * 
     */
    public String connectorId() {
        return this.connectorId;
    }
    /**
     * @return The status of the Database Management service.
     * 
     */
    public String databaseManagementStatus() {
        return this.databaseManagementStatus;
    }
    /**
     * @return The Oracle license model that applies to the external database.
     * 
     */
    public String licenseModel() {
        return this.licenseModel;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetExternalDatabasesExternalDatabaseCollectionItemDbManagementConfig defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String connectorId;
        private String databaseManagementStatus;
        private String licenseModel;
        public Builder() {}
        public Builder(GetExternalDatabasesExternalDatabaseCollectionItemDbManagementConfig defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.connectorId = defaults.connectorId;
    	      this.databaseManagementStatus = defaults.databaseManagementStatus;
    	      this.licenseModel = defaults.licenseModel;
        }

        @CustomType.Setter
        public Builder connectorId(String connectorId) {
            this.connectorId = Objects.requireNonNull(connectorId);
            return this;
        }
        @CustomType.Setter
        public Builder databaseManagementStatus(String databaseManagementStatus) {
            this.databaseManagementStatus = Objects.requireNonNull(databaseManagementStatus);
            return this;
        }
        @CustomType.Setter
        public Builder licenseModel(String licenseModel) {
            this.licenseModel = Objects.requireNonNull(licenseModel);
            return this;
        }
        public GetExternalDatabasesExternalDatabaseCollectionItemDbManagementConfig build() {
            final var o = new GetExternalDatabasesExternalDatabaseCollectionItemDbManagementConfig();
            o.connectorId = connectorId;
            o.databaseManagementStatus = databaseManagementStatus;
            o.licenseModel = licenseModel;
            return o;
        }
    }
}