// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DatabaseManagement.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.DatabaseManagement.outputs.GetManagedDatabasesManagedDatabaseCollectionItemDbmgmtFeatureConfigDatabaseConnectionDetailConnectionCredential;
import com.pulumi.oci.DatabaseManagement.outputs.GetManagedDatabasesManagedDatabaseCollectionItemDbmgmtFeatureConfigDatabaseConnectionDetailConnectionString;
import java.util.List;
import java.util.Objects;

@CustomType
public final class GetManagedDatabasesManagedDatabaseCollectionItemDbmgmtFeatureConfigDatabaseConnectionDetail {
    /**
     * @return The credentials used to connect to the database. Currently only the `DETAILS` type is supported for creating MACS connector credentials.
     * 
     */
    private List<GetManagedDatabasesManagedDatabaseCollectionItemDbmgmtFeatureConfigDatabaseConnectionDetailConnectionCredential> connectionCredentials;
    /**
     * @return The details of the Oracle Database connection string.
     * 
     */
    private List<GetManagedDatabasesManagedDatabaseCollectionItemDbmgmtFeatureConfigDatabaseConnectionDetailConnectionString> connectionStrings;

    private GetManagedDatabasesManagedDatabaseCollectionItemDbmgmtFeatureConfigDatabaseConnectionDetail() {}
    /**
     * @return The credentials used to connect to the database. Currently only the `DETAILS` type is supported for creating MACS connector credentials.
     * 
     */
    public List<GetManagedDatabasesManagedDatabaseCollectionItemDbmgmtFeatureConfigDatabaseConnectionDetailConnectionCredential> connectionCredentials() {
        return this.connectionCredentials;
    }
    /**
     * @return The details of the Oracle Database connection string.
     * 
     */
    public List<GetManagedDatabasesManagedDatabaseCollectionItemDbmgmtFeatureConfigDatabaseConnectionDetailConnectionString> connectionStrings() {
        return this.connectionStrings;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetManagedDatabasesManagedDatabaseCollectionItemDbmgmtFeatureConfigDatabaseConnectionDetail defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private List<GetManagedDatabasesManagedDatabaseCollectionItemDbmgmtFeatureConfigDatabaseConnectionDetailConnectionCredential> connectionCredentials;
        private List<GetManagedDatabasesManagedDatabaseCollectionItemDbmgmtFeatureConfigDatabaseConnectionDetailConnectionString> connectionStrings;
        public Builder() {}
        public Builder(GetManagedDatabasesManagedDatabaseCollectionItemDbmgmtFeatureConfigDatabaseConnectionDetail defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.connectionCredentials = defaults.connectionCredentials;
    	      this.connectionStrings = defaults.connectionStrings;
        }

        @CustomType.Setter
        public Builder connectionCredentials(List<GetManagedDatabasesManagedDatabaseCollectionItemDbmgmtFeatureConfigDatabaseConnectionDetailConnectionCredential> connectionCredentials) {
            if (connectionCredentials == null) {
              throw new MissingRequiredPropertyException("GetManagedDatabasesManagedDatabaseCollectionItemDbmgmtFeatureConfigDatabaseConnectionDetail", "connectionCredentials");
            }
            this.connectionCredentials = connectionCredentials;
            return this;
        }
        public Builder connectionCredentials(GetManagedDatabasesManagedDatabaseCollectionItemDbmgmtFeatureConfigDatabaseConnectionDetailConnectionCredential... connectionCredentials) {
            return connectionCredentials(List.of(connectionCredentials));
        }
        @CustomType.Setter
        public Builder connectionStrings(List<GetManagedDatabasesManagedDatabaseCollectionItemDbmgmtFeatureConfigDatabaseConnectionDetailConnectionString> connectionStrings) {
            if (connectionStrings == null) {
              throw new MissingRequiredPropertyException("GetManagedDatabasesManagedDatabaseCollectionItemDbmgmtFeatureConfigDatabaseConnectionDetail", "connectionStrings");
            }
            this.connectionStrings = connectionStrings;
            return this;
        }
        public Builder connectionStrings(GetManagedDatabasesManagedDatabaseCollectionItemDbmgmtFeatureConfigDatabaseConnectionDetailConnectionString... connectionStrings) {
            return connectionStrings(List.of(connectionStrings));
        }
        public GetManagedDatabasesManagedDatabaseCollectionItemDbmgmtFeatureConfigDatabaseConnectionDetail build() {
            final var _resultValue = new GetManagedDatabasesManagedDatabaseCollectionItemDbmgmtFeatureConfigDatabaseConnectionDetail();
            _resultValue.connectionCredentials = connectionCredentials;
            _resultValue.connectionStrings = connectionStrings;
            return _resultValue;
        }
    }
}
