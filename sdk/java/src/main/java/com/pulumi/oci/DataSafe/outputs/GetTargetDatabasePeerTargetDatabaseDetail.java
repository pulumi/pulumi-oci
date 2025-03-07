// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DataSafe.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.DataSafe.outputs.GetTargetDatabasePeerTargetDatabaseDetailDatabaseDetail;
import com.pulumi.oci.DataSafe.outputs.GetTargetDatabasePeerTargetDatabaseDetailTlsConfig;
import java.lang.String;
import java.util.List;
import java.util.Objects;

@CustomType
public final class GetTargetDatabasePeerTargetDatabaseDetail {
    /**
     * @return Details of the database for the registration in Data Safe.
     * 
     */
    private List<GetTargetDatabasePeerTargetDatabaseDetailDatabaseDetail> databaseDetails;
    /**
     * @return The OCID of the Data Guard Association resource in which the database associated to the peer target database is considered as peer database to the primary database.
     * 
     */
    private String dataguardAssociationId;
    /**
     * @return The description of the peer target database in Data Safe.
     * 
     */
    private String description;
    /**
     * @return The display name of the peer target database in Data Safe.
     * 
     */
    private String displayName;
    /**
     * @return The details required to establish a TLS enabled connection.
     * 
     */
    private List<GetTargetDatabasePeerTargetDatabaseDetailTlsConfig> tlsConfigs;

    private GetTargetDatabasePeerTargetDatabaseDetail() {}
    /**
     * @return Details of the database for the registration in Data Safe.
     * 
     */
    public List<GetTargetDatabasePeerTargetDatabaseDetailDatabaseDetail> databaseDetails() {
        return this.databaseDetails;
    }
    /**
     * @return The OCID of the Data Guard Association resource in which the database associated to the peer target database is considered as peer database to the primary database.
     * 
     */
    public String dataguardAssociationId() {
        return this.dataguardAssociationId;
    }
    /**
     * @return The description of the peer target database in Data Safe.
     * 
     */
    public String description() {
        return this.description;
    }
    /**
     * @return The display name of the peer target database in Data Safe.
     * 
     */
    public String displayName() {
        return this.displayName;
    }
    /**
     * @return The details required to establish a TLS enabled connection.
     * 
     */
    public List<GetTargetDatabasePeerTargetDatabaseDetailTlsConfig> tlsConfigs() {
        return this.tlsConfigs;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetTargetDatabasePeerTargetDatabaseDetail defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private List<GetTargetDatabasePeerTargetDatabaseDetailDatabaseDetail> databaseDetails;
        private String dataguardAssociationId;
        private String description;
        private String displayName;
        private List<GetTargetDatabasePeerTargetDatabaseDetailTlsConfig> tlsConfigs;
        public Builder() {}
        public Builder(GetTargetDatabasePeerTargetDatabaseDetail defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.databaseDetails = defaults.databaseDetails;
    	      this.dataguardAssociationId = defaults.dataguardAssociationId;
    	      this.description = defaults.description;
    	      this.displayName = defaults.displayName;
    	      this.tlsConfigs = defaults.tlsConfigs;
        }

        @CustomType.Setter
        public Builder databaseDetails(List<GetTargetDatabasePeerTargetDatabaseDetailDatabaseDetail> databaseDetails) {
            if (databaseDetails == null) {
              throw new MissingRequiredPropertyException("GetTargetDatabasePeerTargetDatabaseDetail", "databaseDetails");
            }
            this.databaseDetails = databaseDetails;
            return this;
        }
        public Builder databaseDetails(GetTargetDatabasePeerTargetDatabaseDetailDatabaseDetail... databaseDetails) {
            return databaseDetails(List.of(databaseDetails));
        }
        @CustomType.Setter
        public Builder dataguardAssociationId(String dataguardAssociationId) {
            if (dataguardAssociationId == null) {
              throw new MissingRequiredPropertyException("GetTargetDatabasePeerTargetDatabaseDetail", "dataguardAssociationId");
            }
            this.dataguardAssociationId = dataguardAssociationId;
            return this;
        }
        @CustomType.Setter
        public Builder description(String description) {
            if (description == null) {
              throw new MissingRequiredPropertyException("GetTargetDatabasePeerTargetDatabaseDetail", "description");
            }
            this.description = description;
            return this;
        }
        @CustomType.Setter
        public Builder displayName(String displayName) {
            if (displayName == null) {
              throw new MissingRequiredPropertyException("GetTargetDatabasePeerTargetDatabaseDetail", "displayName");
            }
            this.displayName = displayName;
            return this;
        }
        @CustomType.Setter
        public Builder tlsConfigs(List<GetTargetDatabasePeerTargetDatabaseDetailTlsConfig> tlsConfigs) {
            if (tlsConfigs == null) {
              throw new MissingRequiredPropertyException("GetTargetDatabasePeerTargetDatabaseDetail", "tlsConfigs");
            }
            this.tlsConfigs = tlsConfigs;
            return this;
        }
        public Builder tlsConfigs(GetTargetDatabasePeerTargetDatabaseDetailTlsConfig... tlsConfigs) {
            return tlsConfigs(List.of(tlsConfigs));
        }
        public GetTargetDatabasePeerTargetDatabaseDetail build() {
            final var _resultValue = new GetTargetDatabasePeerTargetDatabaseDetail();
            _resultValue.databaseDetails = databaseDetails;
            _resultValue.dataguardAssociationId = dataguardAssociationId;
            _resultValue.description = description;
            _resultValue.displayName = displayName;
            _resultValue.tlsConfigs = tlsConfigs;
            return _resultValue;
        }
    }
}
