// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.StackMonitoring.outputs;

import com.pulumi.core.annotations.CustomType;
import java.lang.Integer;
import java.lang.String;
import java.util.Objects;

@CustomType
public final class GetMonitoredResourcesMonitoredResourceCollectionItemDatabaseConnectionDetail {
    /**
     * @return Database connector Identifier [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
     * 
     */
    private String connectorId;
    /**
     * @return dbId of the database.
     * 
     */
    private String dbId;
    /**
     * @return UniqueName used for database connection requests.
     * 
     */
    private String dbUniqueName;
    /**
     * @return Listener Port number used for connection requests.
     * 
     */
    private Integer port;
    /**
     * @return Protocol used in DB connection string when connecting to external database service.
     * 
     */
    private String protocol;
    /**
     * @return Service name used for connection requests.
     * 
     */
    private String serviceName;
    /**
     * @return SSL Secret Identifier for TCPS connector in Oracle Cloud Infrastructure Vault[OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
     * 
     */
    private String sslSecretId;

    private GetMonitoredResourcesMonitoredResourceCollectionItemDatabaseConnectionDetail() {}
    /**
     * @return Database connector Identifier [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
     * 
     */
    public String connectorId() {
        return this.connectorId;
    }
    /**
     * @return dbId of the database.
     * 
     */
    public String dbId() {
        return this.dbId;
    }
    /**
     * @return UniqueName used for database connection requests.
     * 
     */
    public String dbUniqueName() {
        return this.dbUniqueName;
    }
    /**
     * @return Listener Port number used for connection requests.
     * 
     */
    public Integer port() {
        return this.port;
    }
    /**
     * @return Protocol used in DB connection string when connecting to external database service.
     * 
     */
    public String protocol() {
        return this.protocol;
    }
    /**
     * @return Service name used for connection requests.
     * 
     */
    public String serviceName() {
        return this.serviceName;
    }
    /**
     * @return SSL Secret Identifier for TCPS connector in Oracle Cloud Infrastructure Vault[OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
     * 
     */
    public String sslSecretId() {
        return this.sslSecretId;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetMonitoredResourcesMonitoredResourceCollectionItemDatabaseConnectionDetail defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String connectorId;
        private String dbId;
        private String dbUniqueName;
        private Integer port;
        private String protocol;
        private String serviceName;
        private String sslSecretId;
        public Builder() {}
        public Builder(GetMonitoredResourcesMonitoredResourceCollectionItemDatabaseConnectionDetail defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.connectorId = defaults.connectorId;
    	      this.dbId = defaults.dbId;
    	      this.dbUniqueName = defaults.dbUniqueName;
    	      this.port = defaults.port;
    	      this.protocol = defaults.protocol;
    	      this.serviceName = defaults.serviceName;
    	      this.sslSecretId = defaults.sslSecretId;
        }

        @CustomType.Setter
        public Builder connectorId(String connectorId) {
            this.connectorId = Objects.requireNonNull(connectorId);
            return this;
        }
        @CustomType.Setter
        public Builder dbId(String dbId) {
            this.dbId = Objects.requireNonNull(dbId);
            return this;
        }
        @CustomType.Setter
        public Builder dbUniqueName(String dbUniqueName) {
            this.dbUniqueName = Objects.requireNonNull(dbUniqueName);
            return this;
        }
        @CustomType.Setter
        public Builder port(Integer port) {
            this.port = Objects.requireNonNull(port);
            return this;
        }
        @CustomType.Setter
        public Builder protocol(String protocol) {
            this.protocol = Objects.requireNonNull(protocol);
            return this;
        }
        @CustomType.Setter
        public Builder serviceName(String serviceName) {
            this.serviceName = Objects.requireNonNull(serviceName);
            return this;
        }
        @CustomType.Setter
        public Builder sslSecretId(String sslSecretId) {
            this.sslSecretId = Objects.requireNonNull(sslSecretId);
            return this;
        }
        public GetMonitoredResourcesMonitoredResourceCollectionItemDatabaseConnectionDetail build() {
            final var o = new GetMonitoredResourcesMonitoredResourceCollectionItemDatabaseConnectionDetail();
            o.connectorId = connectorId;
            o.dbId = dbId;
            o.dbUniqueName = dbUniqueName;
            o.port = port;
            o.protocol = protocol;
            o.serviceName = serviceName;
            o.sslSecretId = sslSecretId;
            return o;
        }
    }
}