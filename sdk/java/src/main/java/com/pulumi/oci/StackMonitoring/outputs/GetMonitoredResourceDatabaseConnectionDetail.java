// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.StackMonitoring.outputs;

import com.pulumi.core.annotations.CustomType;
import java.lang.Integer;
import java.lang.String;
import java.util.Objects;

@CustomType
public final class GetMonitoredResourceDatabaseConnectionDetail {
    /**
     * @return Database connector Identifier
     * 
     */
    private String connectorId;
    /**
     * @return dbId of the database
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

    private GetMonitoredResourceDatabaseConnectionDetail() {}
    /**
     * @return Database connector Identifier
     * 
     */
    public String connectorId() {
        return this.connectorId;
    }
    /**
     * @return dbId of the database
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

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetMonitoredResourceDatabaseConnectionDetail defaults) {
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
        public Builder() {}
        public Builder(GetMonitoredResourceDatabaseConnectionDetail defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.connectorId = defaults.connectorId;
    	      this.dbId = defaults.dbId;
    	      this.dbUniqueName = defaults.dbUniqueName;
    	      this.port = defaults.port;
    	      this.protocol = defaults.protocol;
    	      this.serviceName = defaults.serviceName;
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
        public GetMonitoredResourceDatabaseConnectionDetail build() {
            final var o = new GetMonitoredResourceDatabaseConnectionDetail();
            o.connectorId = connectorId;
            o.dbId = dbId;
            o.dbUniqueName = dbUniqueName;
            o.port = port;
            o.protocol = protocol;
            o.serviceName = serviceName;
            return o;
        }
    }
}