// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Database.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.Integer;
import java.lang.String;
import java.util.Objects;

@CustomType
public final class GetExternalDatabaseConnectorsExternalDatabaseConnectorConnectionString {
    /**
     * @return The host name of the database.
     * 
     */
    private String hostname;
    /**
     * @return The port used to connect to the database.
     * 
     */
    private Integer port;
    /**
     * @return The protocol used to connect to the database.
     * 
     */
    private String protocol;
    /**
     * @return The name of the service alias used to connect to the database.
     * 
     */
    private String service;

    private GetExternalDatabaseConnectorsExternalDatabaseConnectorConnectionString() {}
    /**
     * @return The host name of the database.
     * 
     */
    public String hostname() {
        return this.hostname;
    }
    /**
     * @return The port used to connect to the database.
     * 
     */
    public Integer port() {
        return this.port;
    }
    /**
     * @return The protocol used to connect to the database.
     * 
     */
    public String protocol() {
        return this.protocol;
    }
    /**
     * @return The name of the service alias used to connect to the database.
     * 
     */
    public String service() {
        return this.service;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetExternalDatabaseConnectorsExternalDatabaseConnectorConnectionString defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String hostname;
        private Integer port;
        private String protocol;
        private String service;
        public Builder() {}
        public Builder(GetExternalDatabaseConnectorsExternalDatabaseConnectorConnectionString defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.hostname = defaults.hostname;
    	      this.port = defaults.port;
    	      this.protocol = defaults.protocol;
    	      this.service = defaults.service;
        }

        @CustomType.Setter
        public Builder hostname(String hostname) {
            if (hostname == null) {
              throw new MissingRequiredPropertyException("GetExternalDatabaseConnectorsExternalDatabaseConnectorConnectionString", "hostname");
            }
            this.hostname = hostname;
            return this;
        }
        @CustomType.Setter
        public Builder port(Integer port) {
            if (port == null) {
              throw new MissingRequiredPropertyException("GetExternalDatabaseConnectorsExternalDatabaseConnectorConnectionString", "port");
            }
            this.port = port;
            return this;
        }
        @CustomType.Setter
        public Builder protocol(String protocol) {
            if (protocol == null) {
              throw new MissingRequiredPropertyException("GetExternalDatabaseConnectorsExternalDatabaseConnectorConnectionString", "protocol");
            }
            this.protocol = protocol;
            return this;
        }
        @CustomType.Setter
        public Builder service(String service) {
            if (service == null) {
              throw new MissingRequiredPropertyException("GetExternalDatabaseConnectorsExternalDatabaseConnectorConnectionString", "service");
            }
            this.service = service;
            return this;
        }
        public GetExternalDatabaseConnectorsExternalDatabaseConnectorConnectionString build() {
            final var _resultValue = new GetExternalDatabaseConnectorsExternalDatabaseConnectorConnectionString();
            _resultValue.hostname = hostname;
            _resultValue.port = port;
            _resultValue.protocol = protocol;
            _resultValue.service = service;
            return _resultValue;
        }
    }
}
