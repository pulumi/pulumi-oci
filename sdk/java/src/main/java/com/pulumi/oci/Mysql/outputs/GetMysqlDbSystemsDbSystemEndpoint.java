// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Mysql.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.Integer;
import java.lang.String;
import java.util.List;
import java.util.Objects;

@CustomType
public final class GetMysqlDbSystemsDbSystemEndpoint {
    /**
     * @return The network address of the DB System.
     * 
     */
    private String hostname;
    /**
     * @return The IP address the DB System is configured to listen on. A private IP address of the primary endpoint of the DB System. Must be an available IP address within the subnet&#39;s CIDR. This will be a &#34;dotted-quad&#34; style IPv4 address.
     * 
     */
    private String ipAddress;
    /**
     * @return The access modes from the client that this endpoint supports.
     * 
     */
    private List<String> modes;
    /**
     * @return The port for REST to listen on. Supported port numbers are 443 and from 1024 to 65535.
     * 
     */
    private Integer port;
    /**
     * @return The network port on which X Plugin listens for TCP/IP connections. This is the X Plugin equivalent of port.
     * 
     */
    private Integer portX;
    /**
     * @return The OCID of the resource that this endpoint is attached to.
     * 
     */
    private String resourceId;
    /**
     * @return The type of endpoint that clients and connectors can connect to.
     * 
     */
    private String resourceType;
    /**
     * @return The state of the endpoints, as far as it can seen from the DB System. There may be some inconsistency with the actual state of the MySQL service.
     * 
     */
    private String status;
    /**
     * @return Additional information about the current endpoint status.
     * 
     */
    private String statusDetails;

    private GetMysqlDbSystemsDbSystemEndpoint() {}
    /**
     * @return The network address of the DB System.
     * 
     */
    public String hostname() {
        return this.hostname;
    }
    /**
     * @return The IP address the DB System is configured to listen on. A private IP address of the primary endpoint of the DB System. Must be an available IP address within the subnet&#39;s CIDR. This will be a &#34;dotted-quad&#34; style IPv4 address.
     * 
     */
    public String ipAddress() {
        return this.ipAddress;
    }
    /**
     * @return The access modes from the client that this endpoint supports.
     * 
     */
    public List<String> modes() {
        return this.modes;
    }
    /**
     * @return The port for REST to listen on. Supported port numbers are 443 and from 1024 to 65535.
     * 
     */
    public Integer port() {
        return this.port;
    }
    /**
     * @return The network port on which X Plugin listens for TCP/IP connections. This is the X Plugin equivalent of port.
     * 
     */
    public Integer portX() {
        return this.portX;
    }
    /**
     * @return The OCID of the resource that this endpoint is attached to.
     * 
     */
    public String resourceId() {
        return this.resourceId;
    }
    /**
     * @return The type of endpoint that clients and connectors can connect to.
     * 
     */
    public String resourceType() {
        return this.resourceType;
    }
    /**
     * @return The state of the endpoints, as far as it can seen from the DB System. There may be some inconsistency with the actual state of the MySQL service.
     * 
     */
    public String status() {
        return this.status;
    }
    /**
     * @return Additional information about the current endpoint status.
     * 
     */
    public String statusDetails() {
        return this.statusDetails;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetMysqlDbSystemsDbSystemEndpoint defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String hostname;
        private String ipAddress;
        private List<String> modes;
        private Integer port;
        private Integer portX;
        private String resourceId;
        private String resourceType;
        private String status;
        private String statusDetails;
        public Builder() {}
        public Builder(GetMysqlDbSystemsDbSystemEndpoint defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.hostname = defaults.hostname;
    	      this.ipAddress = defaults.ipAddress;
    	      this.modes = defaults.modes;
    	      this.port = defaults.port;
    	      this.portX = defaults.portX;
    	      this.resourceId = defaults.resourceId;
    	      this.resourceType = defaults.resourceType;
    	      this.status = defaults.status;
    	      this.statusDetails = defaults.statusDetails;
        }

        @CustomType.Setter
        public Builder hostname(String hostname) {
            if (hostname == null) {
              throw new MissingRequiredPropertyException("GetMysqlDbSystemsDbSystemEndpoint", "hostname");
            }
            this.hostname = hostname;
            return this;
        }
        @CustomType.Setter
        public Builder ipAddress(String ipAddress) {
            if (ipAddress == null) {
              throw new MissingRequiredPropertyException("GetMysqlDbSystemsDbSystemEndpoint", "ipAddress");
            }
            this.ipAddress = ipAddress;
            return this;
        }
        @CustomType.Setter
        public Builder modes(List<String> modes) {
            if (modes == null) {
              throw new MissingRequiredPropertyException("GetMysqlDbSystemsDbSystemEndpoint", "modes");
            }
            this.modes = modes;
            return this;
        }
        public Builder modes(String... modes) {
            return modes(List.of(modes));
        }
        @CustomType.Setter
        public Builder port(Integer port) {
            if (port == null) {
              throw new MissingRequiredPropertyException("GetMysqlDbSystemsDbSystemEndpoint", "port");
            }
            this.port = port;
            return this;
        }
        @CustomType.Setter
        public Builder portX(Integer portX) {
            if (portX == null) {
              throw new MissingRequiredPropertyException("GetMysqlDbSystemsDbSystemEndpoint", "portX");
            }
            this.portX = portX;
            return this;
        }
        @CustomType.Setter
        public Builder resourceId(String resourceId) {
            if (resourceId == null) {
              throw new MissingRequiredPropertyException("GetMysqlDbSystemsDbSystemEndpoint", "resourceId");
            }
            this.resourceId = resourceId;
            return this;
        }
        @CustomType.Setter
        public Builder resourceType(String resourceType) {
            if (resourceType == null) {
              throw new MissingRequiredPropertyException("GetMysqlDbSystemsDbSystemEndpoint", "resourceType");
            }
            this.resourceType = resourceType;
            return this;
        }
        @CustomType.Setter
        public Builder status(String status) {
            if (status == null) {
              throw new MissingRequiredPropertyException("GetMysqlDbSystemsDbSystemEndpoint", "status");
            }
            this.status = status;
            return this;
        }
        @CustomType.Setter
        public Builder statusDetails(String statusDetails) {
            if (statusDetails == null) {
              throw new MissingRequiredPropertyException("GetMysqlDbSystemsDbSystemEndpoint", "statusDetails");
            }
            this.statusDetails = statusDetails;
            return this;
        }
        public GetMysqlDbSystemsDbSystemEndpoint build() {
            final var _resultValue = new GetMysqlDbSystemsDbSystemEndpoint();
            _resultValue.hostname = hostname;
            _resultValue.ipAddress = ipAddress;
            _resultValue.modes = modes;
            _resultValue.port = port;
            _resultValue.portX = portX;
            _resultValue.resourceId = resourceId;
            _resultValue.resourceType = resourceType;
            _resultValue.status = status;
            _resultValue.statusDetails = statusDetails;
            return _resultValue;
        }
    }
}
