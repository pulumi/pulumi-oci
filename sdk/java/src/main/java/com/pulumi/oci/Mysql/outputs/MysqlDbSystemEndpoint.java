// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Mysql.outputs;

import com.pulumi.core.annotations.CustomType;
import java.lang.Integer;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;

@CustomType
public final class MysqlDbSystemEndpoint {
    /**
     * @return The network address of the DB System.
     * 
     */
    private @Nullable String hostname;
    /**
     * @return The IP address the DB System is configured to listen on. A private IP address of your choice to assign to the primary endpoint of the DB System. Must be an available IP address within the subnet&#39;s CIDR. If you don&#39;t specify a value, Oracle automatically assigns a private IP address from the subnet. This should be a &#34;dotted-quad&#34; style IPv4 address.
     * 
     */
    private @Nullable String ipAddress;
    /**
     * @return The access modes from the client that this endpoint supports.
     * 
     */
    private @Nullable List<String> modes;
    /**
     * @return The port for primary endpoint of the DB System to listen on.
     * 
     */
    private @Nullable Integer port;
    /**
     * @return The TCP network port on which X Plugin listens for connections. This is the X Plugin equivalent of port.
     * 
     */
    private @Nullable Integer portX;
    /**
     * @return The state of the endpoints, as far as it can seen from the DB System. There may be some inconsistency with the actual state of the MySQL service.
     * 
     */
    private @Nullable String status;
    /**
     * @return Additional information about the current endpoint status.
     * 
     */
    private @Nullable String statusDetails;

    private MysqlDbSystemEndpoint() {}
    /**
     * @return The network address of the DB System.
     * 
     */
    public Optional<String> hostname() {
        return Optional.ofNullable(this.hostname);
    }
    /**
     * @return The IP address the DB System is configured to listen on. A private IP address of your choice to assign to the primary endpoint of the DB System. Must be an available IP address within the subnet&#39;s CIDR. If you don&#39;t specify a value, Oracle automatically assigns a private IP address from the subnet. This should be a &#34;dotted-quad&#34; style IPv4 address.
     * 
     */
    public Optional<String> ipAddress() {
        return Optional.ofNullable(this.ipAddress);
    }
    /**
     * @return The access modes from the client that this endpoint supports.
     * 
     */
    public List<String> modes() {
        return this.modes == null ? List.of() : this.modes;
    }
    /**
     * @return The port for primary endpoint of the DB System to listen on.
     * 
     */
    public Optional<Integer> port() {
        return Optional.ofNullable(this.port);
    }
    /**
     * @return The TCP network port on which X Plugin listens for connections. This is the X Plugin equivalent of port.
     * 
     */
    public Optional<Integer> portX() {
        return Optional.ofNullable(this.portX);
    }
    /**
     * @return The state of the endpoints, as far as it can seen from the DB System. There may be some inconsistency with the actual state of the MySQL service.
     * 
     */
    public Optional<String> status() {
        return Optional.ofNullable(this.status);
    }
    /**
     * @return Additional information about the current endpoint status.
     * 
     */
    public Optional<String> statusDetails() {
        return Optional.ofNullable(this.statusDetails);
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(MysqlDbSystemEndpoint defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private @Nullable String hostname;
        private @Nullable String ipAddress;
        private @Nullable List<String> modes;
        private @Nullable Integer port;
        private @Nullable Integer portX;
        private @Nullable String status;
        private @Nullable String statusDetails;
        public Builder() {}
        public Builder(MysqlDbSystemEndpoint defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.hostname = defaults.hostname;
    	      this.ipAddress = defaults.ipAddress;
    	      this.modes = defaults.modes;
    	      this.port = defaults.port;
    	      this.portX = defaults.portX;
    	      this.status = defaults.status;
    	      this.statusDetails = defaults.statusDetails;
        }

        @CustomType.Setter
        public Builder hostname(@Nullable String hostname) {
            this.hostname = hostname;
            return this;
        }
        @CustomType.Setter
        public Builder ipAddress(@Nullable String ipAddress) {
            this.ipAddress = ipAddress;
            return this;
        }
        @CustomType.Setter
        public Builder modes(@Nullable List<String> modes) {
            this.modes = modes;
            return this;
        }
        public Builder modes(String... modes) {
            return modes(List.of(modes));
        }
        @CustomType.Setter
        public Builder port(@Nullable Integer port) {
            this.port = port;
            return this;
        }
        @CustomType.Setter
        public Builder portX(@Nullable Integer portX) {
            this.portX = portX;
            return this;
        }
        @CustomType.Setter
        public Builder status(@Nullable String status) {
            this.status = status;
            return this;
        }
        @CustomType.Setter
        public Builder statusDetails(@Nullable String statusDetails) {
            this.statusDetails = statusDetails;
            return this;
        }
        public MysqlDbSystemEndpoint build() {
            final var o = new MysqlDbSystemEndpoint();
            o.hostname = hostname;
            o.ipAddress = ipAddress;
            o.modes = modes;
            o.port = port;
            o.portX = portX;
            o.status = status;
            o.statusDetails = statusDetails;
            return o;
        }
    }
}