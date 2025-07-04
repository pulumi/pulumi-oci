// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.LoadBalancer.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.Boolean;
import java.lang.Integer;
import java.lang.String;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;

@CustomType
public final class GetBackendsBackend {
    /**
     * @return The name of the backend set associated with the backend servers.  Example: `example_backend_set`
     * 
     */
    private String backendsetName;
    /**
     * @return Whether the load balancer should treat this server as a backup unit. If `true`, the load balancer forwards no ingress traffic to this backend server unless all other backend servers not marked as &#34;backup&#34; fail the health check policy.
     * 
     */
    private @Nullable Boolean backup;
    /**
     * @return Whether the load balancer should drain this server. Servers marked &#34;drain&#34; receive no new incoming traffic.  Example: `false`
     * 
     */
    private Boolean drain;
    /**
     * @return The IP address of the backend server.  Example: `10.0.0.3`
     * 
     */
    private String ipAddress;
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the load balancer associated with the backend set and servers.
     * 
     */
    private String loadBalancerId;
    /**
     * @return The maximum number of simultaneous connections the load balancer can make to the backend. If this is not set or set to 0 then the maximum number of simultaneous connections the load balancer can make to the backend is unlimited.  Example: `300`
     * 
     */
    private Integer maxConnections;
    /**
     * @return A read-only field showing the IP address and port that uniquely identify this backend server in the backend set.  Example: `10.0.0.3:8080`
     * 
     */
    private String name;
    /**
     * @return Whether the load balancer should treat this server as offline. Offline servers receive no incoming traffic.  Example: `false`
     * 
     */
    private Boolean offline;
    /**
     * @return The communication port for the backend server.  Example: `8080`
     * 
     */
    private Integer port;
    private String state;
    /**
     * @return The load balancing policy weight assigned to the server. Backend servers with a higher weight receive a larger proportion of incoming traffic. For example, a server weighted &#39;3&#39; receives 3 times the number of new connections as a server weighted &#39;1&#39;. For more information on load balancing policies, see [How Load Balancing Policies Work](https://docs.cloud.oracle.com/iaas/Content/Balance/Reference/lbpolicies.htm).  Example: `3`
     * 
     */
    private Integer weight;

    private GetBackendsBackend() {}
    /**
     * @return The name of the backend set associated with the backend servers.  Example: `example_backend_set`
     * 
     */
    public String backendsetName() {
        return this.backendsetName;
    }
    /**
     * @return Whether the load balancer should treat this server as a backup unit. If `true`, the load balancer forwards no ingress traffic to this backend server unless all other backend servers not marked as &#34;backup&#34; fail the health check policy.
     * 
     */
    public Optional<Boolean> backup() {
        return Optional.ofNullable(this.backup);
    }
    /**
     * @return Whether the load balancer should drain this server. Servers marked &#34;drain&#34; receive no new incoming traffic.  Example: `false`
     * 
     */
    public Boolean drain() {
        return this.drain;
    }
    /**
     * @return The IP address of the backend server.  Example: `10.0.0.3`
     * 
     */
    public String ipAddress() {
        return this.ipAddress;
    }
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the load balancer associated with the backend set and servers.
     * 
     */
    public String loadBalancerId() {
        return this.loadBalancerId;
    }
    /**
     * @return The maximum number of simultaneous connections the load balancer can make to the backend. If this is not set or set to 0 then the maximum number of simultaneous connections the load balancer can make to the backend is unlimited.  Example: `300`
     * 
     */
    public Integer maxConnections() {
        return this.maxConnections;
    }
    /**
     * @return A read-only field showing the IP address and port that uniquely identify this backend server in the backend set.  Example: `10.0.0.3:8080`
     * 
     */
    public String name() {
        return this.name;
    }
    /**
     * @return Whether the load balancer should treat this server as offline. Offline servers receive no incoming traffic.  Example: `false`
     * 
     */
    public Boolean offline() {
        return this.offline;
    }
    /**
     * @return The communication port for the backend server.  Example: `8080`
     * 
     */
    public Integer port() {
        return this.port;
    }
    public String state() {
        return this.state;
    }
    /**
     * @return The load balancing policy weight assigned to the server. Backend servers with a higher weight receive a larger proportion of incoming traffic. For example, a server weighted &#39;3&#39; receives 3 times the number of new connections as a server weighted &#39;1&#39;. For more information on load balancing policies, see [How Load Balancing Policies Work](https://docs.cloud.oracle.com/iaas/Content/Balance/Reference/lbpolicies.htm).  Example: `3`
     * 
     */
    public Integer weight() {
        return this.weight;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetBackendsBackend defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String backendsetName;
        private @Nullable Boolean backup;
        private Boolean drain;
        private String ipAddress;
        private String loadBalancerId;
        private Integer maxConnections;
        private String name;
        private Boolean offline;
        private Integer port;
        private String state;
        private Integer weight;
        public Builder() {}
        public Builder(GetBackendsBackend defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.backendsetName = defaults.backendsetName;
    	      this.backup = defaults.backup;
    	      this.drain = defaults.drain;
    	      this.ipAddress = defaults.ipAddress;
    	      this.loadBalancerId = defaults.loadBalancerId;
    	      this.maxConnections = defaults.maxConnections;
    	      this.name = defaults.name;
    	      this.offline = defaults.offline;
    	      this.port = defaults.port;
    	      this.state = defaults.state;
    	      this.weight = defaults.weight;
        }

        @CustomType.Setter
        public Builder backendsetName(String backendsetName) {
            if (backendsetName == null) {
              throw new MissingRequiredPropertyException("GetBackendsBackend", "backendsetName");
            }
            this.backendsetName = backendsetName;
            return this;
        }
        @CustomType.Setter
        public Builder backup(@Nullable Boolean backup) {

            this.backup = backup;
            return this;
        }
        @CustomType.Setter
        public Builder drain(Boolean drain) {
            if (drain == null) {
              throw new MissingRequiredPropertyException("GetBackendsBackend", "drain");
            }
            this.drain = drain;
            return this;
        }
        @CustomType.Setter
        public Builder ipAddress(String ipAddress) {
            if (ipAddress == null) {
              throw new MissingRequiredPropertyException("GetBackendsBackend", "ipAddress");
            }
            this.ipAddress = ipAddress;
            return this;
        }
        @CustomType.Setter
        public Builder loadBalancerId(String loadBalancerId) {
            if (loadBalancerId == null) {
              throw new MissingRequiredPropertyException("GetBackendsBackend", "loadBalancerId");
            }
            this.loadBalancerId = loadBalancerId;
            return this;
        }
        @CustomType.Setter
        public Builder maxConnections(Integer maxConnections) {
            if (maxConnections == null) {
              throw new MissingRequiredPropertyException("GetBackendsBackend", "maxConnections");
            }
            this.maxConnections = maxConnections;
            return this;
        }
        @CustomType.Setter
        public Builder name(String name) {
            if (name == null) {
              throw new MissingRequiredPropertyException("GetBackendsBackend", "name");
            }
            this.name = name;
            return this;
        }
        @CustomType.Setter
        public Builder offline(Boolean offline) {
            if (offline == null) {
              throw new MissingRequiredPropertyException("GetBackendsBackend", "offline");
            }
            this.offline = offline;
            return this;
        }
        @CustomType.Setter
        public Builder port(Integer port) {
            if (port == null) {
              throw new MissingRequiredPropertyException("GetBackendsBackend", "port");
            }
            this.port = port;
            return this;
        }
        @CustomType.Setter
        public Builder state(String state) {
            if (state == null) {
              throw new MissingRequiredPropertyException("GetBackendsBackend", "state");
            }
            this.state = state;
            return this;
        }
        @CustomType.Setter
        public Builder weight(Integer weight) {
            if (weight == null) {
              throw new MissingRequiredPropertyException("GetBackendsBackend", "weight");
            }
            this.weight = weight;
            return this;
        }
        public GetBackendsBackend build() {
            final var _resultValue = new GetBackendsBackend();
            _resultValue.backendsetName = backendsetName;
            _resultValue.backup = backup;
            _resultValue.drain = drain;
            _resultValue.ipAddress = ipAddress;
            _resultValue.loadBalancerId = loadBalancerId;
            _resultValue.maxConnections = maxConnections;
            _resultValue.name = name;
            _resultValue.offline = offline;
            _resultValue.port = port;
            _resultValue.state = state;
            _resultValue.weight = weight;
            return _resultValue;
        }
    }
}
