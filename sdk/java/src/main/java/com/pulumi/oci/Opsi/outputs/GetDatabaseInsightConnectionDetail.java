// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Opsi.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.Opsi.outputs.GetDatabaseInsightConnectionDetailHost;
import java.lang.Integer;
import java.lang.String;
import java.util.List;
import java.util.Objects;

@CustomType
public final class GetDatabaseInsightConnectionDetail {
    /**
     * @return Name of the listener host that will be used to create the connect string to the database.
     * 
     */
    private String hostName;
    /**
     * @return List of hosts and port for private endpoint accessed database resource.
     * 
     */
    private List<GetDatabaseInsightConnectionDetailHost> hosts;
    /**
     * @return Listener port number used for connection requests.
     * 
     */
    private Integer port;
    /**
     * @return Protocol used for connection requests for private endpoint accssed database resource.
     * 
     */
    private String protocol;
    /**
     * @return Database service name used for connection requests.
     * 
     */
    private String serviceName;

    private GetDatabaseInsightConnectionDetail() {}
    /**
     * @return Name of the listener host that will be used to create the connect string to the database.
     * 
     */
    public String hostName() {
        return this.hostName;
    }
    /**
     * @return List of hosts and port for private endpoint accessed database resource.
     * 
     */
    public List<GetDatabaseInsightConnectionDetailHost> hosts() {
        return this.hosts;
    }
    /**
     * @return Listener port number used for connection requests.
     * 
     */
    public Integer port() {
        return this.port;
    }
    /**
     * @return Protocol used for connection requests for private endpoint accssed database resource.
     * 
     */
    public String protocol() {
        return this.protocol;
    }
    /**
     * @return Database service name used for connection requests.
     * 
     */
    public String serviceName() {
        return this.serviceName;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetDatabaseInsightConnectionDetail defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String hostName;
        private List<GetDatabaseInsightConnectionDetailHost> hosts;
        private Integer port;
        private String protocol;
        private String serviceName;
        public Builder() {}
        public Builder(GetDatabaseInsightConnectionDetail defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.hostName = defaults.hostName;
    	      this.hosts = defaults.hosts;
    	      this.port = defaults.port;
    	      this.protocol = defaults.protocol;
    	      this.serviceName = defaults.serviceName;
        }

        @CustomType.Setter
        public Builder hostName(String hostName) {
            if (hostName == null) {
              throw new MissingRequiredPropertyException("GetDatabaseInsightConnectionDetail", "hostName");
            }
            this.hostName = hostName;
            return this;
        }
        @CustomType.Setter
        public Builder hosts(List<GetDatabaseInsightConnectionDetailHost> hosts) {
            if (hosts == null) {
              throw new MissingRequiredPropertyException("GetDatabaseInsightConnectionDetail", "hosts");
            }
            this.hosts = hosts;
            return this;
        }
        public Builder hosts(GetDatabaseInsightConnectionDetailHost... hosts) {
            return hosts(List.of(hosts));
        }
        @CustomType.Setter
        public Builder port(Integer port) {
            if (port == null) {
              throw new MissingRequiredPropertyException("GetDatabaseInsightConnectionDetail", "port");
            }
            this.port = port;
            return this;
        }
        @CustomType.Setter
        public Builder protocol(String protocol) {
            if (protocol == null) {
              throw new MissingRequiredPropertyException("GetDatabaseInsightConnectionDetail", "protocol");
            }
            this.protocol = protocol;
            return this;
        }
        @CustomType.Setter
        public Builder serviceName(String serviceName) {
            if (serviceName == null) {
              throw new MissingRequiredPropertyException("GetDatabaseInsightConnectionDetail", "serviceName");
            }
            this.serviceName = serviceName;
            return this;
        }
        public GetDatabaseInsightConnectionDetail build() {
            final var _resultValue = new GetDatabaseInsightConnectionDetail();
            _resultValue.hostName = hostName;
            _resultValue.hosts = hosts;
            _resultValue.port = port;
            _resultValue.protocol = protocol;
            _resultValue.serviceName = serviceName;
            return _resultValue;
        }
    }
}
