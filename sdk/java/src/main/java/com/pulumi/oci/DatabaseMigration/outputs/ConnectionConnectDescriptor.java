// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DatabaseMigration.outputs;

import com.pulumi.core.annotations.CustomType;
import java.lang.Integer;
import java.lang.String;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;

@CustomType
public final class ConnectionConnectDescriptor {
    /**
     * @return (Updatable) Connect String. Required if no host, port nor databaseServiceName were specified. If a Private Endpoint was specified in the Connection, the host entry should be a valid IP address. Supported formats: Easy connect: &lt;host&gt;:&lt;port&gt;/&lt;db_service_name&gt; Long format: (description= (address=(port=&lt;port&gt;)(host=&lt;host&gt;))(connect_data=(service_name=&lt;db_service_name&gt;)))
     * 
     */
    private final @Nullable String connectString;
    /**
     * @return (Updatable) Database service name. Required if no connectString was specified.
     * 
     */
    private final @Nullable String databaseServiceName;
    /**
     * @return (Updatable) Name of the host the SSH key is valid for.
     * 
     */
    private final @Nullable String host;
    /**
     * @return (Updatable) Port of the connect descriptor. Required if no connectString was specified.
     * 
     */
    private final @Nullable Integer port;

    @CustomType.Constructor
    private ConnectionConnectDescriptor(
        @CustomType.Parameter("connectString") @Nullable String connectString,
        @CustomType.Parameter("databaseServiceName") @Nullable String databaseServiceName,
        @CustomType.Parameter("host") @Nullable String host,
        @CustomType.Parameter("port") @Nullable Integer port) {
        this.connectString = connectString;
        this.databaseServiceName = databaseServiceName;
        this.host = host;
        this.port = port;
    }

    /**
     * @return (Updatable) Connect String. Required if no host, port nor databaseServiceName were specified. If a Private Endpoint was specified in the Connection, the host entry should be a valid IP address. Supported formats: Easy connect: &lt;host&gt;:&lt;port&gt;/&lt;db_service_name&gt; Long format: (description= (address=(port=&lt;port&gt;)(host=&lt;host&gt;))(connect_data=(service_name=&lt;db_service_name&gt;)))
     * 
     */
    public Optional<String> connectString() {
        return Optional.ofNullable(this.connectString);
    }
    /**
     * @return (Updatable) Database service name. Required if no connectString was specified.
     * 
     */
    public Optional<String> databaseServiceName() {
        return Optional.ofNullable(this.databaseServiceName);
    }
    /**
     * @return (Updatable) Name of the host the SSH key is valid for.
     * 
     */
    public Optional<String> host() {
        return Optional.ofNullable(this.host);
    }
    /**
     * @return (Updatable) Port of the connect descriptor. Required if no connectString was specified.
     * 
     */
    public Optional<Integer> port() {
        return Optional.ofNullable(this.port);
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(ConnectionConnectDescriptor defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private @Nullable String connectString;
        private @Nullable String databaseServiceName;
        private @Nullable String host;
        private @Nullable Integer port;

        public Builder() {
    	      // Empty
        }

        public Builder(ConnectionConnectDescriptor defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.connectString = defaults.connectString;
    	      this.databaseServiceName = defaults.databaseServiceName;
    	      this.host = defaults.host;
    	      this.port = defaults.port;
        }

        public Builder connectString(@Nullable String connectString) {
            this.connectString = connectString;
            return this;
        }
        public Builder databaseServiceName(@Nullable String databaseServiceName) {
            this.databaseServiceName = databaseServiceName;
            return this;
        }
        public Builder host(@Nullable String host) {
            this.host = host;
            return this;
        }
        public Builder port(@Nullable Integer port) {
            this.port = port;
            return this;
        }        public ConnectionConnectDescriptor build() {
            return new ConnectionConnectDescriptor(connectString, databaseServiceName, host, port);
        }
    }
}
