// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.NetworkLoadBalancer.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.NetworkLoadBalancer.inputs.NetworkLoadBalancersBackendSetsUnifiedHealthCheckerDnsArgs;
import java.lang.Integer;
import java.lang.String;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class NetworkLoadBalancersBackendSetsUnifiedHealthCheckerArgs extends com.pulumi.resources.ResourceArgs {

    public static final NetworkLoadBalancersBackendSetsUnifiedHealthCheckerArgs Empty = new NetworkLoadBalancersBackendSetsUnifiedHealthCheckerArgs();

    /**
     * (Updatable) DNS healthcheck configurations.
     * 
     */
    @Import(name="dns")
    private @Nullable Output<NetworkLoadBalancersBackendSetsUnifiedHealthCheckerDnsArgs> dns;

    /**
     * @return (Updatable) DNS healthcheck configurations.
     * 
     */
    public Optional<Output<NetworkLoadBalancersBackendSetsUnifiedHealthCheckerDnsArgs>> dns() {
        return Optional.ofNullable(this.dns);
    }

    /**
     * (Updatable) The interval between health checks, in milliseconds. The default value is 10000 (10 seconds).  Example: `10000`
     * 
     */
    @Import(name="intervalInMillis")
    private @Nullable Output<Integer> intervalInMillis;

    /**
     * @return (Updatable) The interval between health checks, in milliseconds. The default value is 10000 (10 seconds).  Example: `10000`
     * 
     */
    public Optional<Output<Integer>> intervalInMillis() {
        return Optional.ofNullable(this.intervalInMillis);
    }

    /**
     * (Updatable) The backend server port against which to run the health check. If the port is not specified, then the network load balancer uses the port information from the `Backend` object. The port must be specified if the backend port is 0.  Example: `8080`
     * 
     */
    @Import(name="port")
    private @Nullable Output<Integer> port;

    /**
     * @return (Updatable) The backend server port against which to run the health check. If the port is not specified, then the network load balancer uses the port information from the `Backend` object. The port must be specified if the backend port is 0.  Example: `8080`
     * 
     */
    public Optional<Output<Integer>> port() {
        return Optional.ofNullable(this.port);
    }

    /**
     * (Updatable) The protocol the health check must use; either HTTP or HTTPS, or UDP or TCP.  Example: `HTTP`
     * 
     */
    @Import(name="protocol", required=true)
    private Output<String> protocol;

    /**
     * @return (Updatable) The protocol the health check must use; either HTTP or HTTPS, or UDP or TCP.  Example: `HTTP`
     * 
     */
    public Output<String> protocol() {
        return this.protocol;
    }

    /**
     * (Updatable) Base64 encoded pattern to be sent as UDP or TCP health check probe.
     * 
     */
    @Import(name="requestData")
    private @Nullable Output<String> requestData;

    /**
     * @return (Updatable) Base64 encoded pattern to be sent as UDP or TCP health check probe.
     * 
     */
    public Optional<Output<String>> requestData() {
        return Optional.ofNullable(this.requestData);
    }

    /**
     * (Updatable) A regular expression for parsing the response body from the backend server.  Example: `^((?!false).|\s)*$`
     * 
     */
    @Import(name="responseBodyRegex")
    private @Nullable Output<String> responseBodyRegex;

    /**
     * @return (Updatable) A regular expression for parsing the response body from the backend server.  Example: `^((?!false).|\s)*$`
     * 
     */
    public Optional<Output<String>> responseBodyRegex() {
        return Optional.ofNullable(this.responseBodyRegex);
    }

    /**
     * (Updatable) Base64 encoded pattern to be validated as UDP or TCP health check probe response.
     * 
     */
    @Import(name="responseData")
    private @Nullable Output<String> responseData;

    /**
     * @return (Updatable) Base64 encoded pattern to be validated as UDP or TCP health check probe response.
     * 
     */
    public Optional<Output<String>> responseData() {
        return Optional.ofNullable(this.responseData);
    }

    /**
     * (Updatable) The number of retries to attempt before a backend server is considered &#34;unhealthy&#34;. This number also applies when recovering a server to the &#34;healthy&#34; state. The default value is 3.  Example: `3`
     * 
     */
    @Import(name="retries")
    private @Nullable Output<Integer> retries;

    /**
     * @return (Updatable) The number of retries to attempt before a backend server is considered &#34;unhealthy&#34;. This number also applies when recovering a server to the &#34;healthy&#34; state. The default value is 3.  Example: `3`
     * 
     */
    public Optional<Output<Integer>> retries() {
        return Optional.ofNullable(this.retries);
    }

    /**
     * (Updatable) The status code a healthy backend server should return. If you configure the health check policy to use the HTTP protocol, then you can use common HTTP status codes such as &#34;200&#34;.  Example: `200`
     * 
     */
    @Import(name="returnCode")
    private @Nullable Output<Integer> returnCode;

    /**
     * @return (Updatable) The status code a healthy backend server should return. If you configure the health check policy to use the HTTP protocol, then you can use common HTTP status codes such as &#34;200&#34;.  Example: `200`
     * 
     */
    public Optional<Output<Integer>> returnCode() {
        return Optional.ofNullable(this.returnCode);
    }

    /**
     * (Updatable) The maximum time, in milliseconds, to wait for a reply to a health check. A health check is successful only if a reply returns within this timeout period. The default value is 3000 (3 seconds).  Example: `3000`
     * 
     */
    @Import(name="timeoutInMillis")
    private @Nullable Output<Integer> timeoutInMillis;

    /**
     * @return (Updatable) The maximum time, in milliseconds, to wait for a reply to a health check. A health check is successful only if a reply returns within this timeout period. The default value is 3000 (3 seconds).  Example: `3000`
     * 
     */
    public Optional<Output<Integer>> timeoutInMillis() {
        return Optional.ofNullable(this.timeoutInMillis);
    }

    /**
     * (Updatable) The path against which to run the health check.  Example: `/healthcheck`
     * 
     */
    @Import(name="urlPath")
    private @Nullable Output<String> urlPath;

    /**
     * @return (Updatable) The path against which to run the health check.  Example: `/healthcheck`
     * 
     */
    public Optional<Output<String>> urlPath() {
        return Optional.ofNullable(this.urlPath);
    }

    private NetworkLoadBalancersBackendSetsUnifiedHealthCheckerArgs() {}

    private NetworkLoadBalancersBackendSetsUnifiedHealthCheckerArgs(NetworkLoadBalancersBackendSetsUnifiedHealthCheckerArgs $) {
        this.dns = $.dns;
        this.intervalInMillis = $.intervalInMillis;
        this.port = $.port;
        this.protocol = $.protocol;
        this.requestData = $.requestData;
        this.responseBodyRegex = $.responseBodyRegex;
        this.responseData = $.responseData;
        this.retries = $.retries;
        this.returnCode = $.returnCode;
        this.timeoutInMillis = $.timeoutInMillis;
        this.urlPath = $.urlPath;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(NetworkLoadBalancersBackendSetsUnifiedHealthCheckerArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private NetworkLoadBalancersBackendSetsUnifiedHealthCheckerArgs $;

        public Builder() {
            $ = new NetworkLoadBalancersBackendSetsUnifiedHealthCheckerArgs();
        }

        public Builder(NetworkLoadBalancersBackendSetsUnifiedHealthCheckerArgs defaults) {
            $ = new NetworkLoadBalancersBackendSetsUnifiedHealthCheckerArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param dns (Updatable) DNS healthcheck configurations.
         * 
         * @return builder
         * 
         */
        public Builder dns(@Nullable Output<NetworkLoadBalancersBackendSetsUnifiedHealthCheckerDnsArgs> dns) {
            $.dns = dns;
            return this;
        }

        /**
         * @param dns (Updatable) DNS healthcheck configurations.
         * 
         * @return builder
         * 
         */
        public Builder dns(NetworkLoadBalancersBackendSetsUnifiedHealthCheckerDnsArgs dns) {
            return dns(Output.of(dns));
        }

        /**
         * @param intervalInMillis (Updatable) The interval between health checks, in milliseconds. The default value is 10000 (10 seconds).  Example: `10000`
         * 
         * @return builder
         * 
         */
        public Builder intervalInMillis(@Nullable Output<Integer> intervalInMillis) {
            $.intervalInMillis = intervalInMillis;
            return this;
        }

        /**
         * @param intervalInMillis (Updatable) The interval between health checks, in milliseconds. The default value is 10000 (10 seconds).  Example: `10000`
         * 
         * @return builder
         * 
         */
        public Builder intervalInMillis(Integer intervalInMillis) {
            return intervalInMillis(Output.of(intervalInMillis));
        }

        /**
         * @param port (Updatable) The backend server port against which to run the health check. If the port is not specified, then the network load balancer uses the port information from the `Backend` object. The port must be specified if the backend port is 0.  Example: `8080`
         * 
         * @return builder
         * 
         */
        public Builder port(@Nullable Output<Integer> port) {
            $.port = port;
            return this;
        }

        /**
         * @param port (Updatable) The backend server port against which to run the health check. If the port is not specified, then the network load balancer uses the port information from the `Backend` object. The port must be specified if the backend port is 0.  Example: `8080`
         * 
         * @return builder
         * 
         */
        public Builder port(Integer port) {
            return port(Output.of(port));
        }

        /**
         * @param protocol (Updatable) The protocol the health check must use; either HTTP or HTTPS, or UDP or TCP.  Example: `HTTP`
         * 
         * @return builder
         * 
         */
        public Builder protocol(Output<String> protocol) {
            $.protocol = protocol;
            return this;
        }

        /**
         * @param protocol (Updatable) The protocol the health check must use; either HTTP or HTTPS, or UDP or TCP.  Example: `HTTP`
         * 
         * @return builder
         * 
         */
        public Builder protocol(String protocol) {
            return protocol(Output.of(protocol));
        }

        /**
         * @param requestData (Updatable) Base64 encoded pattern to be sent as UDP or TCP health check probe.
         * 
         * @return builder
         * 
         */
        public Builder requestData(@Nullable Output<String> requestData) {
            $.requestData = requestData;
            return this;
        }

        /**
         * @param requestData (Updatable) Base64 encoded pattern to be sent as UDP or TCP health check probe.
         * 
         * @return builder
         * 
         */
        public Builder requestData(String requestData) {
            return requestData(Output.of(requestData));
        }

        /**
         * @param responseBodyRegex (Updatable) A regular expression for parsing the response body from the backend server.  Example: `^((?!false).|\s)*$`
         * 
         * @return builder
         * 
         */
        public Builder responseBodyRegex(@Nullable Output<String> responseBodyRegex) {
            $.responseBodyRegex = responseBodyRegex;
            return this;
        }

        /**
         * @param responseBodyRegex (Updatable) A regular expression for parsing the response body from the backend server.  Example: `^((?!false).|\s)*$`
         * 
         * @return builder
         * 
         */
        public Builder responseBodyRegex(String responseBodyRegex) {
            return responseBodyRegex(Output.of(responseBodyRegex));
        }

        /**
         * @param responseData (Updatable) Base64 encoded pattern to be validated as UDP or TCP health check probe response.
         * 
         * @return builder
         * 
         */
        public Builder responseData(@Nullable Output<String> responseData) {
            $.responseData = responseData;
            return this;
        }

        /**
         * @param responseData (Updatable) Base64 encoded pattern to be validated as UDP or TCP health check probe response.
         * 
         * @return builder
         * 
         */
        public Builder responseData(String responseData) {
            return responseData(Output.of(responseData));
        }

        /**
         * @param retries (Updatable) The number of retries to attempt before a backend server is considered &#34;unhealthy&#34;. This number also applies when recovering a server to the &#34;healthy&#34; state. The default value is 3.  Example: `3`
         * 
         * @return builder
         * 
         */
        public Builder retries(@Nullable Output<Integer> retries) {
            $.retries = retries;
            return this;
        }

        /**
         * @param retries (Updatable) The number of retries to attempt before a backend server is considered &#34;unhealthy&#34;. This number also applies when recovering a server to the &#34;healthy&#34; state. The default value is 3.  Example: `3`
         * 
         * @return builder
         * 
         */
        public Builder retries(Integer retries) {
            return retries(Output.of(retries));
        }

        /**
         * @param returnCode (Updatable) The status code a healthy backend server should return. If you configure the health check policy to use the HTTP protocol, then you can use common HTTP status codes such as &#34;200&#34;.  Example: `200`
         * 
         * @return builder
         * 
         */
        public Builder returnCode(@Nullable Output<Integer> returnCode) {
            $.returnCode = returnCode;
            return this;
        }

        /**
         * @param returnCode (Updatable) The status code a healthy backend server should return. If you configure the health check policy to use the HTTP protocol, then you can use common HTTP status codes such as &#34;200&#34;.  Example: `200`
         * 
         * @return builder
         * 
         */
        public Builder returnCode(Integer returnCode) {
            return returnCode(Output.of(returnCode));
        }

        /**
         * @param timeoutInMillis (Updatable) The maximum time, in milliseconds, to wait for a reply to a health check. A health check is successful only if a reply returns within this timeout period. The default value is 3000 (3 seconds).  Example: `3000`
         * 
         * @return builder
         * 
         */
        public Builder timeoutInMillis(@Nullable Output<Integer> timeoutInMillis) {
            $.timeoutInMillis = timeoutInMillis;
            return this;
        }

        /**
         * @param timeoutInMillis (Updatable) The maximum time, in milliseconds, to wait for a reply to a health check. A health check is successful only if a reply returns within this timeout period. The default value is 3000 (3 seconds).  Example: `3000`
         * 
         * @return builder
         * 
         */
        public Builder timeoutInMillis(Integer timeoutInMillis) {
            return timeoutInMillis(Output.of(timeoutInMillis));
        }

        /**
         * @param urlPath (Updatable) The path against which to run the health check.  Example: `/healthcheck`
         * 
         * @return builder
         * 
         */
        public Builder urlPath(@Nullable Output<String> urlPath) {
            $.urlPath = urlPath;
            return this;
        }

        /**
         * @param urlPath (Updatable) The path against which to run the health check.  Example: `/healthcheck`
         * 
         * @return builder
         * 
         */
        public Builder urlPath(String urlPath) {
            return urlPath(Output.of(urlPath));
        }

        public NetworkLoadBalancersBackendSetsUnifiedHealthCheckerArgs build() {
            if ($.protocol == null) {
                throw new MissingRequiredPropertyException("NetworkLoadBalancersBackendSetsUnifiedHealthCheckerArgs", "protocol");
            }
            return $;
        }
    }

}
