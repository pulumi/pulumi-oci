// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Waas.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import java.lang.Integer;
import java.lang.String;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class PolicyPolicyConfigLoadBalancingMethodArgs extends com.pulumi.resources.ResourceArgs {

    public static final PolicyPolicyConfigLoadBalancingMethodArgs Empty = new PolicyPolicyConfigLoadBalancingMethodArgs();

    /**
     * (Updatable) The domain for which the cookie is set, defaults to WAAS policy domain.
     * 
     */
    @Import(name="domain")
    private @Nullable Output<String> domain;

    /**
     * @return (Updatable) The domain for which the cookie is set, defaults to WAAS policy domain.
     * 
     */
    public Optional<Output<String>> domain() {
        return Optional.ofNullable(this.domain);
    }

    /**
     * (Updatable) The time for which a browser should keep the cookie in seconds. Empty value will cause the cookie to expire at the end of a browser session.
     * 
     */
    @Import(name="expirationTimeInSeconds")
    private @Nullable Output<Integer> expirationTimeInSeconds;

    /**
     * @return (Updatable) The time for which a browser should keep the cookie in seconds. Empty value will cause the cookie to expire at the end of a browser session.
     * 
     */
    public Optional<Output<Integer>> expirationTimeInSeconds() {
        return Optional.ofNullable(this.expirationTimeInSeconds);
    }

    /**
     * (Updatable) Load balancing methods are algorithms used to efficiently distribute traffic among origin servers.
     * * **[IP_HASH](https://www.terraform.io/iaas/api/#/en/waas/latest/datatypes/IPHashLoadBalancingMethod):** All the incoming requests from the same client IP address should go to the same content origination server. IP_HASH load balancing method uses origin weights when choosing which origin should the hash be assigned to initially.
     * * **[ROUND_ROBIN](https://www.terraform.io/iaas/api/#/en/waas/latest/datatypes/RoundRobinLoadBalancingMethod):** Forwards requests sequentially to the available origin servers. The first request - to the first origin server, the second request - to the next origin server, and so on. After it sends a request to the last origin server, it starts again with the first origin server. When using weights on origins, Weighted Round Robin assigns more requests to origins with a greater weight. Over a period of time, origins will receive a number of requests in proportion to their weight.
     * * **[STICKY_COOKIE](https://www.terraform.io/iaas/api/#/en/waas/latest/datatypes/StickyCookieLoadBalancingMethod):** Adds a session cookie to the first response from the origin server and identifies the server that sent the response. The client&#39;s next request contains the cookie value, and nginx routes the request to the origin server that responded to the first request. STICKY_COOKIE load balancing method falls back to Round Robin for the first request.
     * 
     */
    @Import(name="method", required=true)
    private Output<String> method;

    /**
     * @return (Updatable) Load balancing methods are algorithms used to efficiently distribute traffic among origin servers.
     * * **[IP_HASH](https://www.terraform.io/iaas/api/#/en/waas/latest/datatypes/IPHashLoadBalancingMethod):** All the incoming requests from the same client IP address should go to the same content origination server. IP_HASH load balancing method uses origin weights when choosing which origin should the hash be assigned to initially.
     * * **[ROUND_ROBIN](https://www.terraform.io/iaas/api/#/en/waas/latest/datatypes/RoundRobinLoadBalancingMethod):** Forwards requests sequentially to the available origin servers. The first request - to the first origin server, the second request - to the next origin server, and so on. After it sends a request to the last origin server, it starts again with the first origin server. When using weights on origins, Weighted Round Robin assigns more requests to origins with a greater weight. Over a period of time, origins will receive a number of requests in proportion to their weight.
     * * **[STICKY_COOKIE](https://www.terraform.io/iaas/api/#/en/waas/latest/datatypes/StickyCookieLoadBalancingMethod):** Adds a session cookie to the first response from the origin server and identifies the server that sent the response. The client&#39;s next request contains the cookie value, and nginx routes the request to the origin server that responded to the first request. STICKY_COOKIE load balancing method falls back to Round Robin for the first request.
     * 
     */
    public Output<String> method() {
        return this.method;
    }

    /**
     * (Updatable) The unique name of the whitelist.
     * 
     */
    @Import(name="name")
    private @Nullable Output<String> name;

    /**
     * @return (Updatable) The unique name of the whitelist.
     * 
     */
    public Optional<Output<String>> name() {
        return Optional.ofNullable(this.name);
    }

    private PolicyPolicyConfigLoadBalancingMethodArgs() {}

    private PolicyPolicyConfigLoadBalancingMethodArgs(PolicyPolicyConfigLoadBalancingMethodArgs $) {
        this.domain = $.domain;
        this.expirationTimeInSeconds = $.expirationTimeInSeconds;
        this.method = $.method;
        this.name = $.name;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(PolicyPolicyConfigLoadBalancingMethodArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private PolicyPolicyConfigLoadBalancingMethodArgs $;

        public Builder() {
            $ = new PolicyPolicyConfigLoadBalancingMethodArgs();
        }

        public Builder(PolicyPolicyConfigLoadBalancingMethodArgs defaults) {
            $ = new PolicyPolicyConfigLoadBalancingMethodArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param domain (Updatable) The domain for which the cookie is set, defaults to WAAS policy domain.
         * 
         * @return builder
         * 
         */
        public Builder domain(@Nullable Output<String> domain) {
            $.domain = domain;
            return this;
        }

        /**
         * @param domain (Updatable) The domain for which the cookie is set, defaults to WAAS policy domain.
         * 
         * @return builder
         * 
         */
        public Builder domain(String domain) {
            return domain(Output.of(domain));
        }

        /**
         * @param expirationTimeInSeconds (Updatable) The time for which a browser should keep the cookie in seconds. Empty value will cause the cookie to expire at the end of a browser session.
         * 
         * @return builder
         * 
         */
        public Builder expirationTimeInSeconds(@Nullable Output<Integer> expirationTimeInSeconds) {
            $.expirationTimeInSeconds = expirationTimeInSeconds;
            return this;
        }

        /**
         * @param expirationTimeInSeconds (Updatable) The time for which a browser should keep the cookie in seconds. Empty value will cause the cookie to expire at the end of a browser session.
         * 
         * @return builder
         * 
         */
        public Builder expirationTimeInSeconds(Integer expirationTimeInSeconds) {
            return expirationTimeInSeconds(Output.of(expirationTimeInSeconds));
        }

        /**
         * @param method (Updatable) Load balancing methods are algorithms used to efficiently distribute traffic among origin servers.
         * * **[IP_HASH](https://www.terraform.io/iaas/api/#/en/waas/latest/datatypes/IPHashLoadBalancingMethod):** All the incoming requests from the same client IP address should go to the same content origination server. IP_HASH load balancing method uses origin weights when choosing which origin should the hash be assigned to initially.
         * * **[ROUND_ROBIN](https://www.terraform.io/iaas/api/#/en/waas/latest/datatypes/RoundRobinLoadBalancingMethod):** Forwards requests sequentially to the available origin servers. The first request - to the first origin server, the second request - to the next origin server, and so on. After it sends a request to the last origin server, it starts again with the first origin server. When using weights on origins, Weighted Round Robin assigns more requests to origins with a greater weight. Over a period of time, origins will receive a number of requests in proportion to their weight.
         * * **[STICKY_COOKIE](https://www.terraform.io/iaas/api/#/en/waas/latest/datatypes/StickyCookieLoadBalancingMethod):** Adds a session cookie to the first response from the origin server and identifies the server that sent the response. The client&#39;s next request contains the cookie value, and nginx routes the request to the origin server that responded to the first request. STICKY_COOKIE load balancing method falls back to Round Robin for the first request.
         * 
         * @return builder
         * 
         */
        public Builder method(Output<String> method) {
            $.method = method;
            return this;
        }

        /**
         * @param method (Updatable) Load balancing methods are algorithms used to efficiently distribute traffic among origin servers.
         * * **[IP_HASH](https://www.terraform.io/iaas/api/#/en/waas/latest/datatypes/IPHashLoadBalancingMethod):** All the incoming requests from the same client IP address should go to the same content origination server. IP_HASH load balancing method uses origin weights when choosing which origin should the hash be assigned to initially.
         * * **[ROUND_ROBIN](https://www.terraform.io/iaas/api/#/en/waas/latest/datatypes/RoundRobinLoadBalancingMethod):** Forwards requests sequentially to the available origin servers. The first request - to the first origin server, the second request - to the next origin server, and so on. After it sends a request to the last origin server, it starts again with the first origin server. When using weights on origins, Weighted Round Robin assigns more requests to origins with a greater weight. Over a period of time, origins will receive a number of requests in proportion to their weight.
         * * **[STICKY_COOKIE](https://www.terraform.io/iaas/api/#/en/waas/latest/datatypes/StickyCookieLoadBalancingMethod):** Adds a session cookie to the first response from the origin server and identifies the server that sent the response. The client&#39;s next request contains the cookie value, and nginx routes the request to the origin server that responded to the first request. STICKY_COOKIE load balancing method falls back to Round Robin for the first request.
         * 
         * @return builder
         * 
         */
        public Builder method(String method) {
            return method(Output.of(method));
        }

        /**
         * @param name (Updatable) The unique name of the whitelist.
         * 
         * @return builder
         * 
         */
        public Builder name(@Nullable Output<String> name) {
            $.name = name;
            return this;
        }

        /**
         * @param name (Updatable) The unique name of the whitelist.
         * 
         * @return builder
         * 
         */
        public Builder name(String name) {
            return name(Output.of(name));
        }

        public PolicyPolicyConfigLoadBalancingMethodArgs build() {
            $.method = Objects.requireNonNull($.method, "expected parameter 'method' to be non-null");
            return $;
        }
    }

}