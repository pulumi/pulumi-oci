// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.ApiGateway.outputs;

import com.pulumi.core.annotations.CustomType;
import java.lang.Integer;
import java.lang.String;
import java.util.Objects;

@CustomType
public final class GetDeploymentSpecificationRouteResponsePolicyResponseCacheStore {
    /**
     * @return Sets the number of seconds for a response from a backend being stored in the Response Cache before it expires.
     * 
     */
    private Integer timeToLiveInSeconds;
    /**
     * @return Type of the Response Cache Store Policy.
     * 
     */
    private String type;

    private GetDeploymentSpecificationRouteResponsePolicyResponseCacheStore() {}
    /**
     * @return Sets the number of seconds for a response from a backend being stored in the Response Cache before it expires.
     * 
     */
    public Integer timeToLiveInSeconds() {
        return this.timeToLiveInSeconds;
    }
    /**
     * @return Type of the Response Cache Store Policy.
     * 
     */
    public String type() {
        return this.type;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetDeploymentSpecificationRouteResponsePolicyResponseCacheStore defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private Integer timeToLiveInSeconds;
        private String type;
        public Builder() {}
        public Builder(GetDeploymentSpecificationRouteResponsePolicyResponseCacheStore defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.timeToLiveInSeconds = defaults.timeToLiveInSeconds;
    	      this.type = defaults.type;
        }

        @CustomType.Setter
        public Builder timeToLiveInSeconds(Integer timeToLiveInSeconds) {
            this.timeToLiveInSeconds = Objects.requireNonNull(timeToLiveInSeconds);
            return this;
        }
        @CustomType.Setter
        public Builder type(String type) {
            this.type = Objects.requireNonNull(type);
            return this;
        }
        public GetDeploymentSpecificationRouteResponsePolicyResponseCacheStore build() {
            final var o = new GetDeploymentSpecificationRouteResponsePolicyResponseCacheStore();
            o.timeToLiveInSeconds = timeToLiveInSeconds;
            o.type = type;
            return o;
        }
    }
}