// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.ApiGateway.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.Integer;
import java.lang.String;
import java.util.Objects;

@CustomType
public final class GetApiDeploymentSpecificationRouteResponsePolicyResponseCacheStore {
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

    private GetApiDeploymentSpecificationRouteResponsePolicyResponseCacheStore() {}
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

    public static Builder builder(GetApiDeploymentSpecificationRouteResponsePolicyResponseCacheStore defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private Integer timeToLiveInSeconds;
        private String type;
        public Builder() {}
        public Builder(GetApiDeploymentSpecificationRouteResponsePolicyResponseCacheStore defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.timeToLiveInSeconds = defaults.timeToLiveInSeconds;
    	      this.type = defaults.type;
        }

        @CustomType.Setter
        public Builder timeToLiveInSeconds(Integer timeToLiveInSeconds) {
            if (timeToLiveInSeconds == null) {
              throw new MissingRequiredPropertyException("GetApiDeploymentSpecificationRouteResponsePolicyResponseCacheStore", "timeToLiveInSeconds");
            }
            this.timeToLiveInSeconds = timeToLiveInSeconds;
            return this;
        }
        @CustomType.Setter
        public Builder type(String type) {
            if (type == null) {
              throw new MissingRequiredPropertyException("GetApiDeploymentSpecificationRouteResponsePolicyResponseCacheStore", "type");
            }
            this.type = type;
            return this;
        }
        public GetApiDeploymentSpecificationRouteResponsePolicyResponseCacheStore build() {
            final var _resultValue = new GetApiDeploymentSpecificationRouteResponsePolicyResponseCacheStore();
            _resultValue.timeToLiveInSeconds = timeToLiveInSeconds;
            _resultValue.type = type;
            return _resultValue;
        }
    }
}
