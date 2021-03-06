// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.ApiGateway.outputs;

import com.pulumi.core.annotations.CustomType;
import java.lang.Boolean;
import java.lang.String;
import java.util.List;
import java.util.Objects;

@CustomType
public final class GetApiDeploymentSpecificationRouteRequestPolicyResponseCacheLookup {
    /**
     * @return A list of context expressions whose values will be added to the base cache key. Values should contain an expression enclosed within ${} delimiters. Only the request context is available.
     * 
     */
    private final List<String> cacheKeyAdditions;
    /**
     * @return Whether this policy is currently enabled.
     * 
     */
    private final Boolean isEnabled;
    /**
     * @return Set true to allow caching responses where the request has an Authorization header. Ensure you have configured your  cache key additions to get the level of isolation across authenticated requests that you require.
     * 
     */
    private final Boolean isPrivateCachingEnabled;
    /**
     * @return Type of the Response Cache Store Policy.
     * 
     */
    private final String type;

    @CustomType.Constructor
    private GetApiDeploymentSpecificationRouteRequestPolicyResponseCacheLookup(
        @CustomType.Parameter("cacheKeyAdditions") List<String> cacheKeyAdditions,
        @CustomType.Parameter("isEnabled") Boolean isEnabled,
        @CustomType.Parameter("isPrivateCachingEnabled") Boolean isPrivateCachingEnabled,
        @CustomType.Parameter("type") String type) {
        this.cacheKeyAdditions = cacheKeyAdditions;
        this.isEnabled = isEnabled;
        this.isPrivateCachingEnabled = isPrivateCachingEnabled;
        this.type = type;
    }

    /**
     * @return A list of context expressions whose values will be added to the base cache key. Values should contain an expression enclosed within ${} delimiters. Only the request context is available.
     * 
     */
    public List<String> cacheKeyAdditions() {
        return this.cacheKeyAdditions;
    }
    /**
     * @return Whether this policy is currently enabled.
     * 
     */
    public Boolean isEnabled() {
        return this.isEnabled;
    }
    /**
     * @return Set true to allow caching responses where the request has an Authorization header. Ensure you have configured your  cache key additions to get the level of isolation across authenticated requests that you require.
     * 
     */
    public Boolean isPrivateCachingEnabled() {
        return this.isPrivateCachingEnabled;
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

    public static Builder builder(GetApiDeploymentSpecificationRouteRequestPolicyResponseCacheLookup defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private List<String> cacheKeyAdditions;
        private Boolean isEnabled;
        private Boolean isPrivateCachingEnabled;
        private String type;

        public Builder() {
    	      // Empty
        }

        public Builder(GetApiDeploymentSpecificationRouteRequestPolicyResponseCacheLookup defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.cacheKeyAdditions = defaults.cacheKeyAdditions;
    	      this.isEnabled = defaults.isEnabled;
    	      this.isPrivateCachingEnabled = defaults.isPrivateCachingEnabled;
    	      this.type = defaults.type;
        }

        public Builder cacheKeyAdditions(List<String> cacheKeyAdditions) {
            this.cacheKeyAdditions = Objects.requireNonNull(cacheKeyAdditions);
            return this;
        }
        public Builder cacheKeyAdditions(String... cacheKeyAdditions) {
            return cacheKeyAdditions(List.of(cacheKeyAdditions));
        }
        public Builder isEnabled(Boolean isEnabled) {
            this.isEnabled = Objects.requireNonNull(isEnabled);
            return this;
        }
        public Builder isPrivateCachingEnabled(Boolean isPrivateCachingEnabled) {
            this.isPrivateCachingEnabled = Objects.requireNonNull(isPrivateCachingEnabled);
            return this;
        }
        public Builder type(String type) {
            this.type = Objects.requireNonNull(type);
            return this;
        }        public GetApiDeploymentSpecificationRouteRequestPolicyResponseCacheLookup build() {
            return new GetApiDeploymentSpecificationRouteRequestPolicyResponseCacheLookup(cacheKeyAdditions, isEnabled, isPrivateCachingEnabled, type);
        }
    }
}
