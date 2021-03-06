// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.ApiGateway.outputs;

import com.pulumi.core.annotations.CustomType;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;

@CustomType
public final class DeploymentSpecificationRouteRequestPoliciesAuthorization {
    /**
     * @return (Updatable) A user whose scope includes any of these access ranges is allowed on this route. Access ranges are case-sensitive.
     * 
     */
    private final @Nullable List<String> allowedScopes;
    /**
     * @return (Updatable) Type of the Response Cache Store Policy.
     * 
     */
    private final @Nullable String type;

    @CustomType.Constructor
    private DeploymentSpecificationRouteRequestPoliciesAuthorization(
        @CustomType.Parameter("allowedScopes") @Nullable List<String> allowedScopes,
        @CustomType.Parameter("type") @Nullable String type) {
        this.allowedScopes = allowedScopes;
        this.type = type;
    }

    /**
     * @return (Updatable) A user whose scope includes any of these access ranges is allowed on this route. Access ranges are case-sensitive.
     * 
     */
    public List<String> allowedScopes() {
        return this.allowedScopes == null ? List.of() : this.allowedScopes;
    }
    /**
     * @return (Updatable) Type of the Response Cache Store Policy.
     * 
     */
    public Optional<String> type() {
        return Optional.ofNullable(this.type);
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(DeploymentSpecificationRouteRequestPoliciesAuthorization defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private @Nullable List<String> allowedScopes;
        private @Nullable String type;

        public Builder() {
    	      // Empty
        }

        public Builder(DeploymentSpecificationRouteRequestPoliciesAuthorization defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.allowedScopes = defaults.allowedScopes;
    	      this.type = defaults.type;
        }

        public Builder allowedScopes(@Nullable List<String> allowedScopes) {
            this.allowedScopes = allowedScopes;
            return this;
        }
        public Builder allowedScopes(String... allowedScopes) {
            return allowedScopes(List.of(allowedScopes));
        }
        public Builder type(@Nullable String type) {
            this.type = type;
            return this;
        }        public DeploymentSpecificationRouteRequestPoliciesAuthorization build() {
            return new DeploymentSpecificationRouteRequestPoliciesAuthorization(allowedScopes, type);
        }
    }
}
