// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.ApiGateway.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.String;
import java.util.List;
import java.util.Objects;


public final class DeploymentSpecificationRequestPoliciesUsagePlansArgs extends com.pulumi.resources.ResourceArgs {

    public static final DeploymentSpecificationRequestPoliciesUsagePlansArgs Empty = new DeploymentSpecificationRequestPoliciesUsagePlansArgs();

    /**
     * (Updatable) A list of context variables specifying where API tokens may be located in a request. Example locations:
     * * &#34;request.headers[token]&#34;
     * * &#34;request.query[token]&#34;
     * * &#34;request.auth[Token]&#34;
     * * &#34;request.path[TOKEN]&#34;
     * 
     */
    @Import(name="tokenLocations", required=true)
    private Output<List<String>> tokenLocations;

    /**
     * @return (Updatable) A list of context variables specifying where API tokens may be located in a request. Example locations:
     * * &#34;request.headers[token]&#34;
     * * &#34;request.query[token]&#34;
     * * &#34;request.auth[Token]&#34;
     * * &#34;request.path[TOKEN]&#34;
     * 
     */
    public Output<List<String>> tokenLocations() {
        return this.tokenLocations;
    }

    private DeploymentSpecificationRequestPoliciesUsagePlansArgs() {}

    private DeploymentSpecificationRequestPoliciesUsagePlansArgs(DeploymentSpecificationRequestPoliciesUsagePlansArgs $) {
        this.tokenLocations = $.tokenLocations;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(DeploymentSpecificationRequestPoliciesUsagePlansArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private DeploymentSpecificationRequestPoliciesUsagePlansArgs $;

        public Builder() {
            $ = new DeploymentSpecificationRequestPoliciesUsagePlansArgs();
        }

        public Builder(DeploymentSpecificationRequestPoliciesUsagePlansArgs defaults) {
            $ = new DeploymentSpecificationRequestPoliciesUsagePlansArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param tokenLocations (Updatable) A list of context variables specifying where API tokens may be located in a request. Example locations:
         * * &#34;request.headers[token]&#34;
         * * &#34;request.query[token]&#34;
         * * &#34;request.auth[Token]&#34;
         * * &#34;request.path[TOKEN]&#34;
         * 
         * @return builder
         * 
         */
        public Builder tokenLocations(Output<List<String>> tokenLocations) {
            $.tokenLocations = tokenLocations;
            return this;
        }

        /**
         * @param tokenLocations (Updatable) A list of context variables specifying where API tokens may be located in a request. Example locations:
         * * &#34;request.headers[token]&#34;
         * * &#34;request.query[token]&#34;
         * * &#34;request.auth[Token]&#34;
         * * &#34;request.path[TOKEN]&#34;
         * 
         * @return builder
         * 
         */
        public Builder tokenLocations(List<String> tokenLocations) {
            return tokenLocations(Output.of(tokenLocations));
        }

        /**
         * @param tokenLocations (Updatable) A list of context variables specifying where API tokens may be located in a request. Example locations:
         * * &#34;request.headers[token]&#34;
         * * &#34;request.query[token]&#34;
         * * &#34;request.auth[Token]&#34;
         * * &#34;request.path[TOKEN]&#34;
         * 
         * @return builder
         * 
         */
        public Builder tokenLocations(String... tokenLocations) {
            return tokenLocations(List.of(tokenLocations));
        }

        public DeploymentSpecificationRequestPoliciesUsagePlansArgs build() {
            if ($.tokenLocations == null) {
                throw new MissingRequiredPropertyException("DeploymentSpecificationRequestPoliciesUsagePlansArgs", "tokenLocations");
            }
            return $;
        }
    }

}
