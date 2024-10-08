// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.CloudBridge.inputs;

import com.pulumi.core.annotations.Import;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.String;
import java.util.Objects;


public final class GetAgentDependencyPlainArgs extends com.pulumi.resources.InvokeArgs {

    public static final GetAgentDependencyPlainArgs Empty = new GetAgentDependencyPlainArgs();

    /**
     * A unique AgentDependency identifier.
     * 
     */
    @Import(name="agentDependencyId", required=true)
    private String agentDependencyId;

    /**
     * @return A unique AgentDependency identifier.
     * 
     */
    public String agentDependencyId() {
        return this.agentDependencyId;
    }

    private GetAgentDependencyPlainArgs() {}

    private GetAgentDependencyPlainArgs(GetAgentDependencyPlainArgs $) {
        this.agentDependencyId = $.agentDependencyId;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(GetAgentDependencyPlainArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private GetAgentDependencyPlainArgs $;

        public Builder() {
            $ = new GetAgentDependencyPlainArgs();
        }

        public Builder(GetAgentDependencyPlainArgs defaults) {
            $ = new GetAgentDependencyPlainArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param agentDependencyId A unique AgentDependency identifier.
         * 
         * @return builder
         * 
         */
        public Builder agentDependencyId(String agentDependencyId) {
            $.agentDependencyId = agentDependencyId;
            return this;
        }

        public GetAgentDependencyPlainArgs build() {
            if ($.agentDependencyId == null) {
                throw new MissingRequiredPropertyException("GetAgentDependencyPlainArgs", "agentDependencyId");
            }
            return $;
        }
    }

}
