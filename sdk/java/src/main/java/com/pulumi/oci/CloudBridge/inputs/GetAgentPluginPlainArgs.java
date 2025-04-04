// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.CloudBridge.inputs;

import com.pulumi.core.annotations.Import;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.String;
import java.util.Objects;


public final class GetAgentPluginPlainArgs extends com.pulumi.resources.InvokeArgs {

    public static final GetAgentPluginPlainArgs Empty = new GetAgentPluginPlainArgs();

    /**
     * Unique Agent identifier path parameter.
     * 
     */
    @Import(name="agentId", required=true)
    private String agentId;

    /**
     * @return Unique Agent identifier path parameter.
     * 
     */
    public String agentId() {
        return this.agentId;
    }

    /**
     * Unique plugin identifier path parameter.
     * 
     */
    @Import(name="pluginName", required=true)
    private String pluginName;

    /**
     * @return Unique plugin identifier path parameter.
     * 
     */
    public String pluginName() {
        return this.pluginName;
    }

    private GetAgentPluginPlainArgs() {}

    private GetAgentPluginPlainArgs(GetAgentPluginPlainArgs $) {
        this.agentId = $.agentId;
        this.pluginName = $.pluginName;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(GetAgentPluginPlainArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private GetAgentPluginPlainArgs $;

        public Builder() {
            $ = new GetAgentPluginPlainArgs();
        }

        public Builder(GetAgentPluginPlainArgs defaults) {
            $ = new GetAgentPluginPlainArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param agentId Unique Agent identifier path parameter.
         * 
         * @return builder
         * 
         */
        public Builder agentId(String agentId) {
            $.agentId = agentId;
            return this;
        }

        /**
         * @param pluginName Unique plugin identifier path parameter.
         * 
         * @return builder
         * 
         */
        public Builder pluginName(String pluginName) {
            $.pluginName = pluginName;
            return this;
        }

        public GetAgentPluginPlainArgs build() {
            if ($.agentId == null) {
                throw new MissingRequiredPropertyException("GetAgentPluginPlainArgs", "agentId");
            }
            if ($.pluginName == null) {
                throw new MissingRequiredPropertyException("GetAgentPluginPlainArgs", "pluginName");
            }
            return $;
        }
    }

}
