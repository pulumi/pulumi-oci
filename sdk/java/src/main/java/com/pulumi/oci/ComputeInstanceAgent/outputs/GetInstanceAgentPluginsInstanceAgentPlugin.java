// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.ComputeInstanceAgent.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.String;
import java.util.Objects;

@CustomType
public final class GetInstanceAgentPluginsInstanceAgentPlugin {
    /**
     * @return The optional message from the agent plugin
     * 
     */
    private String message;
    /**
     * @return The plugin name
     * 
     */
    private String name;
    /**
     * @return The plugin status
     * 
     */
    private String status;
    /**
     * @return The last update time of the plugin in UTC
     * 
     */
    private String timeLastUpdatedUtc;

    private GetInstanceAgentPluginsInstanceAgentPlugin() {}
    /**
     * @return The optional message from the agent plugin
     * 
     */
    public String message() {
        return this.message;
    }
    /**
     * @return The plugin name
     * 
     */
    public String name() {
        return this.name;
    }
    /**
     * @return The plugin status
     * 
     */
    public String status() {
        return this.status;
    }
    /**
     * @return The last update time of the plugin in UTC
     * 
     */
    public String timeLastUpdatedUtc() {
        return this.timeLastUpdatedUtc;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetInstanceAgentPluginsInstanceAgentPlugin defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String message;
        private String name;
        private String status;
        private String timeLastUpdatedUtc;
        public Builder() {}
        public Builder(GetInstanceAgentPluginsInstanceAgentPlugin defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.message = defaults.message;
    	      this.name = defaults.name;
    	      this.status = defaults.status;
    	      this.timeLastUpdatedUtc = defaults.timeLastUpdatedUtc;
        }

        @CustomType.Setter
        public Builder message(String message) {
            if (message == null) {
              throw new MissingRequiredPropertyException("GetInstanceAgentPluginsInstanceAgentPlugin", "message");
            }
            this.message = message;
            return this;
        }
        @CustomType.Setter
        public Builder name(String name) {
            if (name == null) {
              throw new MissingRequiredPropertyException("GetInstanceAgentPluginsInstanceAgentPlugin", "name");
            }
            this.name = name;
            return this;
        }
        @CustomType.Setter
        public Builder status(String status) {
            if (status == null) {
              throw new MissingRequiredPropertyException("GetInstanceAgentPluginsInstanceAgentPlugin", "status");
            }
            this.status = status;
            return this;
        }
        @CustomType.Setter
        public Builder timeLastUpdatedUtc(String timeLastUpdatedUtc) {
            if (timeLastUpdatedUtc == null) {
              throw new MissingRequiredPropertyException("GetInstanceAgentPluginsInstanceAgentPlugin", "timeLastUpdatedUtc");
            }
            this.timeLastUpdatedUtc = timeLastUpdatedUtc;
            return this;
        }
        public GetInstanceAgentPluginsInstanceAgentPlugin build() {
            final var _resultValue = new GetInstanceAgentPluginsInstanceAgentPlugin();
            _resultValue.message = message;
            _resultValue.name = name;
            _resultValue.status = status;
            _resultValue.timeLastUpdatedUtc = timeLastUpdatedUtc;
            return _resultValue;
        }
    }
}
