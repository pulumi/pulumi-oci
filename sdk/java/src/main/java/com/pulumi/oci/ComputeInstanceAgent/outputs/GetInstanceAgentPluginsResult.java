// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.ComputeInstanceAgent.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.oci.ComputeInstanceAgent.outputs.GetInstanceAgentPluginsFilter;
import com.pulumi.oci.ComputeInstanceAgent.outputs.GetInstanceAgentPluginsInstanceAgentPlugin;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;

@CustomType
public final class GetInstanceAgentPluginsResult {
    private final String compartmentId;
    private final @Nullable List<GetInstanceAgentPluginsFilter> filters;
    /**
     * @return The provider-assigned unique ID for this managed resource.
     * 
     */
    private final String id;
    /**
     * @return The list of instance_agent_plugins.
     * 
     */
    private final List<GetInstanceAgentPluginsInstanceAgentPlugin> instanceAgentPlugins;
    private final String instanceagentId;
    /**
     * @return The plugin name
     * 
     */
    private final @Nullable String name;
    /**
     * @return The plugin status Specified the plugin state on the instance * `RUNNING` - The plugin is in running state * `STOPPED` - The plugin is in stopped state * `NOT_SUPPORTED` - The plugin is not supported on this platform * `INVALID` - The plugin state is not recognizable by the service
     * 
     */
    private final @Nullable String status;

    @CustomType.Constructor
    private GetInstanceAgentPluginsResult(
        @CustomType.Parameter("compartmentId") String compartmentId,
        @CustomType.Parameter("filters") @Nullable List<GetInstanceAgentPluginsFilter> filters,
        @CustomType.Parameter("id") String id,
        @CustomType.Parameter("instanceAgentPlugins") List<GetInstanceAgentPluginsInstanceAgentPlugin> instanceAgentPlugins,
        @CustomType.Parameter("instanceagentId") String instanceagentId,
        @CustomType.Parameter("name") @Nullable String name,
        @CustomType.Parameter("status") @Nullable String status) {
        this.compartmentId = compartmentId;
        this.filters = filters;
        this.id = id;
        this.instanceAgentPlugins = instanceAgentPlugins;
        this.instanceagentId = instanceagentId;
        this.name = name;
        this.status = status;
    }

    public String compartmentId() {
        return this.compartmentId;
    }
    public List<GetInstanceAgentPluginsFilter> filters() {
        return this.filters == null ? List.of() : this.filters;
    }
    /**
     * @return The provider-assigned unique ID for this managed resource.
     * 
     */
    public String id() {
        return this.id;
    }
    /**
     * @return The list of instance_agent_plugins.
     * 
     */
    public List<GetInstanceAgentPluginsInstanceAgentPlugin> instanceAgentPlugins() {
        return this.instanceAgentPlugins;
    }
    public String instanceagentId() {
        return this.instanceagentId;
    }
    /**
     * @return The plugin name
     * 
     */
    public Optional<String> name() {
        return Optional.ofNullable(this.name);
    }
    /**
     * @return The plugin status Specified the plugin state on the instance * `RUNNING` - The plugin is in running state * `STOPPED` - The plugin is in stopped state * `NOT_SUPPORTED` - The plugin is not supported on this platform * `INVALID` - The plugin state is not recognizable by the service
     * 
     */
    public Optional<String> status() {
        return Optional.ofNullable(this.status);
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetInstanceAgentPluginsResult defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private String compartmentId;
        private @Nullable List<GetInstanceAgentPluginsFilter> filters;
        private String id;
        private List<GetInstanceAgentPluginsInstanceAgentPlugin> instanceAgentPlugins;
        private String instanceagentId;
        private @Nullable String name;
        private @Nullable String status;

        public Builder() {
    	      // Empty
        }

        public Builder(GetInstanceAgentPluginsResult defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.compartmentId = defaults.compartmentId;
    	      this.filters = defaults.filters;
    	      this.id = defaults.id;
    	      this.instanceAgentPlugins = defaults.instanceAgentPlugins;
    	      this.instanceagentId = defaults.instanceagentId;
    	      this.name = defaults.name;
    	      this.status = defaults.status;
        }

        public Builder compartmentId(String compartmentId) {
            this.compartmentId = Objects.requireNonNull(compartmentId);
            return this;
        }
        public Builder filters(@Nullable List<GetInstanceAgentPluginsFilter> filters) {
            this.filters = filters;
            return this;
        }
        public Builder filters(GetInstanceAgentPluginsFilter... filters) {
            return filters(List.of(filters));
        }
        public Builder id(String id) {
            this.id = Objects.requireNonNull(id);
            return this;
        }
        public Builder instanceAgentPlugins(List<GetInstanceAgentPluginsInstanceAgentPlugin> instanceAgentPlugins) {
            this.instanceAgentPlugins = Objects.requireNonNull(instanceAgentPlugins);
            return this;
        }
        public Builder instanceAgentPlugins(GetInstanceAgentPluginsInstanceAgentPlugin... instanceAgentPlugins) {
            return instanceAgentPlugins(List.of(instanceAgentPlugins));
        }
        public Builder instanceagentId(String instanceagentId) {
            this.instanceagentId = Objects.requireNonNull(instanceagentId);
            return this;
        }
        public Builder name(@Nullable String name) {
            this.name = name;
            return this;
        }
        public Builder status(@Nullable String status) {
            this.status = status;
            return this;
        }        public GetInstanceAgentPluginsResult build() {
            return new GetInstanceAgentPluginsResult(compartmentId, filters, id, instanceAgentPlugins, instanceagentId, name, status);
        }
    }
}
