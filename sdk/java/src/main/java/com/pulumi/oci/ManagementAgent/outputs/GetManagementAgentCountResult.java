// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.ManagementAgent.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.oci.ManagementAgent.outputs.GetManagementAgentCountItem;
import java.lang.Boolean;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;

@CustomType
public final class GetManagementAgentCountResult {
    private String compartmentId;
    private List<String> groupBies;
    /**
     * @return Whether or not a managementAgent has at least one plugin
     * 
     */
    private @Nullable Boolean hasPlugins;
    /**
     * @return The provider-assigned unique ID for this managed resource.
     * 
     */
    private String id;
    /**
     * @return The install type, either AGENT or GATEWAY
     * 
     */
    private @Nullable String installType;
    /**
     * @return List in which each item describes an aggregation of Managment Agents
     * 
     */
    private List<GetManagementAgentCountItem> items;

    private GetManagementAgentCountResult() {}
    public String compartmentId() {
        return this.compartmentId;
    }
    public List<String> groupBies() {
        return this.groupBies;
    }
    /**
     * @return Whether or not a managementAgent has at least one plugin
     * 
     */
    public Optional<Boolean> hasPlugins() {
        return Optional.ofNullable(this.hasPlugins);
    }
    /**
     * @return The provider-assigned unique ID for this managed resource.
     * 
     */
    public String id() {
        return this.id;
    }
    /**
     * @return The install type, either AGENT or GATEWAY
     * 
     */
    public Optional<String> installType() {
        return Optional.ofNullable(this.installType);
    }
    /**
     * @return List in which each item describes an aggregation of Managment Agents
     * 
     */
    public List<GetManagementAgentCountItem> items() {
        return this.items;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetManagementAgentCountResult defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String compartmentId;
        private List<String> groupBies;
        private @Nullable Boolean hasPlugins;
        private String id;
        private @Nullable String installType;
        private List<GetManagementAgentCountItem> items;
        public Builder() {}
        public Builder(GetManagementAgentCountResult defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.compartmentId = defaults.compartmentId;
    	      this.groupBies = defaults.groupBies;
    	      this.hasPlugins = defaults.hasPlugins;
    	      this.id = defaults.id;
    	      this.installType = defaults.installType;
    	      this.items = defaults.items;
        }

        @CustomType.Setter
        public Builder compartmentId(String compartmentId) {
            this.compartmentId = Objects.requireNonNull(compartmentId);
            return this;
        }
        @CustomType.Setter
        public Builder groupBies(List<String> groupBies) {
            this.groupBies = Objects.requireNonNull(groupBies);
            return this;
        }
        public Builder groupBies(String... groupBies) {
            return groupBies(List.of(groupBies));
        }
        @CustomType.Setter
        public Builder hasPlugins(@Nullable Boolean hasPlugins) {
            this.hasPlugins = hasPlugins;
            return this;
        }
        @CustomType.Setter
        public Builder id(String id) {
            this.id = Objects.requireNonNull(id);
            return this;
        }
        @CustomType.Setter
        public Builder installType(@Nullable String installType) {
            this.installType = installType;
            return this;
        }
        @CustomType.Setter
        public Builder items(List<GetManagementAgentCountItem> items) {
            this.items = Objects.requireNonNull(items);
            return this;
        }
        public Builder items(GetManagementAgentCountItem... items) {
            return items(List.of(items));
        }
        public GetManagementAgentCountResult build() {
            final var o = new GetManagementAgentCountResult();
            o.compartmentId = compartmentId;
            o.groupBies = groupBies;
            o.hasPlugins = hasPlugins;
            o.id = id;
            o.installType = installType;
            o.items = items;
            return o;
        }
    }
}