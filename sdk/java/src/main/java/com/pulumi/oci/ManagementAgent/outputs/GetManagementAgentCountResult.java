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
    private final String compartmentId;
    private final List<String> groupBies;
    /**
     * @return Whether or not a managementAgent has at least one plugin
     * 
     */
    private final @Nullable Boolean hasPlugins;
    /**
     * @return The provider-assigned unique ID for this managed resource.
     * 
     */
    private final String id;
    /**
     * @return The install type, either AGENT or GATEWAY
     * 
     */
    private final @Nullable String installType;
    /**
     * @return List in which each item describes an aggregation of Managment Agents
     * 
     */
    private final List<GetManagementAgentCountItem> items;

    @CustomType.Constructor
    private GetManagementAgentCountResult(
        @CustomType.Parameter("compartmentId") String compartmentId,
        @CustomType.Parameter("groupBies") List<String> groupBies,
        @CustomType.Parameter("hasPlugins") @Nullable Boolean hasPlugins,
        @CustomType.Parameter("id") String id,
        @CustomType.Parameter("installType") @Nullable String installType,
        @CustomType.Parameter("items") List<GetManagementAgentCountItem> items) {
        this.compartmentId = compartmentId;
        this.groupBies = groupBies;
        this.hasPlugins = hasPlugins;
        this.id = id;
        this.installType = installType;
        this.items = items;
    }

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

    public static final class Builder {
        private String compartmentId;
        private List<String> groupBies;
        private @Nullable Boolean hasPlugins;
        private String id;
        private @Nullable String installType;
        private List<GetManagementAgentCountItem> items;

        public Builder() {
    	      // Empty
        }

        public Builder(GetManagementAgentCountResult defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.compartmentId = defaults.compartmentId;
    	      this.groupBies = defaults.groupBies;
    	      this.hasPlugins = defaults.hasPlugins;
    	      this.id = defaults.id;
    	      this.installType = defaults.installType;
    	      this.items = defaults.items;
        }

        public Builder compartmentId(String compartmentId) {
            this.compartmentId = Objects.requireNonNull(compartmentId);
            return this;
        }
        public Builder groupBies(List<String> groupBies) {
            this.groupBies = Objects.requireNonNull(groupBies);
            return this;
        }
        public Builder groupBies(String... groupBies) {
            return groupBies(List.of(groupBies));
        }
        public Builder hasPlugins(@Nullable Boolean hasPlugins) {
            this.hasPlugins = hasPlugins;
            return this;
        }
        public Builder id(String id) {
            this.id = Objects.requireNonNull(id);
            return this;
        }
        public Builder installType(@Nullable String installType) {
            this.installType = installType;
            return this;
        }
        public Builder items(List<GetManagementAgentCountItem> items) {
            this.items = Objects.requireNonNull(items);
            return this;
        }
        public Builder items(GetManagementAgentCountItem... items) {
            return items(List.of(items));
        }        public GetManagementAgentCountResult build() {
            return new GetManagementAgentCountResult(compartmentId, groupBies, hasPlugins, id, installType, items);
        }
    }
}
