// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DatabaseMigration.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.oci.DatabaseMigration.outputs.GetAgentImagesAgentImageCollection;
import com.pulumi.oci.DatabaseMigration.outputs.GetAgentImagesFilter;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import javax.annotation.Nullable;

@CustomType
public final class GetAgentImagesResult {
    /**
     * @return The list of agent_image_collection.
     * 
     */
    private final List<GetAgentImagesAgentImageCollection> agentImageCollections;
    private final @Nullable List<GetAgentImagesFilter> filters;
    /**
     * @return The provider-assigned unique ID for this managed resource.
     * 
     */
    private final String id;

    @CustomType.Constructor
    private GetAgentImagesResult(
        @CustomType.Parameter("agentImageCollections") List<GetAgentImagesAgentImageCollection> agentImageCollections,
        @CustomType.Parameter("filters") @Nullable List<GetAgentImagesFilter> filters,
        @CustomType.Parameter("id") String id) {
        this.agentImageCollections = agentImageCollections;
        this.filters = filters;
        this.id = id;
    }

    /**
     * @return The list of agent_image_collection.
     * 
     */
    public List<GetAgentImagesAgentImageCollection> agentImageCollections() {
        return this.agentImageCollections;
    }
    public List<GetAgentImagesFilter> filters() {
        return this.filters == null ? List.of() : this.filters;
    }
    /**
     * @return The provider-assigned unique ID for this managed resource.
     * 
     */
    public String id() {
        return this.id;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetAgentImagesResult defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private List<GetAgentImagesAgentImageCollection> agentImageCollections;
        private @Nullable List<GetAgentImagesFilter> filters;
        private String id;

        public Builder() {
    	      // Empty
        }

        public Builder(GetAgentImagesResult defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.agentImageCollections = defaults.agentImageCollections;
    	      this.filters = defaults.filters;
    	      this.id = defaults.id;
        }

        public Builder agentImageCollections(List<GetAgentImagesAgentImageCollection> agentImageCollections) {
            this.agentImageCollections = Objects.requireNonNull(agentImageCollections);
            return this;
        }
        public Builder agentImageCollections(GetAgentImagesAgentImageCollection... agentImageCollections) {
            return agentImageCollections(List.of(agentImageCollections));
        }
        public Builder filters(@Nullable List<GetAgentImagesFilter> filters) {
            this.filters = filters;
            return this;
        }
        public Builder filters(GetAgentImagesFilter... filters) {
            return filters(List.of(filters));
        }
        public Builder id(String id) {
            this.id = Objects.requireNonNull(id);
            return this;
        }        public GetAgentImagesResult build() {
            return new GetAgentImagesResult(agentImageCollections, filters, id);
        }
    }
}
