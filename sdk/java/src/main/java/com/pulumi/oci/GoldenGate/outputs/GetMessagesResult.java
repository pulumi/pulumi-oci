// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.GoldenGate.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.oci.GoldenGate.outputs.GetMessagesDeploymentMessagesCollection;
import com.pulumi.oci.GoldenGate.outputs.GetMessagesFilter;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import javax.annotation.Nullable;

@CustomType
public final class GetMessagesResult {
    private String deploymentId;
    /**
     * @return The list of deployment_messages_collection.
     * 
     */
    private List<GetMessagesDeploymentMessagesCollection> deploymentMessagesCollections;
    private @Nullable List<GetMessagesFilter> filters;
    /**
     * @return The provider-assigned unique ID for this managed resource.
     * 
     */
    private String id;

    private GetMessagesResult() {}
    public String deploymentId() {
        return this.deploymentId;
    }
    /**
     * @return The list of deployment_messages_collection.
     * 
     */
    public List<GetMessagesDeploymentMessagesCollection> deploymentMessagesCollections() {
        return this.deploymentMessagesCollections;
    }
    public List<GetMessagesFilter> filters() {
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

    public static Builder builder(GetMessagesResult defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String deploymentId;
        private List<GetMessagesDeploymentMessagesCollection> deploymentMessagesCollections;
        private @Nullable List<GetMessagesFilter> filters;
        private String id;
        public Builder() {}
        public Builder(GetMessagesResult defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.deploymentId = defaults.deploymentId;
    	      this.deploymentMessagesCollections = defaults.deploymentMessagesCollections;
    	      this.filters = defaults.filters;
    	      this.id = defaults.id;
        }

        @CustomType.Setter
        public Builder deploymentId(String deploymentId) {
            this.deploymentId = Objects.requireNonNull(deploymentId);
            return this;
        }
        @CustomType.Setter
        public Builder deploymentMessagesCollections(List<GetMessagesDeploymentMessagesCollection> deploymentMessagesCollections) {
            this.deploymentMessagesCollections = Objects.requireNonNull(deploymentMessagesCollections);
            return this;
        }
        public Builder deploymentMessagesCollections(GetMessagesDeploymentMessagesCollection... deploymentMessagesCollections) {
            return deploymentMessagesCollections(List.of(deploymentMessagesCollections));
        }
        @CustomType.Setter
        public Builder filters(@Nullable List<GetMessagesFilter> filters) {
            this.filters = filters;
            return this;
        }
        public Builder filters(GetMessagesFilter... filters) {
            return filters(List.of(filters));
        }
        @CustomType.Setter
        public Builder id(String id) {
            this.id = Objects.requireNonNull(id);
            return this;
        }
        public GetMessagesResult build() {
            final var o = new GetMessagesResult();
            o.deploymentId = deploymentId;
            o.deploymentMessagesCollections = deploymentMessagesCollections;
            o.filters = filters;
            o.id = id;
            return o;
        }
    }
}