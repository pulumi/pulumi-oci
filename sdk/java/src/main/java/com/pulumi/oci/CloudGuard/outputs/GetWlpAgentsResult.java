// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.CloudGuard.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.CloudGuard.outputs.GetWlpAgentsFilter;
import com.pulumi.oci.CloudGuard.outputs.GetWlpAgentsWlpAgentCollection;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import javax.annotation.Nullable;

@CustomType
public final class GetWlpAgentsResult {
    /**
     * @return Compartment OCID of WlpAgent.
     * 
     */
    private String compartmentId;
    private @Nullable List<GetWlpAgentsFilter> filters;
    /**
     * @return The provider-assigned unique ID for this managed resource.
     * 
     */
    private String id;
    /**
     * @return The list of wlp_agent_collection.
     * 
     */
    private List<GetWlpAgentsWlpAgentCollection> wlpAgentCollections;

    private GetWlpAgentsResult() {}
    /**
     * @return Compartment OCID of WlpAgent.
     * 
     */
    public String compartmentId() {
        return this.compartmentId;
    }
    public List<GetWlpAgentsFilter> filters() {
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
     * @return The list of wlp_agent_collection.
     * 
     */
    public List<GetWlpAgentsWlpAgentCollection> wlpAgentCollections() {
        return this.wlpAgentCollections;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetWlpAgentsResult defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String compartmentId;
        private @Nullable List<GetWlpAgentsFilter> filters;
        private String id;
        private List<GetWlpAgentsWlpAgentCollection> wlpAgentCollections;
        public Builder() {}
        public Builder(GetWlpAgentsResult defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.compartmentId = defaults.compartmentId;
    	      this.filters = defaults.filters;
    	      this.id = defaults.id;
    	      this.wlpAgentCollections = defaults.wlpAgentCollections;
        }

        @CustomType.Setter
        public Builder compartmentId(String compartmentId) {
            if (compartmentId == null) {
              throw new MissingRequiredPropertyException("GetWlpAgentsResult", "compartmentId");
            }
            this.compartmentId = compartmentId;
            return this;
        }
        @CustomType.Setter
        public Builder filters(@Nullable List<GetWlpAgentsFilter> filters) {

            this.filters = filters;
            return this;
        }
        public Builder filters(GetWlpAgentsFilter... filters) {
            return filters(List.of(filters));
        }
        @CustomType.Setter
        public Builder id(String id) {
            if (id == null) {
              throw new MissingRequiredPropertyException("GetWlpAgentsResult", "id");
            }
            this.id = id;
            return this;
        }
        @CustomType.Setter
        public Builder wlpAgentCollections(List<GetWlpAgentsWlpAgentCollection> wlpAgentCollections) {
            if (wlpAgentCollections == null) {
              throw new MissingRequiredPropertyException("GetWlpAgentsResult", "wlpAgentCollections");
            }
            this.wlpAgentCollections = wlpAgentCollections;
            return this;
        }
        public Builder wlpAgentCollections(GetWlpAgentsWlpAgentCollection... wlpAgentCollections) {
            return wlpAgentCollections(List.of(wlpAgentCollections));
        }
        public GetWlpAgentsResult build() {
            final var _resultValue = new GetWlpAgentsResult();
            _resultValue.compartmentId = compartmentId;
            _resultValue.filters = filters;
            _resultValue.id = id;
            _resultValue.wlpAgentCollections = wlpAgentCollections;
            return _resultValue;
        }
    }
}
