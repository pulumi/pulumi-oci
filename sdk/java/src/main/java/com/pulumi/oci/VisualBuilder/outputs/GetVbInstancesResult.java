// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.VisualBuilder.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.oci.VisualBuilder.outputs.GetVbInstancesFilter;
import com.pulumi.oci.VisualBuilder.outputs.GetVbInstancesVbInstanceSummaryCollection;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;

@CustomType
public final class GetVbInstancesResult {
    /**
     * @return Compartment Identifier.
     * 
     */
    private String compartmentId;
    /**
     * @return Vb Instance Identifier, can be renamed.
     * 
     */
    private @Nullable String displayName;
    private @Nullable List<GetVbInstancesFilter> filters;
    /**
     * @return The provider-assigned unique ID for this managed resource.
     * 
     */
    private String id;
    /**
     * @return The current state of the vb instance.
     * 
     */
    private @Nullable String state;
    /**
     * @return The list of vb_instance_summary_collection.
     * 
     */
    private List<GetVbInstancesVbInstanceSummaryCollection> vbInstanceSummaryCollections;

    private GetVbInstancesResult() {}
    /**
     * @return Compartment Identifier.
     * 
     */
    public String compartmentId() {
        return this.compartmentId;
    }
    /**
     * @return Vb Instance Identifier, can be renamed.
     * 
     */
    public Optional<String> displayName() {
        return Optional.ofNullable(this.displayName);
    }
    public List<GetVbInstancesFilter> filters() {
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
     * @return The current state of the vb instance.
     * 
     */
    public Optional<String> state() {
        return Optional.ofNullable(this.state);
    }
    /**
     * @return The list of vb_instance_summary_collection.
     * 
     */
    public List<GetVbInstancesVbInstanceSummaryCollection> vbInstanceSummaryCollections() {
        return this.vbInstanceSummaryCollections;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetVbInstancesResult defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String compartmentId;
        private @Nullable String displayName;
        private @Nullable List<GetVbInstancesFilter> filters;
        private String id;
        private @Nullable String state;
        private List<GetVbInstancesVbInstanceSummaryCollection> vbInstanceSummaryCollections;
        public Builder() {}
        public Builder(GetVbInstancesResult defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.compartmentId = defaults.compartmentId;
    	      this.displayName = defaults.displayName;
    	      this.filters = defaults.filters;
    	      this.id = defaults.id;
    	      this.state = defaults.state;
    	      this.vbInstanceSummaryCollections = defaults.vbInstanceSummaryCollections;
        }

        @CustomType.Setter
        public Builder compartmentId(String compartmentId) {
            this.compartmentId = Objects.requireNonNull(compartmentId);
            return this;
        }
        @CustomType.Setter
        public Builder displayName(@Nullable String displayName) {
            this.displayName = displayName;
            return this;
        }
        @CustomType.Setter
        public Builder filters(@Nullable List<GetVbInstancesFilter> filters) {
            this.filters = filters;
            return this;
        }
        public Builder filters(GetVbInstancesFilter... filters) {
            return filters(List.of(filters));
        }
        @CustomType.Setter
        public Builder id(String id) {
            this.id = Objects.requireNonNull(id);
            return this;
        }
        @CustomType.Setter
        public Builder state(@Nullable String state) {
            this.state = state;
            return this;
        }
        @CustomType.Setter
        public Builder vbInstanceSummaryCollections(List<GetVbInstancesVbInstanceSummaryCollection> vbInstanceSummaryCollections) {
            this.vbInstanceSummaryCollections = Objects.requireNonNull(vbInstanceSummaryCollections);
            return this;
        }
        public Builder vbInstanceSummaryCollections(GetVbInstancesVbInstanceSummaryCollection... vbInstanceSummaryCollections) {
            return vbInstanceSummaryCollections(List.of(vbInstanceSummaryCollections));
        }
        public GetVbInstancesResult build() {
            final var o = new GetVbInstancesResult();
            o.compartmentId = compartmentId;
            o.displayName = displayName;
            o.filters = filters;
            o.id = id;
            o.state = state;
            o.vbInstanceSummaryCollections = vbInstanceSummaryCollections;
            return o;
        }
    }
}