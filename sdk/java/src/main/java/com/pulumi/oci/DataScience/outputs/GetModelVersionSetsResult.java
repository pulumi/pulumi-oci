// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DataScience.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.oci.DataScience.outputs.GetModelVersionSetsFilter;
import com.pulumi.oci.DataScience.outputs.GetModelVersionSetsModelVersionSet;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;

@CustomType
public final class GetModelVersionSetsResult {
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the model version set compartment.
     * 
     */
    private String compartmentId;
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the user who created the model version set.
     * 
     */
    private @Nullable String createdBy;
    private @Nullable List<GetModelVersionSetsFilter> filters;
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the model version set.
     * 
     */
    private @Nullable String id;
    /**
     * @return The list of model_version_sets.
     * 
     */
    private List<GetModelVersionSetsModelVersionSet> modelVersionSets;
    /**
     * @return A user-friendly name for the resource. It must be unique and can&#39;t be modified.
     * 
     */
    private @Nullable String name;
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the project associated with the model version set.
     * 
     */
    private @Nullable String projectId;
    /**
     * @return The state of the model version set.
     * 
     */
    private @Nullable String state;

    private GetModelVersionSetsResult() {}
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the model version set compartment.
     * 
     */
    public String compartmentId() {
        return this.compartmentId;
    }
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the user who created the model version set.
     * 
     */
    public Optional<String> createdBy() {
        return Optional.ofNullable(this.createdBy);
    }
    public List<GetModelVersionSetsFilter> filters() {
        return this.filters == null ? List.of() : this.filters;
    }
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the model version set.
     * 
     */
    public Optional<String> id() {
        return Optional.ofNullable(this.id);
    }
    /**
     * @return The list of model_version_sets.
     * 
     */
    public List<GetModelVersionSetsModelVersionSet> modelVersionSets() {
        return this.modelVersionSets;
    }
    /**
     * @return A user-friendly name for the resource. It must be unique and can&#39;t be modified.
     * 
     */
    public Optional<String> name() {
        return Optional.ofNullable(this.name);
    }
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the project associated with the model version set.
     * 
     */
    public Optional<String> projectId() {
        return Optional.ofNullable(this.projectId);
    }
    /**
     * @return The state of the model version set.
     * 
     */
    public Optional<String> state() {
        return Optional.ofNullable(this.state);
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetModelVersionSetsResult defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String compartmentId;
        private @Nullable String createdBy;
        private @Nullable List<GetModelVersionSetsFilter> filters;
        private @Nullable String id;
        private List<GetModelVersionSetsModelVersionSet> modelVersionSets;
        private @Nullable String name;
        private @Nullable String projectId;
        private @Nullable String state;
        public Builder() {}
        public Builder(GetModelVersionSetsResult defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.compartmentId = defaults.compartmentId;
    	      this.createdBy = defaults.createdBy;
    	      this.filters = defaults.filters;
    	      this.id = defaults.id;
    	      this.modelVersionSets = defaults.modelVersionSets;
    	      this.name = defaults.name;
    	      this.projectId = defaults.projectId;
    	      this.state = defaults.state;
        }

        @CustomType.Setter
        public Builder compartmentId(String compartmentId) {
            this.compartmentId = Objects.requireNonNull(compartmentId);
            return this;
        }
        @CustomType.Setter
        public Builder createdBy(@Nullable String createdBy) {
            this.createdBy = createdBy;
            return this;
        }
        @CustomType.Setter
        public Builder filters(@Nullable List<GetModelVersionSetsFilter> filters) {
            this.filters = filters;
            return this;
        }
        public Builder filters(GetModelVersionSetsFilter... filters) {
            return filters(List.of(filters));
        }
        @CustomType.Setter
        public Builder id(@Nullable String id) {
            this.id = id;
            return this;
        }
        @CustomType.Setter
        public Builder modelVersionSets(List<GetModelVersionSetsModelVersionSet> modelVersionSets) {
            this.modelVersionSets = Objects.requireNonNull(modelVersionSets);
            return this;
        }
        public Builder modelVersionSets(GetModelVersionSetsModelVersionSet... modelVersionSets) {
            return modelVersionSets(List.of(modelVersionSets));
        }
        @CustomType.Setter
        public Builder name(@Nullable String name) {
            this.name = name;
            return this;
        }
        @CustomType.Setter
        public Builder projectId(@Nullable String projectId) {
            this.projectId = projectId;
            return this;
        }
        @CustomType.Setter
        public Builder state(@Nullable String state) {
            this.state = state;
            return this;
        }
        public GetModelVersionSetsResult build() {
            final var o = new GetModelVersionSetsResult();
            o.compartmentId = compartmentId;
            o.createdBy = createdBy;
            o.filters = filters;
            o.id = id;
            o.modelVersionSets = modelVersionSets;
            o.name = name;
            o.projectId = projectId;
            o.state = state;
            return o;
        }
    }
}