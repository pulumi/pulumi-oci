// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DataFlow.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.oci.DataFlow.outputs.GetInvokeRunsFilter;
import com.pulumi.oci.DataFlow.outputs.GetInvokeRunsRun;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;

@CustomType
public final class GetInvokeRunsResult {
    /**
     * @return The application ID.
     * 
     */
    private @Nullable String applicationId;
    /**
     * @return The OCID of a compartment.
     * 
     */
    private String compartmentId;
    /**
     * @return A user-friendly name. This name is not necessarily unique.
     * 
     */
    private @Nullable String displayName;
    private @Nullable String displayNameStartsWith;
    private @Nullable List<GetInvokeRunsFilter> filters;
    /**
     * @return The provider-assigned unique ID for this managed resource.
     * 
     */
    private String id;
    /**
     * @return The OCID of the user who created the resource.
     * 
     */
    private @Nullable String ownerPrincipalId;
    /**
     * @return The list of runs.
     * 
     */
    private List<GetInvokeRunsRun> runs;
    /**
     * @return The current state of this run.
     * 
     */
    private @Nullable String state;
    private @Nullable String timeCreatedGreaterThan;

    private GetInvokeRunsResult() {}
    /**
     * @return The application ID.
     * 
     */
    public Optional<String> applicationId() {
        return Optional.ofNullable(this.applicationId);
    }
    /**
     * @return The OCID of a compartment.
     * 
     */
    public String compartmentId() {
        return this.compartmentId;
    }
    /**
     * @return A user-friendly name. This name is not necessarily unique.
     * 
     */
    public Optional<String> displayName() {
        return Optional.ofNullable(this.displayName);
    }
    public Optional<String> displayNameStartsWith() {
        return Optional.ofNullable(this.displayNameStartsWith);
    }
    public List<GetInvokeRunsFilter> filters() {
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
     * @return The OCID of the user who created the resource.
     * 
     */
    public Optional<String> ownerPrincipalId() {
        return Optional.ofNullable(this.ownerPrincipalId);
    }
    /**
     * @return The list of runs.
     * 
     */
    public List<GetInvokeRunsRun> runs() {
        return this.runs;
    }
    /**
     * @return The current state of this run.
     * 
     */
    public Optional<String> state() {
        return Optional.ofNullable(this.state);
    }
    public Optional<String> timeCreatedGreaterThan() {
        return Optional.ofNullable(this.timeCreatedGreaterThan);
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetInvokeRunsResult defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private @Nullable String applicationId;
        private String compartmentId;
        private @Nullable String displayName;
        private @Nullable String displayNameStartsWith;
        private @Nullable List<GetInvokeRunsFilter> filters;
        private String id;
        private @Nullable String ownerPrincipalId;
        private List<GetInvokeRunsRun> runs;
        private @Nullable String state;
        private @Nullable String timeCreatedGreaterThan;
        public Builder() {}
        public Builder(GetInvokeRunsResult defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.applicationId = defaults.applicationId;
    	      this.compartmentId = defaults.compartmentId;
    	      this.displayName = defaults.displayName;
    	      this.displayNameStartsWith = defaults.displayNameStartsWith;
    	      this.filters = defaults.filters;
    	      this.id = defaults.id;
    	      this.ownerPrincipalId = defaults.ownerPrincipalId;
    	      this.runs = defaults.runs;
    	      this.state = defaults.state;
    	      this.timeCreatedGreaterThan = defaults.timeCreatedGreaterThan;
        }

        @CustomType.Setter
        public Builder applicationId(@Nullable String applicationId) {
            this.applicationId = applicationId;
            return this;
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
        public Builder displayNameStartsWith(@Nullable String displayNameStartsWith) {
            this.displayNameStartsWith = displayNameStartsWith;
            return this;
        }
        @CustomType.Setter
        public Builder filters(@Nullable List<GetInvokeRunsFilter> filters) {
            this.filters = filters;
            return this;
        }
        public Builder filters(GetInvokeRunsFilter... filters) {
            return filters(List.of(filters));
        }
        @CustomType.Setter
        public Builder id(String id) {
            this.id = Objects.requireNonNull(id);
            return this;
        }
        @CustomType.Setter
        public Builder ownerPrincipalId(@Nullable String ownerPrincipalId) {
            this.ownerPrincipalId = ownerPrincipalId;
            return this;
        }
        @CustomType.Setter
        public Builder runs(List<GetInvokeRunsRun> runs) {
            this.runs = Objects.requireNonNull(runs);
            return this;
        }
        public Builder runs(GetInvokeRunsRun... runs) {
            return runs(List.of(runs));
        }
        @CustomType.Setter
        public Builder state(@Nullable String state) {
            this.state = state;
            return this;
        }
        @CustomType.Setter
        public Builder timeCreatedGreaterThan(@Nullable String timeCreatedGreaterThan) {
            this.timeCreatedGreaterThan = timeCreatedGreaterThan;
            return this;
        }
        public GetInvokeRunsResult build() {
            final var o = new GetInvokeRunsResult();
            o.applicationId = applicationId;
            o.compartmentId = compartmentId;
            o.displayName = displayName;
            o.displayNameStartsWith = displayNameStartsWith;
            o.filters = filters;
            o.id = id;
            o.ownerPrincipalId = ownerPrincipalId;
            o.runs = runs;
            o.state = state;
            o.timeCreatedGreaterThan = timeCreatedGreaterThan;
            return o;
        }
    }
}