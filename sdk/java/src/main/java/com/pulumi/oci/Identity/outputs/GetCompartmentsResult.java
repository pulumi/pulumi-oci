// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Identity.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.Identity.outputs.GetCompartmentsCompartment;
import com.pulumi.oci.Identity.outputs.GetCompartmentsFilter;
import java.lang.Boolean;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;

@CustomType
public final class GetCompartmentsResult {
    private @Nullable String accessLevel;
    /**
     * @return The OCID of the parent compartment containing the compartment.
     * 
     */
    private String compartmentId;
    private @Nullable Boolean compartmentIdInSubtree;
    /**
     * @return The list of compartments.
     * 
     */
    private List<GetCompartmentsCompartment> compartments;
    private @Nullable List<GetCompartmentsFilter> filters;
    /**
     * @return The provider-assigned unique ID for this managed resource.
     * 
     */
    private String id;
    /**
     * @return The name you assign to the compartment during creation. The name must be unique across all compartments in the parent. Avoid entering confidential information.
     * 
     */
    private @Nullable String name;
    /**
     * @return The compartment&#39;s current state.
     * 
     */
    private @Nullable String state;

    private GetCompartmentsResult() {}
    public Optional<String> accessLevel() {
        return Optional.ofNullable(this.accessLevel);
    }
    /**
     * @return The OCID of the parent compartment containing the compartment.
     * 
     */
    public String compartmentId() {
        return this.compartmentId;
    }
    public Optional<Boolean> compartmentIdInSubtree() {
        return Optional.ofNullable(this.compartmentIdInSubtree);
    }
    /**
     * @return The list of compartments.
     * 
     */
    public List<GetCompartmentsCompartment> compartments() {
        return this.compartments;
    }
    public List<GetCompartmentsFilter> filters() {
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
     * @return The name you assign to the compartment during creation. The name must be unique across all compartments in the parent. Avoid entering confidential information.
     * 
     */
    public Optional<String> name() {
        return Optional.ofNullable(this.name);
    }
    /**
     * @return The compartment&#39;s current state.
     * 
     */
    public Optional<String> state() {
        return Optional.ofNullable(this.state);
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetCompartmentsResult defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private @Nullable String accessLevel;
        private String compartmentId;
        private @Nullable Boolean compartmentIdInSubtree;
        private List<GetCompartmentsCompartment> compartments;
        private @Nullable List<GetCompartmentsFilter> filters;
        private String id;
        private @Nullable String name;
        private @Nullable String state;
        public Builder() {}
        public Builder(GetCompartmentsResult defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.accessLevel = defaults.accessLevel;
    	      this.compartmentId = defaults.compartmentId;
    	      this.compartmentIdInSubtree = defaults.compartmentIdInSubtree;
    	      this.compartments = defaults.compartments;
    	      this.filters = defaults.filters;
    	      this.id = defaults.id;
    	      this.name = defaults.name;
    	      this.state = defaults.state;
        }

        @CustomType.Setter
        public Builder accessLevel(@Nullable String accessLevel) {

            this.accessLevel = accessLevel;
            return this;
        }
        @CustomType.Setter
        public Builder compartmentId(String compartmentId) {
            if (compartmentId == null) {
              throw new MissingRequiredPropertyException("GetCompartmentsResult", "compartmentId");
            }
            this.compartmentId = compartmentId;
            return this;
        }
        @CustomType.Setter
        public Builder compartmentIdInSubtree(@Nullable Boolean compartmentIdInSubtree) {

            this.compartmentIdInSubtree = compartmentIdInSubtree;
            return this;
        }
        @CustomType.Setter
        public Builder compartments(List<GetCompartmentsCompartment> compartments) {
            if (compartments == null) {
              throw new MissingRequiredPropertyException("GetCompartmentsResult", "compartments");
            }
            this.compartments = compartments;
            return this;
        }
        public Builder compartments(GetCompartmentsCompartment... compartments) {
            return compartments(List.of(compartments));
        }
        @CustomType.Setter
        public Builder filters(@Nullable List<GetCompartmentsFilter> filters) {

            this.filters = filters;
            return this;
        }
        public Builder filters(GetCompartmentsFilter... filters) {
            return filters(List.of(filters));
        }
        @CustomType.Setter
        public Builder id(String id) {
            if (id == null) {
              throw new MissingRequiredPropertyException("GetCompartmentsResult", "id");
            }
            this.id = id;
            return this;
        }
        @CustomType.Setter
        public Builder name(@Nullable String name) {

            this.name = name;
            return this;
        }
        @CustomType.Setter
        public Builder state(@Nullable String state) {

            this.state = state;
            return this;
        }
        public GetCompartmentsResult build() {
            final var _resultValue = new GetCompartmentsResult();
            _resultValue.accessLevel = accessLevel;
            _resultValue.compartmentId = compartmentId;
            _resultValue.compartmentIdInSubtree = compartmentIdInSubtree;
            _resultValue.compartments = compartments;
            _resultValue.filters = filters;
            _resultValue.id = id;
            _resultValue.name = name;
            _resultValue.state = state;
            return _resultValue;
        }
    }
}
