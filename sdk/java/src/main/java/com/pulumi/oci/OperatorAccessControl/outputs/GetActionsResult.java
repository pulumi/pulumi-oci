// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.OperatorAccessControl.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.oci.OperatorAccessControl.outputs.GetActionsFilter;
import com.pulumi.oci.OperatorAccessControl.outputs.GetActionsOperatorActionCollection;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;

@CustomType
public final class GetActionsResult {
    private String compartmentId;
    private @Nullable List<GetActionsFilter> filters;
    /**
     * @return The provider-assigned unique ID for this managed resource.
     * 
     */
    private String id;
    /**
     * @return Name of the property
     * 
     */
    private @Nullable String name;
    /**
     * @return The list of operator_action_collection.
     * 
     */
    private List<GetActionsOperatorActionCollection> operatorActionCollections;
    /**
     * @return resourceType for which the OperatorAction is applicable
     * 
     */
    private @Nullable String resourceType;
    private @Nullable String state;

    private GetActionsResult() {}
    public String compartmentId() {
        return this.compartmentId;
    }
    public List<GetActionsFilter> filters() {
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
     * @return Name of the property
     * 
     */
    public Optional<String> name() {
        return Optional.ofNullable(this.name);
    }
    /**
     * @return The list of operator_action_collection.
     * 
     */
    public List<GetActionsOperatorActionCollection> operatorActionCollections() {
        return this.operatorActionCollections;
    }
    /**
     * @return resourceType for which the OperatorAction is applicable
     * 
     */
    public Optional<String> resourceType() {
        return Optional.ofNullable(this.resourceType);
    }
    public Optional<String> state() {
        return Optional.ofNullable(this.state);
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetActionsResult defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String compartmentId;
        private @Nullable List<GetActionsFilter> filters;
        private String id;
        private @Nullable String name;
        private List<GetActionsOperatorActionCollection> operatorActionCollections;
        private @Nullable String resourceType;
        private @Nullable String state;
        public Builder() {}
        public Builder(GetActionsResult defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.compartmentId = defaults.compartmentId;
    	      this.filters = defaults.filters;
    	      this.id = defaults.id;
    	      this.name = defaults.name;
    	      this.operatorActionCollections = defaults.operatorActionCollections;
    	      this.resourceType = defaults.resourceType;
    	      this.state = defaults.state;
        }

        @CustomType.Setter
        public Builder compartmentId(String compartmentId) {
            this.compartmentId = Objects.requireNonNull(compartmentId);
            return this;
        }
        @CustomType.Setter
        public Builder filters(@Nullable List<GetActionsFilter> filters) {
            this.filters = filters;
            return this;
        }
        public Builder filters(GetActionsFilter... filters) {
            return filters(List.of(filters));
        }
        @CustomType.Setter
        public Builder id(String id) {
            this.id = Objects.requireNonNull(id);
            return this;
        }
        @CustomType.Setter
        public Builder name(@Nullable String name) {
            this.name = name;
            return this;
        }
        @CustomType.Setter
        public Builder operatorActionCollections(List<GetActionsOperatorActionCollection> operatorActionCollections) {
            this.operatorActionCollections = Objects.requireNonNull(operatorActionCollections);
            return this;
        }
        public Builder operatorActionCollections(GetActionsOperatorActionCollection... operatorActionCollections) {
            return operatorActionCollections(List.of(operatorActionCollections));
        }
        @CustomType.Setter
        public Builder resourceType(@Nullable String resourceType) {
            this.resourceType = resourceType;
            return this;
        }
        @CustomType.Setter
        public Builder state(@Nullable String state) {
            this.state = state;
            return this;
        }
        public GetActionsResult build() {
            final var o = new GetActionsResult();
            o.compartmentId = compartmentId;
            o.filters = filters;
            o.id = id;
            o.name = name;
            o.operatorActionCollections = operatorActionCollections;
            o.resourceType = resourceType;
            o.state = state;
            return o;
        }
    }
}