// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DelegateAccessControl.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.DelegateAccessControl.outputs.GetDelegationControlsDelegationControlSummaryCollection;
import com.pulumi.oci.DelegateAccessControl.outputs.GetDelegationControlsFilter;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;

@CustomType
public final class GetDelegationControlsResult {
    /**
     * @return The OCID of the compartment that contains the Delegation Control.
     * 
     */
    private String compartmentId;
    /**
     * @return The list of delegation_control_summary_collection.
     * 
     */
    private List<GetDelegationControlsDelegationControlSummaryCollection> delegationControlSummaryCollections;
    /**
     * @return Name of the Delegation Control. The name does not need to be unique.
     * 
     */
    private @Nullable String displayName;
    private @Nullable List<GetDelegationControlsFilter> filters;
    /**
     * @return The provider-assigned unique ID for this managed resource.
     * 
     */
    private String id;
    private @Nullable String resourceId;
    /**
     * @return Resource type for which the Delegation Control is applicable to.
     * 
     */
    private @Nullable String resourceType;
    /**
     * @return The current lifecycle state of the Delegation Control.
     * 
     */
    private @Nullable String state;

    private GetDelegationControlsResult() {}
    /**
     * @return The OCID of the compartment that contains the Delegation Control.
     * 
     */
    public String compartmentId() {
        return this.compartmentId;
    }
    /**
     * @return The list of delegation_control_summary_collection.
     * 
     */
    public List<GetDelegationControlsDelegationControlSummaryCollection> delegationControlSummaryCollections() {
        return this.delegationControlSummaryCollections;
    }
    /**
     * @return Name of the Delegation Control. The name does not need to be unique.
     * 
     */
    public Optional<String> displayName() {
        return Optional.ofNullable(this.displayName);
    }
    public List<GetDelegationControlsFilter> filters() {
        return this.filters == null ? List.of() : this.filters;
    }
    /**
     * @return The provider-assigned unique ID for this managed resource.
     * 
     */
    public String id() {
        return this.id;
    }
    public Optional<String> resourceId() {
        return Optional.ofNullable(this.resourceId);
    }
    /**
     * @return Resource type for which the Delegation Control is applicable to.
     * 
     */
    public Optional<String> resourceType() {
        return Optional.ofNullable(this.resourceType);
    }
    /**
     * @return The current lifecycle state of the Delegation Control.
     * 
     */
    public Optional<String> state() {
        return Optional.ofNullable(this.state);
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetDelegationControlsResult defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String compartmentId;
        private List<GetDelegationControlsDelegationControlSummaryCollection> delegationControlSummaryCollections;
        private @Nullable String displayName;
        private @Nullable List<GetDelegationControlsFilter> filters;
        private String id;
        private @Nullable String resourceId;
        private @Nullable String resourceType;
        private @Nullable String state;
        public Builder() {}
        public Builder(GetDelegationControlsResult defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.compartmentId = defaults.compartmentId;
    	      this.delegationControlSummaryCollections = defaults.delegationControlSummaryCollections;
    	      this.displayName = defaults.displayName;
    	      this.filters = defaults.filters;
    	      this.id = defaults.id;
    	      this.resourceId = defaults.resourceId;
    	      this.resourceType = defaults.resourceType;
    	      this.state = defaults.state;
        }

        @CustomType.Setter
        public Builder compartmentId(String compartmentId) {
            if (compartmentId == null) {
              throw new MissingRequiredPropertyException("GetDelegationControlsResult", "compartmentId");
            }
            this.compartmentId = compartmentId;
            return this;
        }
        @CustomType.Setter
        public Builder delegationControlSummaryCollections(List<GetDelegationControlsDelegationControlSummaryCollection> delegationControlSummaryCollections) {
            if (delegationControlSummaryCollections == null) {
              throw new MissingRequiredPropertyException("GetDelegationControlsResult", "delegationControlSummaryCollections");
            }
            this.delegationControlSummaryCollections = delegationControlSummaryCollections;
            return this;
        }
        public Builder delegationControlSummaryCollections(GetDelegationControlsDelegationControlSummaryCollection... delegationControlSummaryCollections) {
            return delegationControlSummaryCollections(List.of(delegationControlSummaryCollections));
        }
        @CustomType.Setter
        public Builder displayName(@Nullable String displayName) {

            this.displayName = displayName;
            return this;
        }
        @CustomType.Setter
        public Builder filters(@Nullable List<GetDelegationControlsFilter> filters) {

            this.filters = filters;
            return this;
        }
        public Builder filters(GetDelegationControlsFilter... filters) {
            return filters(List.of(filters));
        }
        @CustomType.Setter
        public Builder id(String id) {
            if (id == null) {
              throw new MissingRequiredPropertyException("GetDelegationControlsResult", "id");
            }
            this.id = id;
            return this;
        }
        @CustomType.Setter
        public Builder resourceId(@Nullable String resourceId) {

            this.resourceId = resourceId;
            return this;
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
        public GetDelegationControlsResult build() {
            final var _resultValue = new GetDelegationControlsResult();
            _resultValue.compartmentId = compartmentId;
            _resultValue.delegationControlSummaryCollections = delegationControlSummaryCollections;
            _resultValue.displayName = displayName;
            _resultValue.filters = filters;
            _resultValue.id = id;
            _resultValue.resourceId = resourceId;
            _resultValue.resourceType = resourceType;
            _resultValue.state = state;
            return _resultValue;
        }
    }
}
