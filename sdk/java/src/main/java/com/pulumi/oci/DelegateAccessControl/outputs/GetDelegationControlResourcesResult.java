// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DelegateAccessControl.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.DelegateAccessControl.outputs.GetDelegationControlResourcesDelegationControlResourceCollection;
import com.pulumi.oci.DelegateAccessControl.outputs.GetDelegationControlResourcesFilter;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import javax.annotation.Nullable;

@CustomType
public final class GetDelegationControlResourcesResult {
    private String delegationControlId;
    /**
     * @return The list of delegation_control_resource_collection.
     * 
     */
    private List<GetDelegationControlResourcesDelegationControlResourceCollection> delegationControlResourceCollections;
    private @Nullable List<GetDelegationControlResourcesFilter> filters;
    /**
     * @return The provider-assigned unique ID for this managed resource.
     * 
     */
    private String id;

    private GetDelegationControlResourcesResult() {}
    public String delegationControlId() {
        return this.delegationControlId;
    }
    /**
     * @return The list of delegation_control_resource_collection.
     * 
     */
    public List<GetDelegationControlResourcesDelegationControlResourceCollection> delegationControlResourceCollections() {
        return this.delegationControlResourceCollections;
    }
    public List<GetDelegationControlResourcesFilter> filters() {
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

    public static Builder builder(GetDelegationControlResourcesResult defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String delegationControlId;
        private List<GetDelegationControlResourcesDelegationControlResourceCollection> delegationControlResourceCollections;
        private @Nullable List<GetDelegationControlResourcesFilter> filters;
        private String id;
        public Builder() {}
        public Builder(GetDelegationControlResourcesResult defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.delegationControlId = defaults.delegationControlId;
    	      this.delegationControlResourceCollections = defaults.delegationControlResourceCollections;
    	      this.filters = defaults.filters;
    	      this.id = defaults.id;
        }

        @CustomType.Setter
        public Builder delegationControlId(String delegationControlId) {
            if (delegationControlId == null) {
              throw new MissingRequiredPropertyException("GetDelegationControlResourcesResult", "delegationControlId");
            }
            this.delegationControlId = delegationControlId;
            return this;
        }
        @CustomType.Setter
        public Builder delegationControlResourceCollections(List<GetDelegationControlResourcesDelegationControlResourceCollection> delegationControlResourceCollections) {
            if (delegationControlResourceCollections == null) {
              throw new MissingRequiredPropertyException("GetDelegationControlResourcesResult", "delegationControlResourceCollections");
            }
            this.delegationControlResourceCollections = delegationControlResourceCollections;
            return this;
        }
        public Builder delegationControlResourceCollections(GetDelegationControlResourcesDelegationControlResourceCollection... delegationControlResourceCollections) {
            return delegationControlResourceCollections(List.of(delegationControlResourceCollections));
        }
        @CustomType.Setter
        public Builder filters(@Nullable List<GetDelegationControlResourcesFilter> filters) {

            this.filters = filters;
            return this;
        }
        public Builder filters(GetDelegationControlResourcesFilter... filters) {
            return filters(List.of(filters));
        }
        @CustomType.Setter
        public Builder id(String id) {
            if (id == null) {
              throw new MissingRequiredPropertyException("GetDelegationControlResourcesResult", "id");
            }
            this.id = id;
            return this;
        }
        public GetDelegationControlResourcesResult build() {
            final var _resultValue = new GetDelegationControlResourcesResult();
            _resultValue.delegationControlId = delegationControlId;
            _resultValue.delegationControlResourceCollections = delegationControlResourceCollections;
            _resultValue.filters = filters;
            _resultValue.id = id;
            return _resultValue;
        }
    }
}
