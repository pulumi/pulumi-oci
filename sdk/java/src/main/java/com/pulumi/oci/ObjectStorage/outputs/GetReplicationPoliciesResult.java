// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.ObjectStorage.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.ObjectStorage.outputs.GetReplicationPoliciesFilter;
import com.pulumi.oci.ObjectStorage.outputs.GetReplicationPoliciesReplicationPolicy;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import javax.annotation.Nullable;

@CustomType
public final class GetReplicationPoliciesResult {
    private String bucket;
    private @Nullable List<GetReplicationPoliciesFilter> filters;
    /**
     * @return The provider-assigned unique ID for this managed resource.
     * 
     */
    private String id;
    private String namespace;
    /**
     * @return The list of replication_policies.
     * 
     */
    private List<GetReplicationPoliciesReplicationPolicy> replicationPolicies;

    private GetReplicationPoliciesResult() {}
    public String bucket() {
        return this.bucket;
    }
    public List<GetReplicationPoliciesFilter> filters() {
        return this.filters == null ? List.of() : this.filters;
    }
    /**
     * @return The provider-assigned unique ID for this managed resource.
     * 
     */
    public String id() {
        return this.id;
    }
    public String namespace() {
        return this.namespace;
    }
    /**
     * @return The list of replication_policies.
     * 
     */
    public List<GetReplicationPoliciesReplicationPolicy> replicationPolicies() {
        return this.replicationPolicies;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetReplicationPoliciesResult defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String bucket;
        private @Nullable List<GetReplicationPoliciesFilter> filters;
        private String id;
        private String namespace;
        private List<GetReplicationPoliciesReplicationPolicy> replicationPolicies;
        public Builder() {}
        public Builder(GetReplicationPoliciesResult defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.bucket = defaults.bucket;
    	      this.filters = defaults.filters;
    	      this.id = defaults.id;
    	      this.namespace = defaults.namespace;
    	      this.replicationPolicies = defaults.replicationPolicies;
        }

        @CustomType.Setter
        public Builder bucket(String bucket) {
            if (bucket == null) {
              throw new MissingRequiredPropertyException("GetReplicationPoliciesResult", "bucket");
            }
            this.bucket = bucket;
            return this;
        }
        @CustomType.Setter
        public Builder filters(@Nullable List<GetReplicationPoliciesFilter> filters) {

            this.filters = filters;
            return this;
        }
        public Builder filters(GetReplicationPoliciesFilter... filters) {
            return filters(List.of(filters));
        }
        @CustomType.Setter
        public Builder id(String id) {
            if (id == null) {
              throw new MissingRequiredPropertyException("GetReplicationPoliciesResult", "id");
            }
            this.id = id;
            return this;
        }
        @CustomType.Setter
        public Builder namespace(String namespace) {
            if (namespace == null) {
              throw new MissingRequiredPropertyException("GetReplicationPoliciesResult", "namespace");
            }
            this.namespace = namespace;
            return this;
        }
        @CustomType.Setter
        public Builder replicationPolicies(List<GetReplicationPoliciesReplicationPolicy> replicationPolicies) {
            if (replicationPolicies == null) {
              throw new MissingRequiredPropertyException("GetReplicationPoliciesResult", "replicationPolicies");
            }
            this.replicationPolicies = replicationPolicies;
            return this;
        }
        public Builder replicationPolicies(GetReplicationPoliciesReplicationPolicy... replicationPolicies) {
            return replicationPolicies(List.of(replicationPolicies));
        }
        public GetReplicationPoliciesResult build() {
            final var _resultValue = new GetReplicationPoliciesResult();
            _resultValue.bucket = bucket;
            _resultValue.filters = filters;
            _resultValue.id = id;
            _resultValue.namespace = namespace;
            _resultValue.replicationPolicies = replicationPolicies;
            return _resultValue;
        }
    }
}
