// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.BigDataService.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.BigDataService.outputs.GetBdsInstancesBdsInstance;
import com.pulumi.oci.BigDataService.outputs.GetBdsInstancesFilter;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;

@CustomType
public final class GetBdsInstancesResult {
    /**
     * @return The list of bds_instances.
     * 
     */
    private List<GetBdsInstancesBdsInstance> bdsInstances;
    /**
     * @return The OCID of the compartment.
     * 
     */
    private String compartmentId;
    /**
     * @return The name of the node.
     * 
     */
    private @Nullable String displayName;
    private @Nullable List<GetBdsInstancesFilter> filters;
    /**
     * @return The provider-assigned unique ID for this managed resource.
     * 
     */
    private String id;
    /**
     * @return The state of the cluster.
     * 
     */
    private @Nullable String state;

    private GetBdsInstancesResult() {}
    /**
     * @return The list of bds_instances.
     * 
     */
    public List<GetBdsInstancesBdsInstance> bdsInstances() {
        return this.bdsInstances;
    }
    /**
     * @return The OCID of the compartment.
     * 
     */
    public String compartmentId() {
        return this.compartmentId;
    }
    /**
     * @return The name of the node.
     * 
     */
    public Optional<String> displayName() {
        return Optional.ofNullable(this.displayName);
    }
    public List<GetBdsInstancesFilter> filters() {
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
     * @return The state of the cluster.
     * 
     */
    public Optional<String> state() {
        return Optional.ofNullable(this.state);
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetBdsInstancesResult defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private List<GetBdsInstancesBdsInstance> bdsInstances;
        private String compartmentId;
        private @Nullable String displayName;
        private @Nullable List<GetBdsInstancesFilter> filters;
        private String id;
        private @Nullable String state;
        public Builder() {}
        public Builder(GetBdsInstancesResult defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.bdsInstances = defaults.bdsInstances;
    	      this.compartmentId = defaults.compartmentId;
    	      this.displayName = defaults.displayName;
    	      this.filters = defaults.filters;
    	      this.id = defaults.id;
    	      this.state = defaults.state;
        }

        @CustomType.Setter
        public Builder bdsInstances(List<GetBdsInstancesBdsInstance> bdsInstances) {
            if (bdsInstances == null) {
              throw new MissingRequiredPropertyException("GetBdsInstancesResult", "bdsInstances");
            }
            this.bdsInstances = bdsInstances;
            return this;
        }
        public Builder bdsInstances(GetBdsInstancesBdsInstance... bdsInstances) {
            return bdsInstances(List.of(bdsInstances));
        }
        @CustomType.Setter
        public Builder compartmentId(String compartmentId) {
            if (compartmentId == null) {
              throw new MissingRequiredPropertyException("GetBdsInstancesResult", "compartmentId");
            }
            this.compartmentId = compartmentId;
            return this;
        }
        @CustomType.Setter
        public Builder displayName(@Nullable String displayName) {

            this.displayName = displayName;
            return this;
        }
        @CustomType.Setter
        public Builder filters(@Nullable List<GetBdsInstancesFilter> filters) {

            this.filters = filters;
            return this;
        }
        public Builder filters(GetBdsInstancesFilter... filters) {
            return filters(List.of(filters));
        }
        @CustomType.Setter
        public Builder id(String id) {
            if (id == null) {
              throw new MissingRequiredPropertyException("GetBdsInstancesResult", "id");
            }
            this.id = id;
            return this;
        }
        @CustomType.Setter
        public Builder state(@Nullable String state) {

            this.state = state;
            return this;
        }
        public GetBdsInstancesResult build() {
            final var _resultValue = new GetBdsInstancesResult();
            _resultValue.bdsInstances = bdsInstances;
            _resultValue.compartmentId = compartmentId;
            _resultValue.displayName = displayName;
            _resultValue.filters = filters;
            _resultValue.id = id;
            _resultValue.state = state;
            return _resultValue;
        }
    }
}
