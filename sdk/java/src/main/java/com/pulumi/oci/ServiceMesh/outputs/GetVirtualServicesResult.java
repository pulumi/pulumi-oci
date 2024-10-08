// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.ServiceMesh.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.ServiceMesh.outputs.GetVirtualServicesFilter;
import com.pulumi.oci.ServiceMesh.outputs.GetVirtualServicesVirtualServiceCollection;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;

@CustomType
public final class GetVirtualServicesResult {
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
     * 
     */
    private String compartmentId;
    private @Nullable List<GetVirtualServicesFilter> filters;
    /**
     * @return Unique identifier that is immutable on creation.
     * 
     */
    private @Nullable String id;
    /**
     * @return The OCID of the service mesh in which this virtual service is created.
     * 
     */
    private @Nullable String meshId;
    /**
     * @return A user-friendly name. The name has to be unique within the same service mesh and cannot be changed after creation. Avoid entering confidential information.  Example: `My unique resource name`
     * 
     */
    private @Nullable String name;
    /**
     * @return The current state of the Resource.
     * 
     */
    private @Nullable String state;
    /**
     * @return The list of virtual_service_collection.
     * 
     */
    private List<GetVirtualServicesVirtualServiceCollection> virtualServiceCollections;

    private GetVirtualServicesResult() {}
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
     * 
     */
    public String compartmentId() {
        return this.compartmentId;
    }
    public List<GetVirtualServicesFilter> filters() {
        return this.filters == null ? List.of() : this.filters;
    }
    /**
     * @return Unique identifier that is immutable on creation.
     * 
     */
    public Optional<String> id() {
        return Optional.ofNullable(this.id);
    }
    /**
     * @return The OCID of the service mesh in which this virtual service is created.
     * 
     */
    public Optional<String> meshId() {
        return Optional.ofNullable(this.meshId);
    }
    /**
     * @return A user-friendly name. The name has to be unique within the same service mesh and cannot be changed after creation. Avoid entering confidential information.  Example: `My unique resource name`
     * 
     */
    public Optional<String> name() {
        return Optional.ofNullable(this.name);
    }
    /**
     * @return The current state of the Resource.
     * 
     */
    public Optional<String> state() {
        return Optional.ofNullable(this.state);
    }
    /**
     * @return The list of virtual_service_collection.
     * 
     */
    public List<GetVirtualServicesVirtualServiceCollection> virtualServiceCollections() {
        return this.virtualServiceCollections;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetVirtualServicesResult defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String compartmentId;
        private @Nullable List<GetVirtualServicesFilter> filters;
        private @Nullable String id;
        private @Nullable String meshId;
        private @Nullable String name;
        private @Nullable String state;
        private List<GetVirtualServicesVirtualServiceCollection> virtualServiceCollections;
        public Builder() {}
        public Builder(GetVirtualServicesResult defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.compartmentId = defaults.compartmentId;
    	      this.filters = defaults.filters;
    	      this.id = defaults.id;
    	      this.meshId = defaults.meshId;
    	      this.name = defaults.name;
    	      this.state = defaults.state;
    	      this.virtualServiceCollections = defaults.virtualServiceCollections;
        }

        @CustomType.Setter
        public Builder compartmentId(String compartmentId) {
            if (compartmentId == null) {
              throw new MissingRequiredPropertyException("GetVirtualServicesResult", "compartmentId");
            }
            this.compartmentId = compartmentId;
            return this;
        }
        @CustomType.Setter
        public Builder filters(@Nullable List<GetVirtualServicesFilter> filters) {

            this.filters = filters;
            return this;
        }
        public Builder filters(GetVirtualServicesFilter... filters) {
            return filters(List.of(filters));
        }
        @CustomType.Setter
        public Builder id(@Nullable String id) {

            this.id = id;
            return this;
        }
        @CustomType.Setter
        public Builder meshId(@Nullable String meshId) {

            this.meshId = meshId;
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
        @CustomType.Setter
        public Builder virtualServiceCollections(List<GetVirtualServicesVirtualServiceCollection> virtualServiceCollections) {
            if (virtualServiceCollections == null) {
              throw new MissingRequiredPropertyException("GetVirtualServicesResult", "virtualServiceCollections");
            }
            this.virtualServiceCollections = virtualServiceCollections;
            return this;
        }
        public Builder virtualServiceCollections(GetVirtualServicesVirtualServiceCollection... virtualServiceCollections) {
            return virtualServiceCollections(List.of(virtualServiceCollections));
        }
        public GetVirtualServicesResult build() {
            final var _resultValue = new GetVirtualServicesResult();
            _resultValue.compartmentId = compartmentId;
            _resultValue.filters = filters;
            _resultValue.id = id;
            _resultValue.meshId = meshId;
            _resultValue.name = name;
            _resultValue.state = state;
            _resultValue.virtualServiceCollections = virtualServiceCollections;
            return _resultValue;
        }
    }
}
