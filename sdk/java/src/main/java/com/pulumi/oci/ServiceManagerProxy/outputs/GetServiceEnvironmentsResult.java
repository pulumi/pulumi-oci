// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.ServiceManagerProxy.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.oci.ServiceManagerProxy.outputs.GetServiceEnvironmentsFilter;
import com.pulumi.oci.ServiceManagerProxy.outputs.GetServiceEnvironmentsServiceEnvironmentCollection;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;

@CustomType
public final class GetServiceEnvironmentsResult {
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) for the compartment.
     * 
     */
    private String compartmentId;
    /**
     * @return Display name of the service. For example, &#34;Oracle Retail Order Management Cloud Service&#34;.
     * 
     */
    private @Nullable String displayName;
    private @Nullable List<GetServiceEnvironmentsFilter> filters;
    /**
     * @return The provider-assigned unique ID for this managed resource.
     * 
     */
    private String id;
    /**
     * @return The list of service_environment_collection.
     * 
     */
    private List<GetServiceEnvironmentsServiceEnvironmentCollection> serviceEnvironmentCollections;
    private @Nullable String serviceEnvironmentId;
    private @Nullable String serviceEnvironmentType;

    private GetServiceEnvironmentsResult() {}
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) for the compartment.
     * 
     */
    public String compartmentId() {
        return this.compartmentId;
    }
    /**
     * @return Display name of the service. For example, &#34;Oracle Retail Order Management Cloud Service&#34;.
     * 
     */
    public Optional<String> displayName() {
        return Optional.ofNullable(this.displayName);
    }
    public List<GetServiceEnvironmentsFilter> filters() {
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
     * @return The list of service_environment_collection.
     * 
     */
    public List<GetServiceEnvironmentsServiceEnvironmentCollection> serviceEnvironmentCollections() {
        return this.serviceEnvironmentCollections;
    }
    public Optional<String> serviceEnvironmentId() {
        return Optional.ofNullable(this.serviceEnvironmentId);
    }
    public Optional<String> serviceEnvironmentType() {
        return Optional.ofNullable(this.serviceEnvironmentType);
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetServiceEnvironmentsResult defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String compartmentId;
        private @Nullable String displayName;
        private @Nullable List<GetServiceEnvironmentsFilter> filters;
        private String id;
        private List<GetServiceEnvironmentsServiceEnvironmentCollection> serviceEnvironmentCollections;
        private @Nullable String serviceEnvironmentId;
        private @Nullable String serviceEnvironmentType;
        public Builder() {}
        public Builder(GetServiceEnvironmentsResult defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.compartmentId = defaults.compartmentId;
    	      this.displayName = defaults.displayName;
    	      this.filters = defaults.filters;
    	      this.id = defaults.id;
    	      this.serviceEnvironmentCollections = defaults.serviceEnvironmentCollections;
    	      this.serviceEnvironmentId = defaults.serviceEnvironmentId;
    	      this.serviceEnvironmentType = defaults.serviceEnvironmentType;
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
        public Builder filters(@Nullable List<GetServiceEnvironmentsFilter> filters) {
            this.filters = filters;
            return this;
        }
        public Builder filters(GetServiceEnvironmentsFilter... filters) {
            return filters(List.of(filters));
        }
        @CustomType.Setter
        public Builder id(String id) {
            this.id = Objects.requireNonNull(id);
            return this;
        }
        @CustomType.Setter
        public Builder serviceEnvironmentCollections(List<GetServiceEnvironmentsServiceEnvironmentCollection> serviceEnvironmentCollections) {
            this.serviceEnvironmentCollections = Objects.requireNonNull(serviceEnvironmentCollections);
            return this;
        }
        public Builder serviceEnvironmentCollections(GetServiceEnvironmentsServiceEnvironmentCollection... serviceEnvironmentCollections) {
            return serviceEnvironmentCollections(List.of(serviceEnvironmentCollections));
        }
        @CustomType.Setter
        public Builder serviceEnvironmentId(@Nullable String serviceEnvironmentId) {
            this.serviceEnvironmentId = serviceEnvironmentId;
            return this;
        }
        @CustomType.Setter
        public Builder serviceEnvironmentType(@Nullable String serviceEnvironmentType) {
            this.serviceEnvironmentType = serviceEnvironmentType;
            return this;
        }
        public GetServiceEnvironmentsResult build() {
            final var o = new GetServiceEnvironmentsResult();
            o.compartmentId = compartmentId;
            o.displayName = displayName;
            o.filters = filters;
            o.id = id;
            o.serviceEnvironmentCollections = serviceEnvironmentCollections;
            o.serviceEnvironmentId = serviceEnvironmentId;
            o.serviceEnvironmentType = serviceEnvironmentType;
            return o;
        }
    }
}