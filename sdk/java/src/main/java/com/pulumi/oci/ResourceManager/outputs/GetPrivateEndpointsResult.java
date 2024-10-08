// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.ResourceManager.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.ResourceManager.outputs.GetPrivateEndpointsFilter;
import com.pulumi.oci.ResourceManager.outputs.GetPrivateEndpointsPrivateEndpointCollection;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;

@CustomType
public final class GetPrivateEndpointsResult {
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment containing this private endpoint details.
     * 
     */
    private @Nullable String compartmentId;
    /**
     * @return A user-friendly name. Does not have to be unique, and it&#39;s changeable. Avoid entering confidential information.
     * 
     */
    private @Nullable String displayName;
    private @Nullable List<GetPrivateEndpointsFilter> filters;
    /**
     * @return The provider-assigned unique ID for this managed resource.
     * 
     */
    private String id;
    /**
     * @return The list of private_endpoint_collection.
     * 
     */
    private List<GetPrivateEndpointsPrivateEndpointCollection> privateEndpointCollections;
    private @Nullable String privateEndpointId;
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the VCN for the private endpoint.
     * 
     */
    private @Nullable String vcnId;

    private GetPrivateEndpointsResult() {}
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment containing this private endpoint details.
     * 
     */
    public Optional<String> compartmentId() {
        return Optional.ofNullable(this.compartmentId);
    }
    /**
     * @return A user-friendly name. Does not have to be unique, and it&#39;s changeable. Avoid entering confidential information.
     * 
     */
    public Optional<String> displayName() {
        return Optional.ofNullable(this.displayName);
    }
    public List<GetPrivateEndpointsFilter> filters() {
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
     * @return The list of private_endpoint_collection.
     * 
     */
    public List<GetPrivateEndpointsPrivateEndpointCollection> privateEndpointCollections() {
        return this.privateEndpointCollections;
    }
    public Optional<String> privateEndpointId() {
        return Optional.ofNullable(this.privateEndpointId);
    }
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the VCN for the private endpoint.
     * 
     */
    public Optional<String> vcnId() {
        return Optional.ofNullable(this.vcnId);
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetPrivateEndpointsResult defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private @Nullable String compartmentId;
        private @Nullable String displayName;
        private @Nullable List<GetPrivateEndpointsFilter> filters;
        private String id;
        private List<GetPrivateEndpointsPrivateEndpointCollection> privateEndpointCollections;
        private @Nullable String privateEndpointId;
        private @Nullable String vcnId;
        public Builder() {}
        public Builder(GetPrivateEndpointsResult defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.compartmentId = defaults.compartmentId;
    	      this.displayName = defaults.displayName;
    	      this.filters = defaults.filters;
    	      this.id = defaults.id;
    	      this.privateEndpointCollections = defaults.privateEndpointCollections;
    	      this.privateEndpointId = defaults.privateEndpointId;
    	      this.vcnId = defaults.vcnId;
        }

        @CustomType.Setter
        public Builder compartmentId(@Nullable String compartmentId) {

            this.compartmentId = compartmentId;
            return this;
        }
        @CustomType.Setter
        public Builder displayName(@Nullable String displayName) {

            this.displayName = displayName;
            return this;
        }
        @CustomType.Setter
        public Builder filters(@Nullable List<GetPrivateEndpointsFilter> filters) {

            this.filters = filters;
            return this;
        }
        public Builder filters(GetPrivateEndpointsFilter... filters) {
            return filters(List.of(filters));
        }
        @CustomType.Setter
        public Builder id(String id) {
            if (id == null) {
              throw new MissingRequiredPropertyException("GetPrivateEndpointsResult", "id");
            }
            this.id = id;
            return this;
        }
        @CustomType.Setter
        public Builder privateEndpointCollections(List<GetPrivateEndpointsPrivateEndpointCollection> privateEndpointCollections) {
            if (privateEndpointCollections == null) {
              throw new MissingRequiredPropertyException("GetPrivateEndpointsResult", "privateEndpointCollections");
            }
            this.privateEndpointCollections = privateEndpointCollections;
            return this;
        }
        public Builder privateEndpointCollections(GetPrivateEndpointsPrivateEndpointCollection... privateEndpointCollections) {
            return privateEndpointCollections(List.of(privateEndpointCollections));
        }
        @CustomType.Setter
        public Builder privateEndpointId(@Nullable String privateEndpointId) {

            this.privateEndpointId = privateEndpointId;
            return this;
        }
        @CustomType.Setter
        public Builder vcnId(@Nullable String vcnId) {

            this.vcnId = vcnId;
            return this;
        }
        public GetPrivateEndpointsResult build() {
            final var _resultValue = new GetPrivateEndpointsResult();
            _resultValue.compartmentId = compartmentId;
            _resultValue.displayName = displayName;
            _resultValue.filters = filters;
            _resultValue.id = id;
            _resultValue.privateEndpointCollections = privateEndpointCollections;
            _resultValue.privateEndpointId = privateEndpointId;
            _resultValue.vcnId = vcnId;
            return _resultValue;
        }
    }
}
