// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.ApiGateway.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.oci.ApiGateway.outputs.GetGatewaysFilter;
import com.pulumi.oci.ApiGateway.outputs.GetGatewaysGatewayCollection;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;

@CustomType
public final class GetGatewaysResult {
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the resource.
     * 
     */
    private @Nullable String certificateId;
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment in which the resource is created.
     * 
     */
    private String compartmentId;
    /**
     * @return A user-friendly name. Does not have to be unique, and it&#39;s changeable. Avoid entering confidential information.  Example: `My new resource`
     * 
     */
    private @Nullable String displayName;
    private @Nullable List<GetGatewaysFilter> filters;
    /**
     * @return The list of gateway_collection.
     * 
     */
    private List<GetGatewaysGatewayCollection> gatewayCollections;
    /**
     * @return The provider-assigned unique ID for this managed resource.
     * 
     */
    private String id;
    /**
     * @return The current state of the gateway.
     * 
     */
    private @Nullable String state;

    private GetGatewaysResult() {}
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the resource.
     * 
     */
    public Optional<String> certificateId() {
        return Optional.ofNullable(this.certificateId);
    }
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment in which the resource is created.
     * 
     */
    public String compartmentId() {
        return this.compartmentId;
    }
    /**
     * @return A user-friendly name. Does not have to be unique, and it&#39;s changeable. Avoid entering confidential information.  Example: `My new resource`
     * 
     */
    public Optional<String> displayName() {
        return Optional.ofNullable(this.displayName);
    }
    public List<GetGatewaysFilter> filters() {
        return this.filters == null ? List.of() : this.filters;
    }
    /**
     * @return The list of gateway_collection.
     * 
     */
    public List<GetGatewaysGatewayCollection> gatewayCollections() {
        return this.gatewayCollections;
    }
    /**
     * @return The provider-assigned unique ID for this managed resource.
     * 
     */
    public String id() {
        return this.id;
    }
    /**
     * @return The current state of the gateway.
     * 
     */
    public Optional<String> state() {
        return Optional.ofNullable(this.state);
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetGatewaysResult defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private @Nullable String certificateId;
        private String compartmentId;
        private @Nullable String displayName;
        private @Nullable List<GetGatewaysFilter> filters;
        private List<GetGatewaysGatewayCollection> gatewayCollections;
        private String id;
        private @Nullable String state;
        public Builder() {}
        public Builder(GetGatewaysResult defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.certificateId = defaults.certificateId;
    	      this.compartmentId = defaults.compartmentId;
    	      this.displayName = defaults.displayName;
    	      this.filters = defaults.filters;
    	      this.gatewayCollections = defaults.gatewayCollections;
    	      this.id = defaults.id;
    	      this.state = defaults.state;
        }

        @CustomType.Setter
        public Builder certificateId(@Nullable String certificateId) {
            this.certificateId = certificateId;
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
        public Builder filters(@Nullable List<GetGatewaysFilter> filters) {
            this.filters = filters;
            return this;
        }
        public Builder filters(GetGatewaysFilter... filters) {
            return filters(List.of(filters));
        }
        @CustomType.Setter
        public Builder gatewayCollections(List<GetGatewaysGatewayCollection> gatewayCollections) {
            this.gatewayCollections = Objects.requireNonNull(gatewayCollections);
            return this;
        }
        public Builder gatewayCollections(GetGatewaysGatewayCollection... gatewayCollections) {
            return gatewayCollections(List.of(gatewayCollections));
        }
        @CustomType.Setter
        public Builder id(String id) {
            this.id = Objects.requireNonNull(id);
            return this;
        }
        @CustomType.Setter
        public Builder state(@Nullable String state) {
            this.state = state;
            return this;
        }
        public GetGatewaysResult build() {
            final var o = new GetGatewaysResult();
            o.certificateId = certificateId;
            o.compartmentId = compartmentId;
            o.displayName = displayName;
            o.filters = filters;
            o.gatewayCollections = gatewayCollections;
            o.id = id;
            o.state = state;
            return o;
        }
    }
}