// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.ServiceMesh.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.oci.ServiceMesh.outputs.GetIngressGatewayRouteTablesFilter;
import com.pulumi.oci.ServiceMesh.outputs.GetIngressGatewayRouteTablesIngressGatewayRouteTableCollection;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;

@CustomType
public final class GetIngressGatewayRouteTablesResult {
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
     * 
     */
    private String compartmentId;
    private @Nullable List<GetIngressGatewayRouteTablesFilter> filters;
    /**
     * @return Unique identifier that is immutable on creation.
     * 
     */
    private @Nullable String id;
    /**
     * @return The OCID of the ingress gateway.
     * 
     */
    private @Nullable String ingressGatewayId;
    /**
     * @return The list of ingress_gateway_route_table_collection.
     * 
     */
    private List<GetIngressGatewayRouteTablesIngressGatewayRouteTableCollection> ingressGatewayRouteTableCollections;
    /**
     * @return Name of the ingress gateway host that this route should apply to.
     * 
     */
    private @Nullable String name;
    /**
     * @return The current state of the Resource.
     * 
     */
    private @Nullable String state;

    private GetIngressGatewayRouteTablesResult() {}
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
     * 
     */
    public String compartmentId() {
        return this.compartmentId;
    }
    public List<GetIngressGatewayRouteTablesFilter> filters() {
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
     * @return The OCID of the ingress gateway.
     * 
     */
    public Optional<String> ingressGatewayId() {
        return Optional.ofNullable(this.ingressGatewayId);
    }
    /**
     * @return The list of ingress_gateway_route_table_collection.
     * 
     */
    public List<GetIngressGatewayRouteTablesIngressGatewayRouteTableCollection> ingressGatewayRouteTableCollections() {
        return this.ingressGatewayRouteTableCollections;
    }
    /**
     * @return Name of the ingress gateway host that this route should apply to.
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

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetIngressGatewayRouteTablesResult defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String compartmentId;
        private @Nullable List<GetIngressGatewayRouteTablesFilter> filters;
        private @Nullable String id;
        private @Nullable String ingressGatewayId;
        private List<GetIngressGatewayRouteTablesIngressGatewayRouteTableCollection> ingressGatewayRouteTableCollections;
        private @Nullable String name;
        private @Nullable String state;
        public Builder() {}
        public Builder(GetIngressGatewayRouteTablesResult defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.compartmentId = defaults.compartmentId;
    	      this.filters = defaults.filters;
    	      this.id = defaults.id;
    	      this.ingressGatewayId = defaults.ingressGatewayId;
    	      this.ingressGatewayRouteTableCollections = defaults.ingressGatewayRouteTableCollections;
    	      this.name = defaults.name;
    	      this.state = defaults.state;
        }

        @CustomType.Setter
        public Builder compartmentId(String compartmentId) {
            this.compartmentId = Objects.requireNonNull(compartmentId);
            return this;
        }
        @CustomType.Setter
        public Builder filters(@Nullable List<GetIngressGatewayRouteTablesFilter> filters) {
            this.filters = filters;
            return this;
        }
        public Builder filters(GetIngressGatewayRouteTablesFilter... filters) {
            return filters(List.of(filters));
        }
        @CustomType.Setter
        public Builder id(@Nullable String id) {
            this.id = id;
            return this;
        }
        @CustomType.Setter
        public Builder ingressGatewayId(@Nullable String ingressGatewayId) {
            this.ingressGatewayId = ingressGatewayId;
            return this;
        }
        @CustomType.Setter
        public Builder ingressGatewayRouteTableCollections(List<GetIngressGatewayRouteTablesIngressGatewayRouteTableCollection> ingressGatewayRouteTableCollections) {
            this.ingressGatewayRouteTableCollections = Objects.requireNonNull(ingressGatewayRouteTableCollections);
            return this;
        }
        public Builder ingressGatewayRouteTableCollections(GetIngressGatewayRouteTablesIngressGatewayRouteTableCollection... ingressGatewayRouteTableCollections) {
            return ingressGatewayRouteTableCollections(List.of(ingressGatewayRouteTableCollections));
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
        public GetIngressGatewayRouteTablesResult build() {
            final var o = new GetIngressGatewayRouteTablesResult();
            o.compartmentId = compartmentId;
            o.filters = filters;
            o.id = id;
            o.ingressGatewayId = ingressGatewayId;
            o.ingressGatewayRouteTableCollections = ingressGatewayRouteTableCollections;
            o.name = name;
            o.state = state;
            return o;
        }
    }
}