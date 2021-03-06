// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Core.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.oci.Core.outputs.GetRouteTablesFilter;
import com.pulumi.oci.Core.outputs.GetRouteTablesRouteTable;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;

@CustomType
public final class GetRouteTablesResult {
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment containing the route table.
     * 
     */
    private final String compartmentId;
    /**
     * @return A user-friendly name. Does not have to be unique, and it&#39;s changeable. Avoid entering confidential information.
     * 
     */
    private final @Nullable String displayName;
    private final @Nullable List<GetRouteTablesFilter> filters;
    /**
     * @return The provider-assigned unique ID for this managed resource.
     * 
     */
    private final String id;
    /**
     * @return The list of route_tables.
     * 
     */
    private final List<GetRouteTablesRouteTable> routeTables;
    /**
     * @return The route table&#39;s current state.
     * 
     */
    private final @Nullable String state;
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the VCN the route table list belongs to.
     * 
     */
    private final @Nullable String vcnId;

    @CustomType.Constructor
    private GetRouteTablesResult(
        @CustomType.Parameter("compartmentId") String compartmentId,
        @CustomType.Parameter("displayName") @Nullable String displayName,
        @CustomType.Parameter("filters") @Nullable List<GetRouteTablesFilter> filters,
        @CustomType.Parameter("id") String id,
        @CustomType.Parameter("routeTables") List<GetRouteTablesRouteTable> routeTables,
        @CustomType.Parameter("state") @Nullable String state,
        @CustomType.Parameter("vcnId") @Nullable String vcnId) {
        this.compartmentId = compartmentId;
        this.displayName = displayName;
        this.filters = filters;
        this.id = id;
        this.routeTables = routeTables;
        this.state = state;
        this.vcnId = vcnId;
    }

    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment containing the route table.
     * 
     */
    public String compartmentId() {
        return this.compartmentId;
    }
    /**
     * @return A user-friendly name. Does not have to be unique, and it&#39;s changeable. Avoid entering confidential information.
     * 
     */
    public Optional<String> displayName() {
        return Optional.ofNullable(this.displayName);
    }
    public List<GetRouteTablesFilter> filters() {
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
     * @return The list of route_tables.
     * 
     */
    public List<GetRouteTablesRouteTable> routeTables() {
        return this.routeTables;
    }
    /**
     * @return The route table&#39;s current state.
     * 
     */
    public Optional<String> state() {
        return Optional.ofNullable(this.state);
    }
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the VCN the route table list belongs to.
     * 
     */
    public Optional<String> vcnId() {
        return Optional.ofNullable(this.vcnId);
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetRouteTablesResult defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private String compartmentId;
        private @Nullable String displayName;
        private @Nullable List<GetRouteTablesFilter> filters;
        private String id;
        private List<GetRouteTablesRouteTable> routeTables;
        private @Nullable String state;
        private @Nullable String vcnId;

        public Builder() {
    	      // Empty
        }

        public Builder(GetRouteTablesResult defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.compartmentId = defaults.compartmentId;
    	      this.displayName = defaults.displayName;
    	      this.filters = defaults.filters;
    	      this.id = defaults.id;
    	      this.routeTables = defaults.routeTables;
    	      this.state = defaults.state;
    	      this.vcnId = defaults.vcnId;
        }

        public Builder compartmentId(String compartmentId) {
            this.compartmentId = Objects.requireNonNull(compartmentId);
            return this;
        }
        public Builder displayName(@Nullable String displayName) {
            this.displayName = displayName;
            return this;
        }
        public Builder filters(@Nullable List<GetRouteTablesFilter> filters) {
            this.filters = filters;
            return this;
        }
        public Builder filters(GetRouteTablesFilter... filters) {
            return filters(List.of(filters));
        }
        public Builder id(String id) {
            this.id = Objects.requireNonNull(id);
            return this;
        }
        public Builder routeTables(List<GetRouteTablesRouteTable> routeTables) {
            this.routeTables = Objects.requireNonNull(routeTables);
            return this;
        }
        public Builder routeTables(GetRouteTablesRouteTable... routeTables) {
            return routeTables(List.of(routeTables));
        }
        public Builder state(@Nullable String state) {
            this.state = state;
            return this;
        }
        public Builder vcnId(@Nullable String vcnId) {
            this.vcnId = vcnId;
            return this;
        }        public GetRouteTablesResult build() {
            return new GetRouteTablesResult(compartmentId, displayName, filters, id, routeTables, state, vcnId);
        }
    }
}
