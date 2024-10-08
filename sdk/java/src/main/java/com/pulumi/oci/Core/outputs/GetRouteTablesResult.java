// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Core.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
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
    private String compartmentId;
    /**
     * @return A user-friendly name. Does not have to be unique, and it&#39;s changeable. Avoid entering confidential information.
     * 
     */
    private @Nullable String displayName;
    private @Nullable List<GetRouteTablesFilter> filters;
    /**
     * @return The provider-assigned unique ID for this managed resource.
     * 
     */
    private String id;
    /**
     * @return The list of route_tables.
     * 
     */
    private List<GetRouteTablesRouteTable> routeTables;
    /**
     * @return The route table&#39;s current state.
     * 
     */
    private @Nullable String state;
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the VCN the route table list belongs to.
     * 
     */
    private @Nullable String vcnId;

    private GetRouteTablesResult() {}
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
    @CustomType.Builder
    public static final class Builder {
        private String compartmentId;
        private @Nullable String displayName;
        private @Nullable List<GetRouteTablesFilter> filters;
        private String id;
        private List<GetRouteTablesRouteTable> routeTables;
        private @Nullable String state;
        private @Nullable String vcnId;
        public Builder() {}
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

        @CustomType.Setter
        public Builder compartmentId(String compartmentId) {
            if (compartmentId == null) {
              throw new MissingRequiredPropertyException("GetRouteTablesResult", "compartmentId");
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
        public Builder filters(@Nullable List<GetRouteTablesFilter> filters) {

            this.filters = filters;
            return this;
        }
        public Builder filters(GetRouteTablesFilter... filters) {
            return filters(List.of(filters));
        }
        @CustomType.Setter
        public Builder id(String id) {
            if (id == null) {
              throw new MissingRequiredPropertyException("GetRouteTablesResult", "id");
            }
            this.id = id;
            return this;
        }
        @CustomType.Setter
        public Builder routeTables(List<GetRouteTablesRouteTable> routeTables) {
            if (routeTables == null) {
              throw new MissingRequiredPropertyException("GetRouteTablesResult", "routeTables");
            }
            this.routeTables = routeTables;
            return this;
        }
        public Builder routeTables(GetRouteTablesRouteTable... routeTables) {
            return routeTables(List.of(routeTables));
        }
        @CustomType.Setter
        public Builder state(@Nullable String state) {

            this.state = state;
            return this;
        }
        @CustomType.Setter
        public Builder vcnId(@Nullable String vcnId) {

            this.vcnId = vcnId;
            return this;
        }
        public GetRouteTablesResult build() {
            final var _resultValue = new GetRouteTablesResult();
            _resultValue.compartmentId = compartmentId;
            _resultValue.displayName = displayName;
            _resultValue.filters = filters;
            _resultValue.id = id;
            _resultValue.routeTables = routeTables;
            _resultValue.state = state;
            _resultValue.vcnId = vcnId;
            return _resultValue;
        }
    }
}
