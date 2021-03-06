// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Core.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.oci.Core.outputs.GetDrgRouteTablesDrgRouteTable;
import com.pulumi.oci.Core.outputs.GetDrgRouteTablesFilter;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;

@CustomType
public final class GetDrgRouteTablesResult {
    /**
     * @return A user-friendly name. Does not have to be unique, and it&#39;s changeable. Avoid entering confidential information.
     * 
     */
    private final @Nullable String displayName;
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the DRG the DRG that contains this route table.
     * 
     */
    private final String drgId;
    /**
     * @return The list of drg_route_tables.
     * 
     */
    private final List<GetDrgRouteTablesDrgRouteTable> drgRouteTables;
    private final @Nullable List<GetDrgRouteTablesFilter> filters;
    /**
     * @return The provider-assigned unique ID for this managed resource.
     * 
     */
    private final String id;
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the import route distribution used to specify how incoming route advertisements from referenced attachments are inserted into the DRG route table.
     * 
     */
    private final @Nullable String importDrgRouteDistributionId;
    /**
     * @return The DRG route table&#39;s current state.
     * 
     */
    private final @Nullable String state;

    @CustomType.Constructor
    private GetDrgRouteTablesResult(
        @CustomType.Parameter("displayName") @Nullable String displayName,
        @CustomType.Parameter("drgId") String drgId,
        @CustomType.Parameter("drgRouteTables") List<GetDrgRouteTablesDrgRouteTable> drgRouteTables,
        @CustomType.Parameter("filters") @Nullable List<GetDrgRouteTablesFilter> filters,
        @CustomType.Parameter("id") String id,
        @CustomType.Parameter("importDrgRouteDistributionId") @Nullable String importDrgRouteDistributionId,
        @CustomType.Parameter("state") @Nullable String state) {
        this.displayName = displayName;
        this.drgId = drgId;
        this.drgRouteTables = drgRouteTables;
        this.filters = filters;
        this.id = id;
        this.importDrgRouteDistributionId = importDrgRouteDistributionId;
        this.state = state;
    }

    /**
     * @return A user-friendly name. Does not have to be unique, and it&#39;s changeable. Avoid entering confidential information.
     * 
     */
    public Optional<String> displayName() {
        return Optional.ofNullable(this.displayName);
    }
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the DRG the DRG that contains this route table.
     * 
     */
    public String drgId() {
        return this.drgId;
    }
    /**
     * @return The list of drg_route_tables.
     * 
     */
    public List<GetDrgRouteTablesDrgRouteTable> drgRouteTables() {
        return this.drgRouteTables;
    }
    public List<GetDrgRouteTablesFilter> filters() {
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
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the import route distribution used to specify how incoming route advertisements from referenced attachments are inserted into the DRG route table.
     * 
     */
    public Optional<String> importDrgRouteDistributionId() {
        return Optional.ofNullable(this.importDrgRouteDistributionId);
    }
    /**
     * @return The DRG route table&#39;s current state.
     * 
     */
    public Optional<String> state() {
        return Optional.ofNullable(this.state);
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetDrgRouteTablesResult defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private @Nullable String displayName;
        private String drgId;
        private List<GetDrgRouteTablesDrgRouteTable> drgRouteTables;
        private @Nullable List<GetDrgRouteTablesFilter> filters;
        private String id;
        private @Nullable String importDrgRouteDistributionId;
        private @Nullable String state;

        public Builder() {
    	      // Empty
        }

        public Builder(GetDrgRouteTablesResult defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.displayName = defaults.displayName;
    	      this.drgId = defaults.drgId;
    	      this.drgRouteTables = defaults.drgRouteTables;
    	      this.filters = defaults.filters;
    	      this.id = defaults.id;
    	      this.importDrgRouteDistributionId = defaults.importDrgRouteDistributionId;
    	      this.state = defaults.state;
        }

        public Builder displayName(@Nullable String displayName) {
            this.displayName = displayName;
            return this;
        }
        public Builder drgId(String drgId) {
            this.drgId = Objects.requireNonNull(drgId);
            return this;
        }
        public Builder drgRouteTables(List<GetDrgRouteTablesDrgRouteTable> drgRouteTables) {
            this.drgRouteTables = Objects.requireNonNull(drgRouteTables);
            return this;
        }
        public Builder drgRouteTables(GetDrgRouteTablesDrgRouteTable... drgRouteTables) {
            return drgRouteTables(List.of(drgRouteTables));
        }
        public Builder filters(@Nullable List<GetDrgRouteTablesFilter> filters) {
            this.filters = filters;
            return this;
        }
        public Builder filters(GetDrgRouteTablesFilter... filters) {
            return filters(List.of(filters));
        }
        public Builder id(String id) {
            this.id = Objects.requireNonNull(id);
            return this;
        }
        public Builder importDrgRouteDistributionId(@Nullable String importDrgRouteDistributionId) {
            this.importDrgRouteDistributionId = importDrgRouteDistributionId;
            return this;
        }
        public Builder state(@Nullable String state) {
            this.state = state;
            return this;
        }        public GetDrgRouteTablesResult build() {
            return new GetDrgRouteTablesResult(displayName, drgId, drgRouteTables, filters, id, importDrgRouteDistributionId, state);
        }
    }
}
