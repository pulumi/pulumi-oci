// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Jms.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.oci.Jms.outputs.GetFleetBlocklistsFilter;
import com.pulumi.oci.Jms.outputs.GetFleetBlocklistsItem;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;

@CustomType
public final class GetFleetBlocklistsResult {
    private final @Nullable List<GetFleetBlocklistsFilter> filters;
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the fleet.
     * 
     */
    private final String fleetId;
    /**
     * @return The provider-assigned unique ID for this managed resource.
     * 
     */
    private final String id;
    /**
     * @return The blocklist
     * 
     */
    private final List<GetFleetBlocklistsItem> items;
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the related managed instance.
     * 
     */
    private final @Nullable String managedInstanceId;
    /**
     * @return The operation type
     * 
     */
    private final @Nullable String operation;

    @CustomType.Constructor
    private GetFleetBlocklistsResult(
        @CustomType.Parameter("filters") @Nullable List<GetFleetBlocklistsFilter> filters,
        @CustomType.Parameter("fleetId") String fleetId,
        @CustomType.Parameter("id") String id,
        @CustomType.Parameter("items") List<GetFleetBlocklistsItem> items,
        @CustomType.Parameter("managedInstanceId") @Nullable String managedInstanceId,
        @CustomType.Parameter("operation") @Nullable String operation) {
        this.filters = filters;
        this.fleetId = fleetId;
        this.id = id;
        this.items = items;
        this.managedInstanceId = managedInstanceId;
        this.operation = operation;
    }

    public List<GetFleetBlocklistsFilter> filters() {
        return this.filters == null ? List.of() : this.filters;
    }
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the fleet.
     * 
     */
    public String fleetId() {
        return this.fleetId;
    }
    /**
     * @return The provider-assigned unique ID for this managed resource.
     * 
     */
    public String id() {
        return this.id;
    }
    /**
     * @return The blocklist
     * 
     */
    public List<GetFleetBlocklistsItem> items() {
        return this.items;
    }
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the related managed instance.
     * 
     */
    public Optional<String> managedInstanceId() {
        return Optional.ofNullable(this.managedInstanceId);
    }
    /**
     * @return The operation type
     * 
     */
    public Optional<String> operation() {
        return Optional.ofNullable(this.operation);
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetFleetBlocklistsResult defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private @Nullable List<GetFleetBlocklistsFilter> filters;
        private String fleetId;
        private String id;
        private List<GetFleetBlocklistsItem> items;
        private @Nullable String managedInstanceId;
        private @Nullable String operation;

        public Builder() {
    	      // Empty
        }

        public Builder(GetFleetBlocklistsResult defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.filters = defaults.filters;
    	      this.fleetId = defaults.fleetId;
    	      this.id = defaults.id;
    	      this.items = defaults.items;
    	      this.managedInstanceId = defaults.managedInstanceId;
    	      this.operation = defaults.operation;
        }

        public Builder filters(@Nullable List<GetFleetBlocklistsFilter> filters) {
            this.filters = filters;
            return this;
        }
        public Builder filters(GetFleetBlocklistsFilter... filters) {
            return filters(List.of(filters));
        }
        public Builder fleetId(String fleetId) {
            this.fleetId = Objects.requireNonNull(fleetId);
            return this;
        }
        public Builder id(String id) {
            this.id = Objects.requireNonNull(id);
            return this;
        }
        public Builder items(List<GetFleetBlocklistsItem> items) {
            this.items = Objects.requireNonNull(items);
            return this;
        }
        public Builder items(GetFleetBlocklistsItem... items) {
            return items(List.of(items));
        }
        public Builder managedInstanceId(@Nullable String managedInstanceId) {
            this.managedInstanceId = managedInstanceId;
            return this;
        }
        public Builder operation(@Nullable String operation) {
            this.operation = operation;
            return this;
        }        public GetFleetBlocklistsResult build() {
            return new GetFleetBlocklistsResult(filters, fleetId, id, items, managedInstanceId, operation);
        }
    }
}
