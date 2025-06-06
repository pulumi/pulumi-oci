// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.OsManagementHub.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.OsManagementHub.outputs.GetEntitlementsEntitlementCollection;
import com.pulumi.oci.OsManagementHub.outputs.GetEntitlementsFilter;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;

@CustomType
public final class GetEntitlementsResult {
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the tenancy containing the entitlement.
     * 
     */
    private String compartmentId;
    /**
     * @return The Customer Support Identifier (CSI) which unlocks the software sources. The CSI is is a unique key given to a customer and it uniquely identifies the entitlement.
     * 
     */
    private @Nullable String csi;
    /**
     * @return The list of entitlement_collection.
     * 
     */
    private List<GetEntitlementsEntitlementCollection> entitlementCollections;
    private @Nullable List<GetEntitlementsFilter> filters;
    /**
     * @return The provider-assigned unique ID for this managed resource.
     * 
     */
    private String id;
    /**
     * @return The vendor for the entitlement.
     * 
     */
    private @Nullable String vendorName;

    private GetEntitlementsResult() {}
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the tenancy containing the entitlement.
     * 
     */
    public String compartmentId() {
        return this.compartmentId;
    }
    /**
     * @return The Customer Support Identifier (CSI) which unlocks the software sources. The CSI is is a unique key given to a customer and it uniquely identifies the entitlement.
     * 
     */
    public Optional<String> csi() {
        return Optional.ofNullable(this.csi);
    }
    /**
     * @return The list of entitlement_collection.
     * 
     */
    public List<GetEntitlementsEntitlementCollection> entitlementCollections() {
        return this.entitlementCollections;
    }
    public List<GetEntitlementsFilter> filters() {
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
     * @return The vendor for the entitlement.
     * 
     */
    public Optional<String> vendorName() {
        return Optional.ofNullable(this.vendorName);
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetEntitlementsResult defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String compartmentId;
        private @Nullable String csi;
        private List<GetEntitlementsEntitlementCollection> entitlementCollections;
        private @Nullable List<GetEntitlementsFilter> filters;
        private String id;
        private @Nullable String vendorName;
        public Builder() {}
        public Builder(GetEntitlementsResult defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.compartmentId = defaults.compartmentId;
    	      this.csi = defaults.csi;
    	      this.entitlementCollections = defaults.entitlementCollections;
    	      this.filters = defaults.filters;
    	      this.id = defaults.id;
    	      this.vendorName = defaults.vendorName;
        }

        @CustomType.Setter
        public Builder compartmentId(String compartmentId) {
            if (compartmentId == null) {
              throw new MissingRequiredPropertyException("GetEntitlementsResult", "compartmentId");
            }
            this.compartmentId = compartmentId;
            return this;
        }
        @CustomType.Setter
        public Builder csi(@Nullable String csi) {

            this.csi = csi;
            return this;
        }
        @CustomType.Setter
        public Builder entitlementCollections(List<GetEntitlementsEntitlementCollection> entitlementCollections) {
            if (entitlementCollections == null) {
              throw new MissingRequiredPropertyException("GetEntitlementsResult", "entitlementCollections");
            }
            this.entitlementCollections = entitlementCollections;
            return this;
        }
        public Builder entitlementCollections(GetEntitlementsEntitlementCollection... entitlementCollections) {
            return entitlementCollections(List.of(entitlementCollections));
        }
        @CustomType.Setter
        public Builder filters(@Nullable List<GetEntitlementsFilter> filters) {

            this.filters = filters;
            return this;
        }
        public Builder filters(GetEntitlementsFilter... filters) {
            return filters(List.of(filters));
        }
        @CustomType.Setter
        public Builder id(String id) {
            if (id == null) {
              throw new MissingRequiredPropertyException("GetEntitlementsResult", "id");
            }
            this.id = id;
            return this;
        }
        @CustomType.Setter
        public Builder vendorName(@Nullable String vendorName) {

            this.vendorName = vendorName;
            return this;
        }
        public GetEntitlementsResult build() {
            final var _resultValue = new GetEntitlementsResult();
            _resultValue.compartmentId = compartmentId;
            _resultValue.csi = csi;
            _resultValue.entitlementCollections = entitlementCollections;
            _resultValue.filters = filters;
            _resultValue.id = id;
            _resultValue.vendorName = vendorName;
            return _resultValue;
        }
    }
}
