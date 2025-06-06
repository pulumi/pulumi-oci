// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.OsManagementHub.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.OsManagementHub.inputs.GetEntitlementsFilterArgs;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class GetEntitlementsArgs extends com.pulumi.resources.InvokeArgs {

    public static final GetEntitlementsArgs Empty = new GetEntitlementsArgs();

    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment. This parameter is required and returns only resources contained within the specified compartment.
     * 
     */
    @Import(name="compartmentId", required=true)
    private Output<String> compartmentId;

    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment. This parameter is required and returns only resources contained within the specified compartment.
     * 
     */
    public Output<String> compartmentId() {
        return this.compartmentId;
    }

    /**
     * A filter to return entitlements that match the given customer support identifier (CSI).
     * 
     */
    @Import(name="csi")
    private @Nullable Output<String> csi;

    /**
     * @return A filter to return entitlements that match the given customer support identifier (CSI).
     * 
     */
    public Optional<Output<String>> csi() {
        return Optional.ofNullable(this.csi);
    }

    @Import(name="filters")
    private @Nullable Output<List<GetEntitlementsFilterArgs>> filters;

    public Optional<Output<List<GetEntitlementsFilterArgs>>> filters() {
        return Optional.ofNullable(this.filters);
    }

    /**
     * A filter to return only resources that match the given vendor name.
     * 
     */
    @Import(name="vendorName")
    private @Nullable Output<String> vendorName;

    /**
     * @return A filter to return only resources that match the given vendor name.
     * 
     */
    public Optional<Output<String>> vendorName() {
        return Optional.ofNullable(this.vendorName);
    }

    private GetEntitlementsArgs() {}

    private GetEntitlementsArgs(GetEntitlementsArgs $) {
        this.compartmentId = $.compartmentId;
        this.csi = $.csi;
        this.filters = $.filters;
        this.vendorName = $.vendorName;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(GetEntitlementsArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private GetEntitlementsArgs $;

        public Builder() {
            $ = new GetEntitlementsArgs();
        }

        public Builder(GetEntitlementsArgs defaults) {
            $ = new GetEntitlementsArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param compartmentId The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment. This parameter is required and returns only resources contained within the specified compartment.
         * 
         * @return builder
         * 
         */
        public Builder compartmentId(Output<String> compartmentId) {
            $.compartmentId = compartmentId;
            return this;
        }

        /**
         * @param compartmentId The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment. This parameter is required and returns only resources contained within the specified compartment.
         * 
         * @return builder
         * 
         */
        public Builder compartmentId(String compartmentId) {
            return compartmentId(Output.of(compartmentId));
        }

        /**
         * @param csi A filter to return entitlements that match the given customer support identifier (CSI).
         * 
         * @return builder
         * 
         */
        public Builder csi(@Nullable Output<String> csi) {
            $.csi = csi;
            return this;
        }

        /**
         * @param csi A filter to return entitlements that match the given customer support identifier (CSI).
         * 
         * @return builder
         * 
         */
        public Builder csi(String csi) {
            return csi(Output.of(csi));
        }

        public Builder filters(@Nullable Output<List<GetEntitlementsFilterArgs>> filters) {
            $.filters = filters;
            return this;
        }

        public Builder filters(List<GetEntitlementsFilterArgs> filters) {
            return filters(Output.of(filters));
        }

        public Builder filters(GetEntitlementsFilterArgs... filters) {
            return filters(List.of(filters));
        }

        /**
         * @param vendorName A filter to return only resources that match the given vendor name.
         * 
         * @return builder
         * 
         */
        public Builder vendorName(@Nullable Output<String> vendorName) {
            $.vendorName = vendorName;
            return this;
        }

        /**
         * @param vendorName A filter to return only resources that match the given vendor name.
         * 
         * @return builder
         * 
         */
        public Builder vendorName(String vendorName) {
            return vendorName(Output.of(vendorName));
        }

        public GetEntitlementsArgs build() {
            if ($.compartmentId == null) {
                throw new MissingRequiredPropertyException("GetEntitlementsArgs", "compartmentId");
            }
            return $;
        }
    }

}
